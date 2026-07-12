//! Startup configuration, validated once from the environment.
//!
//! `Config` is only constructible when every value is valid, so the rest
//! of the program never has to defend against a half-configured state.

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;

use axum::http::Uri;
use blake3::Hash;

/// Default IP socket address the service listens on.
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8000";
/// Environment variable holding the IP socket address to listen on.
const ENV_ADDRESS: &str = "MBA_ADDRESS";
/// Environment variable holding a plain password. At least one of the
/// `MBA_PASSWORD*` family (this or a `MBA_PASSWORD_<label>`) must be
/// non-empty.
const ENV_PASSWORD: &str = "MBA_PASSWORD";
/// Prefix for additional password variables, e.g. `MBA_PASSWORD_BOB`. The
/// suffix is a free-form label (typically who the password belongs to);
/// it carries no meaning at request time. Reserved: future config must
/// not land under `MBA_PASSWORD_*` or it would be read as a password.
const ENV_PASSWORD_PREFIX: &str = "MBA_PASSWORD_";
/// Environment variable holding the upstream URL (required, absolute
/// `http(s)://host[:port]`).
const ENV_UPSTREAM: &str = "MBA_UPSTREAM";

/// Immutable runtime configuration, built once at startup.
///
/// Cloned per request by the gate middleware (`from_fn_with_state`
/// requires the state to be `Clone`), which is why fields stay cheap to
/// clone (`SocketAddr` is `Copy`; `Vec<Hash>` and `String` each clone one
/// small heap allocation per request).
#[derive(Clone)]
pub struct Config {
    /// Validated IP socket address the service listens on.
    bind_address: SocketAddr,
    /// BLAKE3 digests of the configured passwords. The session cookie
    /// carries one of these as hex; a request authenticates by presenting
    /// a cookie that matches **any** of them. `Config` stores only the
    /// digests, not the plaintext. The cookie is not harmless: it never
    /// contains the plaintext password, but it holds a password-equivalent
    /// bearer token and remains sensitive (see the `Debug` redaction
    /// below). This is not memory scrubbing — the plaintext still lives in
    /// the process environment.
    sessions: Vec<Hash>,
    /// Validated absolute `http(s)://host[:port]` upstream. Stored as a
    /// `String` (not `Uri`) because `ReverseProxy::new` takes one generic
    /// `S: Into<String>` for both arguments; a `&Uri` would not satisfy
    /// that bound.
    upstream: String,
}

impl Config {
    /// Build from the process environment. Delegates to the same pure
    /// validation as [`Config::from_values`] so tests do not have to mutate
    /// process-wide env (which is `unsafe` in Rust 2024).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `MBA_ADDRESS` is not a valid non-zero IP
    /// socket address, no `MBA_PASSWORD*` variable has a non-empty UTF-8
    /// value, two of them share the same value, or `MBA_UPSTREAM` is not a
    /// valid absolute HTTP(S) URL.
    pub fn from_env() -> Result<Self, ConfigError> {
        let address = match std::env::var(ENV_ADDRESS) {
            Ok(address) => address,
            Err(std::env::VarError::NotPresent) => DEFAULT_BIND_ADDRESS.to_string(),
            Err(std::env::VarError::NotUnicode(address)) => {
                return Err(ConfigError::InvalidAddress {
                    value: address.to_string_lossy().into_owned(),
                    reason: "not valid Unicode",
                });
            }
        };
        let passwords = passwords_from_env(std::env::vars_os());
        let passwords: Vec<&str> = passwords.iter().map(String::as_str).collect();
        let upstream = std::env::var(ENV_UPSTREAM).unwrap_or_default();
        Self::from_passwords_and_address(&passwords, &upstream, &address)
    }

    /// Build and validate from explicit values (pure, env-free).
    ///
    /// # Examples
    ///
    /// ```
    /// # use mildly_basic_auth::Config;
    /// assert!(Config::from_values("hunter2", "http://app:2001").is_ok());
    /// assert!(Config::from_values("", "http://app:2001").is_err()); // No password.
    /// assert!(Config::from_values("hunter2", "/relative").is_err()); // No host.
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingPassword`] for an empty password, or
    /// [`ConfigError::MissingUpstream`] / [`ConfigError::InvalidUpstream`]
    /// if the upstream is not a valid absolute HTTP(S) URL. The bind
    /// address uses the default `0.0.0.0:8000`.
    pub fn from_values(password: &str, upstream: &str) -> Result<Self, ConfigError> {
        Self::from_values_and_address(password, upstream, DEFAULT_BIND_ADDRESS)
    }

    /// Build and validate from several explicit passwords (pure, env-free).
    /// Empty entries are ignored; at least one must remain, and all must be
    /// distinct. Any of them authenticates.
    ///
    /// # Examples
    ///
    /// ```
    /// # use mildly_basic_auth::Config;
    /// assert!(Config::from_passwords(&["alice", "bob"], "http://app:2001").is_ok());
    /// assert!(Config::from_passwords(&[], "http://app:2001").is_err()); // No password.
    /// assert!(Config::from_passwords(&["x", "x"], "http://app:2001").is_err()); // Duplicate.
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingPassword`] if no password is non-empty,
    /// [`ConfigError::DuplicatePassword`] if two passwords share a value, or
    /// [`ConfigError::MissingUpstream`] / [`ConfigError::InvalidUpstream`]
    /// if the upstream is not a valid absolute HTTP(S) URL. The bind
    /// address uses the default `0.0.0.0:8000`.
    pub fn from_passwords(passwords: &[&str], upstream: &str) -> Result<Self, ConfigError> {
        Self::from_passwords_and_address(passwords, upstream, DEFAULT_BIND_ADDRESS)
    }

    /// Validated IP socket address the service listens on.
    #[must_use]
    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    /// Build and validate the complete runtime configuration from a single
    /// password.
    fn from_values_and_address(
        password: &str,
        upstream: &str,
        address: &str,
    ) -> Result<Self, ConfigError> {
        Self::from_passwords_and_address(&[password], upstream, address)
    }

    /// Build and validate the complete runtime configuration.
    fn from_passwords_and_address(
        passwords: &[&str],
        upstream: &str,
        address: &str,
    ) -> Result<Self, ConfigError> {
        // Keep non-empty values (drop unset/blank vars).
        let passwords: Vec<&str> = passwords
            .iter()
            .copied()
            .filter(|p| !p.is_empty())
            .collect();
        if passwords.is_empty() {
            return Err(ConfigError::MissingPassword);
        }
        // Reject duplicates: two variables sharing a value hash to the same
        // digest, so removing one would not revoke the other — breaking
        // independent revocation. Startup-time over operator input, so a
        // `HashSet` compare (not constant-time) is fine; this is not the
        // request path.
        let unique: HashSet<&str> = passwords.iter().copied().collect();
        if unique.len() != passwords.len() {
            return Err(ConfigError::DuplicatePassword);
        }
        // Only the digests are retained in `Config`; the plaintext stays
        // with the caller and the process environment (not scrubbed here).
        let sessions: Vec<Hash> = passwords
            .iter()
            .map(|p| blake3::hash(p.as_bytes()))
            .collect();
        let upstream = validate_upstream(upstream)?;
        let address = validate_address(address)?;
        Ok(Self {
            bind_address: address,
            sessions,
            upstream,
        })
    }

    /// Expected session-cookie digests. A request authenticates by matching
    /// any of them.
    pub(crate) fn sessions(&self) -> &[Hash] {
        &self.sessions
    }

    /// Validated upstream URL, ready for `ReverseProxy::new`.
    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the session digests: each is a password-equivalent
        // bearer token, so an accidental log must not leak it.
        f.debug_struct("Config")
            .field("bind_address", &self.bind_address)
            .field("sessions", &"<redacted>")
            .field("upstream", &self.upstream)
            .finish()
    }
}

/// Every configured password from the environment: `MBA_PASSWORD` and any
/// name starting with `MBA_PASSWORD_`. Order is irrelevant (any match
/// authenticates); empty values are dropped downstream. Non-Unicode names
/// never match; non-Unicode values are skipped (a form-entered password is
/// always UTF-8, so such a value is unusable anyway).
///
/// Pure over the iterator so it is testable without mutating process-wide
/// env (which is `unsafe` in Rust 2024). `from_env` calls it with
/// `std::env::vars_os()` — `vars_os` (not `vars`) because `vars` panics on
/// any non-Unicode variable anywhere in the environment.
fn passwords_from_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<String> {
    vars.filter_map(|(name, value)| {
        // Filter by name *before* touching the value, so an unrelated
        // non-Unicode variable can never reach `into_string`.
        let name = name.to_str()?;
        (name == ENV_PASSWORD || name.starts_with(ENV_PASSWORD_PREFIX))
            .then(|| value.into_string().ok())
            .flatten()
    })
    .collect()
}

/// Validate `address` as a non-zero IP socket address.
///
/// # Examples
///
/// ```ignore
/// assert!(validate_address("0.0.0.0:4630").is_ok());
/// assert!(validate_address("[::]:4630").is_ok());
/// assert!(validate_address("localhost:4630").is_err()); // Not an IP.
/// assert!(validate_address("0.0.0.0:0").is_err()); // Zero port.
/// ```
fn validate_address(address: &str) -> Result<SocketAddr, ConfigError> {
    let address = address.trim();
    let invalid = |reason: &'static str| ConfigError::InvalidAddress {
        value: address.to_string(),
        reason,
    };
    let address: SocketAddr = address
        .parse()
        .map_err(|_| invalid("expected an IP address and port"))?;
    if address.port() == 0 {
        return Err(invalid("port must not be zero"));
    }
    Ok(address)
}

/// Validate `upstream` as an absolute `http(s)://host[:port]` URL.
///
/// Strictness matters: `http::Uri` parses relative refs like `/foo` or
/// `example:8080` that carry no authority, and `axum-reverse-proxy` then
/// `.expect()`s an authority and **panics** at request time. We reject
/// anything that isn't an absolute HTTP(S) URL up front.
///
/// # Examples
///
/// ```ignore
/// assert!(validate_upstream("http://app:2001").is_ok());
/// assert!(validate_upstream("").is_err()); // Empty.
/// assert!(validate_upstream("/foo").is_err()); // No scheme/host.
/// assert!(validate_upstream("example:8080").is_err()); // No host.
/// assert!(validate_upstream("ftp://host").is_err()); // Not HTTP(S).
/// ```
fn validate_upstream(upstream: &str) -> Result<String, ConfigError> {
    let upstream = upstream.trim();
    if upstream.is_empty() {
        return Err(ConfigError::MissingUpstream);
    }

    let invalid = |reason: &'static str| ConfigError::InvalidUpstream {
        value: upstream.to_string(),
        reason,
    };

    let uri: Uri = upstream.parse().map_err(|_| invalid("not a valid URL"))?;

    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(invalid("scheme must be http or https"));
    }
    let host = uri.host().unwrap_or_default();
    // An authority can parse with an empty host (`http://:8080`), which the
    // connector cannot use.
    if host.is_empty() {
        return Err(invalid("missing host"));
    }
    // Port 0 is never a real destination.
    if uri.port_u16() == Some(0) {
        return Err(invalid("invalid port"));
    }
    // `http::Uri` silently *drops* malformed detail: a bad port (`:abc`,
    // `:`, `:99999`) or junk after an IPv6 literal (`[::1]junk`) all parse
    // with that text discarded, so the connector would target the wrong
    // place (e.g. the scheme default port). Catch it by reconstructing the
    // canonical `host[:port]` from the parsed parts and requiring it to
    // equal the input authority (ignoring any `userinfo@`); a mismatch is
    // exactly the garbage that was dropped. The port is taken from
    // `port().as_str()` (its original text), not `port_u16()`, so a valid
    // leading-zero port like `:080` round-trips instead of collapsing to
    // `:80` and failing the comparison.
    let authority = uri.authority().map_or("", |a| a.as_str());
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let canonical = match uri.port() {
        Some(port) => format!("{host}:{}", port.as_str()),
        None => host.to_string(),
    };
    if host_port != canonical {
        return Err(invalid("invalid host or port"));
    }

    // Normalized form. The proxy trims any trailing slash when joining
    // paths, so the canonical `http://host:port/` cannot produce `//`.
    Ok(uri.to_string())
}

/// Why a `Config` could not be built. Surfaced to stderr at startup so a
/// misconfiguration fails fast with an actionable message.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `MBA_ADDRESS` was not a valid non-zero IP socket address.
    InvalidAddress { value: String, reason: &'static str },
    /// No `MBA_PASSWORD*` variable had a non-empty UTF-8 value.
    MissingPassword,
    /// Two `MBA_PASSWORD*` variables shared the same value, which would
    /// break independent revocation.
    DuplicatePassword,
    /// `MBA_UPSTREAM` was unset or empty.
    MissingUpstream,
    /// `MBA_UPSTREAM` was set but is not an absolute HTTP(S) URL.
    InvalidUpstream { value: String, reason: &'static str },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress { value, reason } => write!(
                f,
                "`{ENV_ADDRESS}` is not a valid IP socket address ({reason}): {value:?}"
            ),
            Self::MissingPassword => write!(
                f,
                "at least one password variable (`{ENV_PASSWORD}` or \
                 `{ENV_PASSWORD_PREFIX}<label>`) must have a non-empty UTF-8 value"
            ),
            Self::DuplicatePassword => write!(
                f,
                "two password variables share the same value; each password \
                 must be distinct to be revoked independently"
            ),
            Self::MissingUpstream => write!(f, "`{ENV_UPSTREAM}` must be set"),
            Self::InvalidUpstream { value, reason } => write!(
                f,
                "`{ENV_UPSTREAM}` is not a valid absolute http(s) URL \
                 ({reason}): {value:?}"
            ),
        }
    }
}

impl Error for ConfigError {}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    #[test]
    fn valid_values_build_a_config() {
        assert!(Config::from_values("hunter2", "http://app:2001").is_ok());
    }

    #[test]
    fn values_use_the_default_address() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        assert_eq!(config.bind_address(), "0.0.0.0:8000".parse().unwrap());
    }

    #[test]
    fn custom_ipv4_address_is_accepted() {
        let config =
            Config::from_values_and_address("hunter2", "http://app:2001", "127.0.0.1:4630")
                .unwrap();
        assert_eq!(config.bind_address(), "127.0.0.1:4630".parse().unwrap());
    }

    #[test]
    fn custom_ipv6_address_is_accepted() {
        let config =
            Config::from_values_and_address("hunter2", "http://app:2001", "[::1]:4630").unwrap();
        assert_eq!(config.bind_address(), "[::1]:4630".parse().unwrap());
    }

    #[test]
    fn surrounding_whitespace_in_address_is_trimmed() {
        let config =
            Config::from_values_and_address("hunter2", "http://app:2001", "  127.0.0.1:4630  ")
                .unwrap();
        assert_eq!(config.bind_address(), "127.0.0.1:4630".parse().unwrap());
    }

    #[test]
    fn empty_address_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", ""),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn hostname_address_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", "localhost:4630"),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn address_without_port_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", "127.0.0.1"),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn address_with_non_numeric_port_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", "127.0.0.1:abc"),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn address_with_out_of_range_port_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", "127.0.0.1:99999"),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn address_with_zero_port_is_rejected() {
        assert_matches!(
            Config::from_values_and_address("hunter2", "http://app:2001", "127.0.0.1:0"),
            Err(ConfigError::InvalidAddress { .. })
        );
    }

    #[test]
    fn https_upstream_is_accepted() {
        assert!(Config::from_values("hunter2", "https://app.example.com").is_ok());
    }

    #[test]
    fn empty_password_is_rejected() {
        assert_matches!(
            Config::from_values("", "http://app:2001"),
            Err(ConfigError::MissingPassword)
        );
    }

    #[test]
    fn empty_upstream_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", ""),
            Err(ConfigError::MissingUpstream)
        );
    }

    #[test]
    fn relative_upstream_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "/foo"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn scheme_only_upstream_without_authority_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "example:8080"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "ftp://host"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn empty_host_upstream_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://:8080"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn out_of_range_port_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://host:99999"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn non_numeric_port_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://host:abc"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn empty_port_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://host:"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn zero_port_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://host:0"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn leading_zero_port_is_accepted() {
        // `:080` is a valid port (80); the connector resolves it fine.
        assert!(Config::from_values("hunter2", "http://host:080").is_ok());
    }

    #[test]
    fn all_zero_port_is_rejected() {
        // `:00` is still port 0.
        assert_matches!(
            Config::from_values("hunter2", "http://host:00"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn ipv6_upstream_is_accepted() {
        assert!(Config::from_values("hunter2", "http://[::1]:8080").is_ok());
    }

    #[test]
    fn ipv6_with_trailing_junk_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://[::1]junk"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn ipv6_junk_before_port_is_rejected() {
        assert_matches!(
            Config::from_values("hunter2", "http://[::1]junk:8080"),
            Err(ConfigError::InvalidUpstream { .. })
        );
    }

    #[test]
    fn session_digest_matches_blake3_of_password() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        assert_eq!(config.sessions(), &[blake3::hash(b"hunter2")]);
    }

    #[test]
    fn multiple_passwords_build_one_digest_each() {
        let config = Config::from_passwords(&["hunter2", "swordfish"], "http://app:2001").unwrap();
        assert_eq!(
            config.sessions(),
            &[blake3::hash(b"hunter2"), blake3::hash(b"swordfish")]
        );
    }

    #[test]
    fn empty_passwords_are_filtered_out() {
        let config = Config::from_passwords(&["", "hunter2", ""], "http://app:2001").unwrap();
        assert_eq!(config.sessions(), &[blake3::hash(b"hunter2")]);
    }

    #[test]
    fn all_empty_passwords_are_rejected() {
        assert_matches!(
            Config::from_passwords(&["", ""], "http://app:2001"),
            Err(ConfigError::MissingPassword)
        );
    }

    #[test]
    fn no_passwords_are_rejected() {
        assert_matches!(
            Config::from_passwords(&[], "http://app:2001"),
            Err(ConfigError::MissingPassword)
        );
    }

    #[test]
    fn duplicate_passwords_are_rejected() {
        assert_matches!(
            Config::from_passwords(&["hunter2", "hunter2"], "http://app:2001"),
            Err(ConfigError::DuplicatePassword)
        );
    }

    #[test]
    fn duplicate_check_ignores_filtered_empties() {
        // The two empties are dropped before the duplicate check, so they
        // are not treated as duplicates of each other.
        assert!(Config::from_passwords(&["a", "", ""], "http://app:2001").is_ok());
    }

    #[test]
    fn passwords_from_env_collects_base_and_suffixed() {
        let vars = [
            ("MBA_PASSWORD", "alpha"),
            ("MBA_PASSWORD_BOB", "bravo"),
            ("MBA_ADDRESS", "0.0.0.0:8000"),
            ("MBA_UPSTREAM", "http://app:2001"),
            ("PATH", "/usr/bin"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let mut got = passwords_from_env(vars);
        got.sort();
        assert_eq!(got, ["alpha".to_string(), "bravo".to_string()]);
    }

    #[test]
    fn passwords_from_env_keeps_empty_values_for_later_filtering() {
        // The scanner is not where empties are dropped; the constructor is.
        let vars = [("MBA_PASSWORD_BOB", "")]
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        assert_eq!(passwords_from_env(vars), [String::new()]);
    }

    #[cfg(unix)]
    #[test]
    fn passwords_from_env_skips_non_unicode_without_panicking() {
        use std::os::unix::ffi::OsStringExt;

        // An unrelated variable with a non-Unicode *name*, and a
        // `MBA_PASSWORD_*` with a non-Unicode *value*: both must be skipped
        // (not panic), while a valid entry alongside them still collects.
        let vars = vec![
            (OsString::from_vec(vec![0xff]), OsString::from("ignored")),
            (
                OsString::from("MBA_PASSWORD_BAD"),
                OsString::from_vec(vec![0xff]),
            ),
            (OsString::from("MBA_PASSWORD"), OsString::from("alpha")),
        ]
        .into_iter();
        assert_eq!(passwords_from_env(vars), ["alpha".to_string()]);
    }

    #[test]
    fn surrounding_whitespace_in_upstream_is_trimmed() {
        let config = Config::from_values("hunter2", "  http://app:2001  ").unwrap();
        assert_eq!(config.upstream(), "http://app:2001/");
    }
}
