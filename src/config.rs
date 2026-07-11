//! Startup configuration, validated once from the environment.
//!
//! `Config` is only constructible when every value is valid, so the rest
//! of the program never has to defend against a half-configured state.

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;

use axum::http::Uri;
use blake3::Hash;

/// Default IP socket address the service listens on.
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8000";
/// Environment variable holding the IP socket address to listen on.
const ENV_ADDRESS: &str = "MBA_ADDRESS";
/// Environment variable holding the plain password (required, non-empty).
const ENV_PASSWORD: &str = "MBA_PASSWORD";
/// Environment variable holding the upstream URL (required, absolute
/// `http(s)://host[:port]`).
const ENV_UPSTREAM: &str = "MBA_UPSTREAM";

/// Immutable runtime configuration, built once at startup.
///
/// Cloned per request by the gate middleware (`from_fn_with_state`
/// requires the state to be `Clone`), which is why fields are cheap to
/// copy/clone (`Hash` and `SocketAddr` are `Copy`, `String` is `Clone`).
#[derive(Clone)]
pub struct Config {
    /// Validated IP socket address the service listens on.
    bind_address: SocketAddr,
    /// BLAKE3 digest of the configured password. The session cookie
    /// carries this same value as hex; a request authenticates by
    /// presenting a cookie that matches it. Storing the digest (not the
    /// password) keeps the plaintext out of memory after startup and out
    /// of the browser jar.
    session: Hash,
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
    /// socket address, `MBA_PASSWORD` is empty, or `MBA_UPSTREAM` is not a
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
        let password = std::env::var(ENV_PASSWORD).unwrap_or_default();
        let upstream = std::env::var(ENV_UPSTREAM).unwrap_or_default();
        Self::from_values_and_address(&password, &upstream, &address)
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

    /// Validated IP socket address the service listens on.
    #[must_use]
    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    /// Build and validate the complete runtime configuration.
    fn from_values_and_address(
        password: &str,
        upstream: &str,
        address: &str,
    ) -> Result<Self, ConfigError> {
        if password.is_empty() {
            return Err(ConfigError::MissingPassword);
        }
        let upstream = validate_upstream(upstream)?;
        let address = validate_address(address)?;
        Ok(Self {
            bind_address: address,
            session: blake3::hash(password.as_bytes()),
            upstream,
        })
    }

    /// Expected session-cookie digest.
    pub(crate) fn session(&self) -> &Hash {
        &self.session
    }

    /// Validated upstream URL, ready for `ReverseProxy::new`.
    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the session digest: it is a password-equivalent
        // bearer token, so an accidental log must not leak it.
        f.debug_struct("Config")
            .field("bind_address", &self.bind_address)
            .field("session", &"<redacted>")
            .field("upstream", &self.upstream)
            .finish()
    }
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
    /// `MBA_PASSWORD` was unset or empty.
    MissingPassword,
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
            Self::MissingPassword => {
                write!(f, "`{ENV_PASSWORD}` must be set to a non-empty value")
            }
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
        assert_eq!(config.session(), &blake3::hash(b"hunter2"));
    }

    #[test]
    fn surrounding_whitespace_in_upstream_is_trimmed() {
        let config = Config::from_values("hunter2", "  http://app:2001  ").unwrap();
        assert_eq!(config.upstream(), "http://app:2001/");
    }
}
