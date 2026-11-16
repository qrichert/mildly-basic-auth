//! Startup configuration, validated once from the environment.
//!
//! `Config` is only constructible when every value is valid, so the rest
//! of the program never has to defend against a half-configured state.

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use axum::body::Bytes;
use axum::http::Uri;
use blake3::Hash;
use ipnet::IpNet;

use crate::client_ip::normalize_ip;

/// Embedded password-page template. Compiled into the binary so rendering
/// has no runtime asset dependency.
const WALL_TEMPLATE: &str = include_str!("template.html");
/// Default password-page icon. The continuation indentation
/// preserves the built-in template's rendered formatting when
/// replacing `{{ICON}}`.
const DEFAULT_TEMPLATE_ICON: &str = r#"<!-- Lock icon from Lucide (https://lucide.dev/icons/lock), ISC license. -->
        <svg
          style="margin: 0 auto; width: 1.5rem; height: 1.5rem;"
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <rect width="18" height="11" x="3" y="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>"#;
/// Default IP socket address the service listens on.
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8000";
/// Refill once per second without prolonged shared-IP lockouts.
const DEFAULT_LOGIN_THROTTLE_RATE: f64 = 1.0;
/// Allow ordinary password retries before slowing sustained guessing.
const DEFAULT_LOGIN_THROTTLE_BURST: u32 = 10;
/// Environment variable holding the IP socket address to listen on.
const ENV_ADDRESS: &str = "MBA_ADDRESS";
/// Environment variable setting replenished login attempts per second.
const ENV_LOGIN_THROTTLE_RATE: &str = "MBA_LOGIN_THROTTLE_RATE";
/// Environment variable setting the maximum immediate login attempts.
const ENV_LOGIN_THROTTLE_BURST: &str = "MBA_LOGIN_THROTTLE_BURST";
/// Environment variable holding a plain password. At least one of the
/// `MBA_PASSWORD*` family (this or a `MBA_PASSWORD_<label>`) must be
/// non-empty.
const ENV_PASSWORD: &str = "MBA_PASSWORD";
/// Prefix for additional password variables, e.g. `MBA_PASSWORD_BOB`. The
/// suffix is a free-form label (typically who the password belongs to);
/// it carries no meaning at request time. Reserved: future config must
/// not land under `MBA_PASSWORD_*` or it would be read as a password.
const ENV_PASSWORD_PREFIX: &str = "MBA_PASSWORD_";
/// Environment variable holding an optional custom password-page template
/// path. The file is read once and all login states render at startup.
const ENV_TEMPLATE_FILE: &str = "MBA_TEMPLATE_FILE";
/// Environment variable overriding the password page's document language.
const ENV_TEMPLATE_PAGE_LANGUAGE: &str = "MBA_TEMPLATE_PAGE_LANGUAGE";
/// Environment variable overriding the password page's title.
const ENV_TEMPLATE_PAGE_TITLE: &str = "MBA_TEMPLATE_PAGE_TITLE";
/// Environment variable overriding the complete password-page icon HTML
/// fragment. Unlike template text, the fragment is inserted unescaped.
const ENV_TEMPLATE_ICON: &str = "MBA_TEMPLATE_ICON";
/// Environment variable overriding the password field's accessible label.
const ENV_TEMPLATE_PASSWORD_LABEL: &str = "MBA_TEMPLATE_PASSWORD_LABEL";
/// Environment variable overriding the password field's placeholder.
const ENV_TEMPLATE_PASSWORD_PLACEHOLDER: &str = "MBA_TEMPLATE_PASSWORD_PLACEHOLDER";
/// Environment variable overriding the failed-login message. In the
/// built-in page it is announced to assistive technologies only and not
/// shown visually (sighted users see the invalid-field icon and red
/// border); a custom template may render `{{WRONG_PASSWORD_MESSAGE}}`
/// wherever it likes.
const ENV_TEMPLATE_WRONG_PASSWORD_MESSAGE: &str = "MBA_TEMPLATE_WRONG_PASSWORD_MESSAGE";
/// Environment variable overriding the visible message when a login
/// attempt is throttled without checking its password.
const ENV_TEMPLATE_THROTTLED_MESSAGE: &str = "MBA_TEMPLATE_THROTTLED_MESSAGE";
/// Environment variable overriding the submit button's text.
const ENV_TEMPLATE_SUBMIT_BUTTON_TEXT: &str = "MBA_TEMPLATE_SUBMIT_BUTTON_TEXT";
/// Environment variable listing IP addresses and CIDRs allowed to supply
/// client identity through `X-Forwarded-For`. Unset means no proxies are
/// trusted; private addresses and loopback receive no implicit trust.
const ENV_TRUSTED_PROXY_IPS: &str = "MBA_TRUSTED_PROXY_IPS";
/// Environment variable holding the upstream URL (required, absolute
/// `http(s)://host[:port]`).
const ENV_UPSTREAM: &str = "MBA_UPSTREAM";

/// Immutable runtime configuration, built once at startup.
///
/// Cloned per request by the gate middleware (`from_fn_with_state`
/// requires the state to be `Clone`), which is why fields stay cheap to
/// clone (`SocketAddr` is `Copy`; `Bytes` is reference-counted; each
/// non-empty `Vec` and `String` clones one heap allocation per request).
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
    /// Positive, finite refill rate with a representable retry delay.
    login_throttle_rate: f64,
    /// Positive capacity with an exact `f64` token count.
    login_throttle_burst: u32,
    /// Normalized proxy networks allowed to supply forwarded identity.
    /// Empty by default, requiring explicit trust configuration.
    trusted_proxy_cidrs: Vec<IpNet>,
    /// Validated absolute `http(s)://host[:port]` upstream. Stored as a
    /// `String` (not `Uri`) because `ReverseProxy::new` takes one generic
    /// `S: Into<String>` for both arguments; a `&Uri` would not satisfy
    /// that bound.
    upstream: String,
    /// Password page rendered once at startup without a login error.
    /// `Bytes` keeps per-response and per-state clones cheap despite the
    /// page's size.
    wall: Bytes,
    /// The same password-page template rendered with a failed-login error.
    wrong_password_wall: Bytes,
    /// Password page explaining that a login attempt was not checked.
    throttled_wall: Bytes,
}

impl Config {
    /// Build from the process environment. Delegates to the same pure
    /// validation as [`Config::from_values`] so tests do not have to
    /// mutate process-wide env (which is `unsafe` in Rust 2024).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `MBA_ADDRESS` is not a valid non-zero
    /// IP socket address, no `MBA_PASSWORD*` variable has a non-empty
    /// UTF-8 value, two of them share the same value, a custom template
    /// file is unusable, a template override is not valid Unicode,
    /// a login-throttle setting is invalid or out of range,
    /// `MBA_TRUSTED_PROXY_IPS` is not a valid Unicode list of IP
    /// addresses or CIDRs, or `MBA_UPSTREAM` is not a valid absolute
    /// HTTP(S) URL.
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
        let custom_template = load_custom_template(std::env::var_os(ENV_TEMPLATE_FILE))?;
        let template = custom_template.as_deref().unwrap_or(WALL_TEMPLATE);
        let template_values = TemplateValues::from_env(std::env::vars_os())?;
        let upstream = std::env::var(ENV_UPSTREAM).unwrap_or_default();
        let login_throttle_rate =
            parse_login_throttle_rate(std::env::var_os(ENV_LOGIN_THROTTLE_RATE))?;
        let login_throttle_burst =
            parse_login_throttle_burst(std::env::var_os(ENV_LOGIN_THROTTLE_BURST))?;
        let trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs(std::env::var_os(ENV_TRUSTED_PROXY_IPS))?;
        let mut config = Self::from_passwords_address_template_and_values(
            &passwords,
            &upstream,
            &address,
            template,
            &template_values,
        )?;
        config.trusted_proxy_cidrs = trusted_proxy_cidrs;
        config.login_throttle_rate = login_throttle_rate;
        config.login_throttle_burst = login_throttle_burst;
        Ok(config)
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
        Self::from_passwords_address_template_and_values(
            passwords,
            upstream,
            address,
            WALL_TEMPLATE,
            &TemplateValues::default(),
        )
    }

    /// Build and validate the complete runtime configuration with
    /// explicit password-page template values.
    fn from_passwords_address_template_and_values(
        passwords: &[&str],
        upstream: &str,
        address: &str,
        template: &str,
        template_values: &TemplateValues,
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
        let wall = render_template(template, template_values, LoginState::Neutral);
        let wrong_password_wall =
            render_template(template, template_values, LoginState::WrongPassword);
        let throttled_wall = render_template(template, template_values, LoginState::Throttled);
        Ok(Self {
            bind_address: address,
            sessions,
            login_throttle_rate: DEFAULT_LOGIN_THROTTLE_RATE,
            login_throttle_burst: DEFAULT_LOGIN_THROTTLE_BURST,
            trusted_proxy_cidrs: Vec::new(),
            upstream,
            wall,
            wrong_password_wall,
            throttled_wall,
        })
    }

    /// Expected session-cookie digests. A request authenticates by matching
    /// any of them.
    pub(crate) fn sessions(&self) -> &[Hash] {
        &self.sessions
    }

    /// Validated number of login attempts replenished per second.
    pub(crate) fn login_throttle_rate(&self) -> f64 {
        self.login_throttle_rate
    }

    /// Validated maximum of immediately available login attempts.
    pub(crate) fn login_throttle_burst(&self) -> u32 {
        self.login_throttle_burst
    }

    /// Networks explicitly trusted to supply forwarded client identity.
    pub(crate) fn trusted_proxy_cidrs(&self) -> &[IpNet] {
        &self.trusted_proxy_cidrs
    }

    /// Validated upstream URL, ready for `ReverseProxy::new`.
    pub(crate) fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Rendered password page, ready to use as an HTML response body.
    pub(crate) fn wall(&self) -> &Bytes {
        &self.wall
    }

    /// Rendered password page with the failed-login state visible.
    pub(crate) fn wrong_password_wall(&self) -> &Bytes {
        &self.wrong_password_wall
    }

    /// Rendered password page with the throttled-login message visible.
    pub(crate) fn throttled_wall(&self) -> &Bytes {
        &self.throttled_wall
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the session digests: each is a password-equivalent
        // bearer token, so an accidental log must not leak it.
        f.debug_struct("Config")
            .field("bind_address", &self.bind_address)
            .field("sessions", &"<redacted>")
            .field("login_throttle_rate", &self.login_throttle_rate)
            .field("login_throttle_burst", &self.login_throttle_burst)
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .field("upstream", &self.upstream)
            .field("wall", &"<rendered HTML>")
            .field("wrong_password_wall", &"<rendered HTML>")
            .field("throttled_wall", &"<rendered HTML>")
            .finish()
    }
}

/// Parse positive attempts per second with a representable retry delay.
///
/// Unset uses the default; empty or invalid values fail startup.
/// For example, `" 0.5 "` becomes `0.5`: one refill per two seconds.
fn parse_login_throttle_rate(value: Option<OsString>) -> Result<f64, ConfigError> {
    let Some(value) = value else {
        return Ok(DEFAULT_LOGIN_THROTTLE_RATE);
    };
    let invalid = |reason| ConfigError::InvalidLoginThrottleRate { reason };
    let value = value
        .into_string()
        .map_err(|_| invalid("must contain valid Unicode"))?;
    let rate = value
        .trim()
        .parse::<f64>()
        .map_err(|_| invalid("must be a positive, finite number of attempts per second"))?;
    if !rate.is_finite() || rate <= 0.0 {
        return Err(invalid(
            "must be a positive, finite number of attempts per second",
        ));
    }
    // `u64::MAX` rounds up to 2^64 in `f64`, so that exact boundary
    // must be excluded before retry seconds are converted to `u64`.
    if (1.0 / rate).ceil() >= 18_446_744_073_709_551_616.0 {
        return Err(invalid(
            "is too small: the rounded-up retry delay must be less than 18446744073709551616 seconds",
        ));
    }
    Ok(rate)
}

/// Parse a positive burst capacity that remains exactly countable.
///
/// Unset uses the default. For example, `" 20 "` becomes `20`; zero and
/// values above `u32::MAX` fail without rounding or disabling limits.
fn parse_login_throttle_burst(value: Option<OsString>) -> Result<u32, ConfigError> {
    let Some(value) = value else {
        return Ok(DEFAULT_LOGIN_THROTTLE_BURST);
    };
    let invalid = |reason| ConfigError::InvalidLoginThrottleBurst { reason };
    let value = value
        .into_string()
        .map_err(|_| invalid("must contain valid Unicode"))?;
    let burst = value
        .trim()
        .parse::<u32>()
        .map_err(|_| invalid("must be an integer between 1 and 4294967295"))?;
    if burst == 0 {
        return Err(invalid("must be an integer between 1 and 4294967295"));
    }
    Ok(burst)
}

/// Parse explicit proxy trust networks; unset or blank means no trust.
///
/// Accept comma-separated IPv4/IPv6 addresses and CIDRs, trimming
/// surrounding whitespace. Exact addresses become `/32` or `/128`.
/// Invalid or non-Unicode input and empty entries in a non-empty list
/// fail startup; hostnames, ports, and scope IDs are not accepted.
/// Duplicate and overlapping entries are harmless. `/0` is valid and
/// trusts every address in that family.
///
/// Normalize IPv4-mapped exact addresses and networks entirely within
/// `::ffff:0:0/96` to IPv4. Other IPv6 networks keep their family, so
/// `::/0` does not implicitly trust IPv4 peers.
///
/// For example, `192.0.2.1,::ffff:192.0.2.123/120` becomes
/// `192.0.2.1/32,192.0.2.0/24`. Other IPv6 networks retain their family.
fn parse_trusted_proxy_cidrs(value: Option<OsString>) -> Result<Vec<IpNet>, ConfigError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let value = value
        .into_string()
        .map_err(|_| ConfigError::InvalidTrustedProxyIps {
            reason: "must contain valid Unicode".to_owned(),
        })?;
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    value
        .split(',')
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.trim();
            let invalid = |reason: &str| ConfigError::InvalidTrustedProxyIps {
                reason: format!("entry {} {reason}: {entry:?}", index + 1),
            };
            if entry.is_empty() {
                return Err(invalid("must not be empty"));
            }
            if let Ok(ip) = entry.parse::<IpAddr>() {
                return Ok(IpNet::from(normalize_ip(ip)));
            }
            let network = entry
                .parse::<IpNet>()
                .map_err(|_| invalid("must be an IP address or CIDR without a port or scope ID"))?
                .trunc();
            if let IpNet::V6(ipv6) = network {
                // Only networks inside `::ffff:0:0/96` represent IPv4.
                // Wider IPv6 networks must not acquire IPv4 trust
                // implicitly.
                if ipv6.prefix_len() >= 96
                    && let Some(ipv4) = ipv6.network().to_ipv4_mapped()
                {
                    // A validated prefix in `96..=128` becomes `0..=32`.
                    return Ok(IpNet::new_assert(IpAddr::V4(ipv4), ipv6.prefix_len() - 96));
                }
            }
            Ok(network)
        })
        .collect()
}

/// Configurable values substituted into the password-page template.
/// Text fields are HTML-escaped; `icon_html` is inserted verbatim.
struct TemplateValues {
    page_language: String,
    page_title: String,
    icon_html: String,
    password_label: String,
    password_placeholder: String,
    wrong_password_message: String,
    throttled_message: String,
    submit_button_text: String,
}

impl TemplateValues {
    /// Read fixed template overrides from the environment. Unknown
    /// `MBA_TEMPLATE_*` variables are deliberately ignored: the prefix is
    /// reserved for explicit settings, including the future template file.
    fn from_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Result<Self, ConfigError> {
        let mut values = Self::default();
        for (name, value) in vars {
            let Some(name) = name.to_str() else { continue };
            let target = match name {
                ENV_TEMPLATE_PAGE_LANGUAGE => &mut values.page_language,
                ENV_TEMPLATE_PAGE_TITLE => &mut values.page_title,
                ENV_TEMPLATE_ICON => &mut values.icon_html,
                ENV_TEMPLATE_PASSWORD_LABEL => &mut values.password_label,
                ENV_TEMPLATE_PASSWORD_PLACEHOLDER => &mut values.password_placeholder,
                ENV_TEMPLATE_WRONG_PASSWORD_MESSAGE => &mut values.wrong_password_message,
                ENV_TEMPLATE_THROTTLED_MESSAGE => &mut values.throttled_message,
                ENV_TEMPLATE_SUBMIT_BUTTON_TEXT => &mut values.submit_button_text,
                _ => continue,
            };
            *target = value
                .into_string()
                .map_err(|_| ConfigError::InvalidTemplateText {
                    variable: name.to_owned(),
                })?;
        }
        Ok(values)
    }
}

impl Default for TemplateValues {
    fn default() -> Self {
        Self {
            page_language: "en".to_owned(),
            page_title: "Welcome!".to_owned(),
            icon_html: DEFAULT_TEMPLATE_ICON.to_owned(),
            password_label: "Password".to_owned(),
            password_placeholder: "password".to_owned(),
            wrong_password_message: "Wrong password.".to_owned(),
            throttled_message: "Too many attempts. Please try again shortly.".to_owned(),
            submit_button_text: "Enter".to_owned(),
        }
    }
}

/// Load an explicitly configured template, returning `None` when unset.
/// Custom files must contain non-whitespace UTF-8 so a definite
/// misconfiguration cannot turn the login page into an empty response.
fn load_custom_template(path: Option<OsString>) -> Result<Option<String>, ConfigError> {
    let Some(path) = path else { return Ok(None) };
    let path = PathBuf::from(path);
    let invalid = |reason: String| ConfigError::InvalidTemplateFile {
        path: path.clone(),
        reason,
    };

    if path.as_os_str().is_empty() {
        return Err(invalid("path must not be empty".to_owned()));
    }

    let template = std::fs::read_to_string(&path).map_err(|error| invalid(error.to_string()))?;
    if template.trim().is_empty() {
        return Err(invalid(
            "template must contain non-whitespace HTML".to_owned(),
        ));
    }
    Ok(Some(template))
}

/// Page states distinguish unchecked from wrong passwords.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginState {
    Neutral,
    WrongPassword,
    Throttled,
}

/// Render known markers from one template for the requested login state,
/// preserving unknown or absent markers. Scanning only the original
/// template ensures marker-like text in an override is not interpreted
/// recursively.
fn render_template(template: &str, values: &TemplateValues, state: LoginState) -> Bytes {
    let mut rendered = String::with_capacity(template.len());
    let mut remaining = template;
    let wrong_password = state == LoginState::WrongPassword;
    // String form of the invalid flag, for `aria-invalid`.
    let is_password_invalid = if wrong_password { "true" } else { "false" };
    // Focus after a rejected submission so its explanation is announced
    // through the field's accessible description (see `template.html`).
    let autofocus_attribute = if state == LoginState::Neutral {
        ""
    } else {
        "autofocus"
    };
    let wrong_password_message = if wrong_password {
        values.wrong_password_message.as_str()
    } else {
        ""
    };
    let throttled_message = if state == LoginState::Throttled {
        values.throttled_message.as_str()
    } else {
        ""
    };
    let throttled_hidden_attribute = if state == LoginState::Throttled {
        ""
    } else {
        "hidden"
    };

    while let Some(marker_start) = remaining.find("{{") {
        rendered.push_str(&remaining[..marker_start]);
        remaining = &remaining[marker_start..];

        // The icon owns its complete element and styling. Keep its raw
        // HTML replacement isolated so every other configurable value
        // remains escaped by default.
        if remaining.starts_with("{{ICON}}") {
            rendered.push_str(&values.icon_html);
            remaining = &remaining["{{ICON}}".len()..];
            continue;
        }

        let replacement = [
            ("{{PAGE_LANGUAGE}}", values.page_language.as_str()),
            ("{{PAGE_TITLE}}", values.page_title.as_str()),
            ("{{PASSWORD_LABEL}}", values.password_label.as_str()),
            (
                "{{PASSWORD_PLACEHOLDER}}",
                values.password_placeholder.as_str(),
            ),
            ("{{WRONG_PASSWORD_MESSAGE}}", wrong_password_message),
            ("{{THROTTLED_MESSAGE}}", throttled_message),
            ("{{SUBMIT_BUTTON_TEXT}}", values.submit_button_text.as_str()),
            ("{{_IS_PASSWORD_INVALID}}", is_password_invalid),
            ("{{_PASSWORD_AUTOFOCUS_ATTRIBUTE}}", autofocus_attribute),
            (
                "{{_THROTTLED_HIDDEN_ATTRIBUTE}}",
                throttled_hidden_attribute,
            ),
        ]
        .into_iter()
        .find(|(marker, _)| remaining.starts_with(marker));

        if let Some((marker, value)) = replacement {
            push_html_escaped(&mut rendered, value);
            remaining = &remaining[marker.len()..];
        } else {
            rendered.push_str("{{");
            remaining = &remaining[2..];
        }
    }
    rendered.push_str(remaining);
    Bytes::from(rendered)
}

/// Append plain text escaped for HTML text and double-quoted attributes.
fn push_html_escaped(rendered: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => rendered.push_str("&amp;"),
            '<' => rendered.push_str("&lt;"),
            '>' => rendered.push_str("&gt;"),
            '"' => rendered.push_str("&quot;"),
            '\'' => rendered.push_str("&#39;"),
            _ => rendered.push(character),
        }
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
    /// The rate was invalid or could not produce a bounded retry delay.
    InvalidLoginThrottleRate { reason: &'static str },
    /// The burst was not a positive integer representable as `u32`.
    InvalidLoginThrottleBurst { reason: &'static str },
    /// No `MBA_PASSWORD*` variable had a non-empty UTF-8 value.
    MissingPassword,
    /// Two `MBA_PASSWORD*` variables shared the same value, which would
    /// break independent revocation.
    DuplicatePassword,
    /// A configured template string override was not valid Unicode.
    InvalidTemplateText { variable: String },
    /// `MBA_TEMPLATE_FILE` did not name a usable UTF-8 template.
    InvalidTemplateFile { path: PathBuf, reason: String },
    /// The trusted-proxy list was non-Unicode or contained an invalid
    /// address, CIDR, or empty entry.
    InvalidTrustedProxyIps { reason: String },
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
            Self::InvalidLoginThrottleRate { reason } => {
                write!(f, "`{ENV_LOGIN_THROTTLE_RATE}` {reason}")
            }
            Self::InvalidLoginThrottleBurst { reason } => {
                write!(f, "`{ENV_LOGIN_THROTTLE_BURST}` {reason}")
            }
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
            Self::InvalidTemplateText { variable } => {
                write!(f, "`{variable}` must contain valid Unicode")
            }
            Self::InvalidTemplateFile { path, reason } => write!(
                f,
                "`{ENV_TEMPLATE_FILE}` is not a usable UTF-8 template ({reason}): \"{}\"",
                path.display(),
            ),
            Self::InvalidTrustedProxyIps { reason } => {
                write!(f, "`{ENV_TRUSTED_PROXY_IPS}` {reason}")
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A uniquely named file removed when its test ends.
    struct TemporaryTemplate {
        path: PathBuf,
    }

    impl TemporaryTemplate {
        /// Write `contents` to a new temporary template.
        fn new(contents: &[u8]) -> Self {
            static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mildly-basic-auth-config-test-{}-{sequence}",
                std::process::id(),
            ));
            std::fs::write(&path, contents).unwrap();
            Self { path }
        }
    }

    impl Drop for TemporaryTemplate {
        fn drop(&mut self) {
            _ = std::fs::remove_file(&self.path);
        }
    }

    /// Build template values from explicit variables without mutating the
    /// process-wide environment.
    fn template_values_from_vars(vars: &[(&str, &str)]) -> TemplateValues {
        TemplateValues::from_env(
            vars.iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .unwrap()
    }

    #[test]
    fn unset_login_throttle_rate_uses_the_default() {
        assert_eq!(
            parse_login_throttle_rate(None).unwrap().to_bits(),
            1.0_f64.to_bits(),
        );
    }

    #[test]
    fn login_throttle_rate_accepts_positive_finite_values() {
        for (value, expected) in [
            (" 0.5 \n", 0.5_f64),
            ("2e3", 2000.0),
            ("1.7976931348623157e308", f64::MAX),
        ] {
            assert_eq!(
                parse_login_throttle_rate(Some(value.into()))
                    .unwrap()
                    .to_bits(),
                expected.to_bits(),
            );
        }
    }

    #[test]
    fn login_throttle_rate_rejects_invalid_numbers() {
        for value in [
            "", " \t", "0", "-0", "-1", "NaN", "inf", "-inf", "1e309", "1e-999", "fast",
        ] {
            let error = parse_login_throttle_rate(Some(value.into())).unwrap_err();

            assert_matches!(error, ConfigError::InvalidLoginThrottleRate { .. });
            assert!(error.to_string().contains(ENV_LOGIN_THROTTLE_RATE));
        }
    }

    #[test]
    fn login_throttle_rate_requires_a_representable_retry_delay() {
        // At 2^-64 attempts per second, even one token needs 2^64
        // seconds. The next greater float has a representable delay.
        let boundary = 2.0_f64.powi(-64);
        let first_valid = boundary.next_up();
        assert_eq!(
            parse_login_throttle_rate(Some(first_valid.to_string().into()))
                .unwrap()
                .to_bits(),
            first_valid.to_bits(),
        );
        for value in [boundary.to_string(), "5e-324".to_owned()] {
            let error = parse_login_throttle_rate(Some(value.into())).unwrap_err();

            assert_matches!(error, ConfigError::InvalidLoginThrottleRate { .. });
            assert!(error.to_string().contains("retry delay"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn login_throttle_rate_rejects_non_unicode() {
        use std::os::unix::ffi::OsStringExt;

        let error = parse_login_throttle_rate(Some(OsString::from_vec(vec![0xff]))).unwrap_err();

        assert_matches!(error, ConfigError::InvalidLoginThrottleRate { .. });
        assert!(error.to_string().contains(ENV_LOGIN_THROTTLE_RATE));
        assert!(error.to_string().contains("Unicode"));
    }

    #[test]
    fn unset_login_throttle_burst_uses_the_default() {
        assert_eq!(parse_login_throttle_burst(None).unwrap(), 10);
    }

    #[test]
    fn login_throttle_burst_accepts_positive_u32_values() {
        for (value, expected) in [("1", 1), (" 20 \n", 20), ("4294967295", u32::MAX)] {
            assert_eq!(
                parse_login_throttle_burst(Some(value.into())).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn login_throttle_burst_rejects_invalid_numbers() {
        for value in [
            "",
            " \t",
            "0",
            "-1",
            "1.5",
            "NaN",
            "inf",
            "1e3",
            "4294967296",
        ] {
            let error = parse_login_throttle_burst(Some(value.into())).unwrap_err();

            assert_matches!(error, ConfigError::InvalidLoginThrottleBurst { .. });
            assert!(error.to_string().contains(ENV_LOGIN_THROTTLE_BURST));
            assert!(error.to_string().contains("between 1 and 4294967295"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn login_throttle_burst_rejects_non_unicode() {
        use std::os::unix::ffi::OsStringExt;

        let error = parse_login_throttle_burst(Some(OsString::from_vec(vec![0xff]))).unwrap_err();

        assert_matches!(error, ConfigError::InvalidLoginThrottleBurst { .. });
        assert!(error.to_string().contains(ENV_LOGIN_THROTTLE_BURST));
        assert!(error.to_string().contains("Unicode"));
    }

    #[test]
    fn single_password_constructor_enables_default_login_throttling() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();

        assert_eq!(config.login_throttle_rate().to_bits(), 1.0_f64.to_bits());
        assert_eq!(config.login_throttle_burst(), 10);
    }

    #[test]
    fn multiple_password_constructor_enables_default_login_throttling() {
        let config = Config::from_passwords(&["hunter2", "swordfish"], "http://app:2001").unwrap();

        assert_eq!(config.login_throttle_rate().to_bits(), 1.0_f64.to_bits());
        assert_eq!(config.login_throttle_burst(), 10);
    }

    #[test]
    fn unset_trusted_proxy_cidrs_are_empty() {
        assert_eq!(
            parse_trusted_proxy_cidrs(None).unwrap(),
            Vec::<IpNet>::new()
        );
    }

    #[test]
    fn empty_trusted_proxy_cidrs_are_empty() {
        for value in ["", " \n\t"] {
            assert_eq!(
                parse_trusted_proxy_cidrs(Some(value.into())).unwrap(),
                Vec::<IpNet>::new()
            );
        }
    }

    #[test]
    fn trusted_proxy_addresses_become_host_networks() {
        let networks = parse_trusted_proxy_cidrs(Some("192.0.2.1, 2001:db8::1".into())).unwrap();

        assert_eq!(
            networks,
            [
                "192.0.2.1/32".parse().unwrap(),
                "2001:db8::1/128".parse().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_cidrs_trim_surrounding_whitespace() {
        let networks =
            parse_trusted_proxy_cidrs(Some(" \t 192.0.2.0/24 , \n 2001:db8::/32 \t ".into()))
                .unwrap();

        assert_eq!(
            networks,
            [
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_cidrs_discard_host_bits() {
        let networks =
            parse_trusted_proxy_cidrs(Some("192.0.2.123/24,2001:db8::1234/32".into())).unwrap();

        assert_eq!(
            networks,
            [
                "192.0.2.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_cidrs_accept_broad_ranges() {
        let networks = parse_trusted_proxy_cidrs(Some("0.0.0.0/0,::/0".into())).unwrap();

        assert_eq!(
            networks,
            ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
        );
    }

    #[test]
    fn mapped_trusted_proxy_addresses_become_ipv4_host_networks() {
        let networks = parse_trusted_proxy_cidrs(Some("::ffff:192.0.2.1".into())).unwrap();

        assert_eq!(networks, ["192.0.2.1/32".parse().unwrap()]);
    }

    #[test]
    fn mapped_trusted_proxy_cidrs_become_ipv4_networks() {
        let networks = parse_trusted_proxy_cidrs(Some(
            "::ffff:192.0.2.123/120,::ffff:0:0/96,::ffff:192.0.2.1/128".into(),
        ))
        .unwrap();

        assert_eq!(
            networks,
            [
                "192.0.2.0/24".parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
                "192.0.2.1/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_cidrs_preserve_other_ipv6_networks() {
        let networks =
            parse_trusted_proxy_cidrs(Some("::ffff:192.0.2.1/95,::/0,::192.0.2.1".into())).unwrap();

        assert_eq!(
            networks,
            [
                "::fffe:0:0/95".parse().unwrap(),
                "::/0".parse().unwrap(),
                "::192.0.2.1/128".parse().unwrap()
            ]
        );
        assert!(!networks[1].contains(&"192.0.2.1".parse::<std::net::IpAddr>().unwrap()));
    }

    #[test]
    fn trusted_proxy_cidrs_keep_duplicates_and_overlaps() {
        let networks =
            parse_trusted_proxy_cidrs(Some("192.0.2.0/24,192.0.2.0/24,192.0.2.1".into())).unwrap();

        assert_eq!(
            networks,
            [
                "192.0.2.0/24".parse().unwrap(),
                "192.0.2.0/24".parse().unwrap(),
                "192.0.2.1/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_cidrs_reject_empty_entries() {
        for (value, position) in [
            (",192.0.2.1", 1),
            ("192.0.2.1, ,198.51.100.1", 2),
            ("192.0.2.1,", 2),
        ] {
            let error = parse_trusted_proxy_cidrs(Some(value.into())).unwrap_err();

            assert_matches!(&error, ConfigError::InvalidTrustedProxyIps { reason }
                if reason.contains(&format!("entry {position}")) && reason.contains("empty"));
            assert!(error.to_string().contains(ENV_TRUSTED_PROXY_IPS));
        }
    }

    #[test]
    fn trusted_proxy_cidrs_reject_invalid_entries() {
        for value in [
            "192.0.2.1/33",
            "2001:db8::1/129",
            "192.0.2.1/-1",
            "192.0.2.1/",
            "localhost",
            "192.0.2.1:8000",
            "[2001:db8::1]:8000",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1/24/32",
        ] {
            let error =
                parse_trusted_proxy_cidrs(Some(format!("127.0.0.1,{value}").into())).unwrap_err();

            assert_matches!(&error, ConfigError::InvalidTrustedProxyIps { reason }
                if reason.contains("entry 2") && reason.contains(value));
            assert!(error.to_string().contains(ENV_TRUSTED_PROXY_IPS));
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_proxy_cidrs_reject_non_unicode_values() {
        use std::os::unix::ffi::OsStringExt;

        let error = parse_trusted_proxy_cidrs(Some(OsString::from_vec(vec![0xff]))).unwrap_err();

        assert_matches!(&error, ConfigError::InvalidTrustedProxyIps { reason }
            if reason.contains("Unicode"));
        assert!(error.to_string().contains(ENV_TRUSTED_PROXY_IPS));
    }

    #[test]
    fn single_password_constructor_defaults_to_no_trusted_proxies() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();

        assert_eq!(config.trusted_proxy_cidrs(), []);
    }

    #[test]
    fn multiple_password_constructor_defaults_to_no_trusted_proxies() {
        let config = Config::from_passwords(&["hunter2", "swordfish"], "http://app:2001").unwrap();

        assert_eq!(config.trusted_proxy_cidrs(), []);
    }

    #[test]
    fn debug_includes_trusted_proxy_networks() {
        let mut config = Config::from_values("hunter2", "http://app:2001").unwrap();
        config.trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs(Some("192.0.2.0/24,2001:db8::/32".into())).unwrap();

        let debug = format!("{config:?}");

        assert!(debug.contains("trusted_proxy_cidrs"));
        assert!(debug.contains("192.0.2.0/24"));
        assert!(debug.contains("2001:db8::/32"));
    }

    #[test]
    fn debug_still_redacts_all_session_digests() {
        let config = Config::from_passwords(&["hunter2", "swordfish"], "http://app:2001").unwrap();

        let debug = format!("{config:?}");

        assert!(debug.contains("<redacted>"));
        for session in config.sessions() {
            assert!(!debug.contains(&session.to_hex().to_string()));
        }
    }

    #[test]
    fn valid_values_build_a_config() {
        assert!(Config::from_values("hunter2", "http://app:2001").is_ok());
    }

    #[test]
    fn default_template_text_renders_the_existing_page_text() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        assert!(wall.contains("<html lang=\"en\">"));
        assert!(wall.contains("<title>Welcome!</title>"));
        assert!(wall.contains(">Password</label>"));
        assert!(wall.contains("placeholder=\"password\""));
        assert!(wall.contains(">Enter</button>"));
    }

    #[test]
    fn default_wall_hides_the_wrong_password_error() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        assert!(wall.contains("aria-invalid=\"false\""));
        assert!(!wall.contains("Wrong password."));
    }

    #[test]
    fn wrong_password_wall_shows_the_error() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wrong_password_wall()).unwrap();

        assert!(wall.contains("aria-invalid=\"true\""));
        assert!(wall.contains("Wrong password."));
    }

    #[test]
    fn wrong_password_wall_autofocuses_the_field() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wrong_password_wall()).unwrap();

        // Scope the check to the `<input>` start tag: the page also carries
        // a marker comment that mentions `autofocus`.
        let tag = &wall[wall.find("<input").unwrap()..];
        let tag = &tag[..tag.find('>').unwrap()];
        assert!(tag.contains("autofocus"));
    }

    #[test]
    fn default_wall_does_not_autofocus() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        let tag = &wall[wall.find("<input").unwrap()..];
        let tag = &tag[..tag.find('>').unwrap()];
        assert!(!tag.contains("autofocus"));
    }

    #[test]
    fn throttled_wall_shows_a_visible_message() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.throttled_wall()).unwrap();
        let message = &wall[wall.find("<p\n").unwrap()..];
        let message = &message[..message.find("</p>").unwrap()];
        let tag = &message[..message.find('>').unwrap()];

        assert!(tag.contains("class=\"throttled-message\""));
        assert!(!tag.contains("hidden"));
        assert!(message.contains("Too many attempts. Please try again shortly."));
    }

    #[test]
    fn throttled_wall_does_not_claim_the_password_was_wrong() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.throttled_wall()).unwrap();

        assert!(wall.contains("aria-invalid=\"false\""));
        assert!(!wall.contains("Wrong password."));
    }

    #[test]
    fn throttled_wall_associates_the_message_with_the_focused_input() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.throttled_wall()).unwrap();
        let input = &wall[wall.find("<input").unwrap()..];
        let input = &input[..input.find('>').unwrap()];

        assert!(input.contains("autofocus"));
        assert!(input.contains("aria-describedby=\"password-error throttled-message\""));
        assert!(wall.contains("id=\"throttled-message\""));
        assert!(wall.contains("role=\"alert\""));
    }

    #[test]
    fn other_wall_states_hide_the_throttled_message() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        for wall in [config.wall(), config.wrong_password_wall()] {
            let wall = std::str::from_utf8(wall).unwrap();
            let message = &wall[wall.find("<p\n").unwrap()..];
            let tag = &message[..message.find('>').unwrap()];

            assert!(tag.contains("hidden"));
            assert!(!wall.contains("Too many attempts. Please try again shortly."));
        }
    }

    #[test]
    fn default_wall_includes_the_lock_icon_glyph() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        assert!(wall.contains(r#"<path d="M7 11V7a5 5 0 0 1 10 0v4">"#));
    }

    #[test]
    fn default_lock_icon_preserves_its_layout() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        assert!(wall.contains(r#"style="margin: 0 auto; width: 1.5rem; height: 1.5rem;""#));
    }

    #[test]
    fn built_in_wall_includes_the_alert_icon_glyph() {
        let config = Config::from_values("hunter2", "http://app:2001").unwrap();
        let wall = std::str::from_utf8(config.wall()).unwrap();

        // The lucide `circle-alert` outline; guards against the icon being
        // dropped. Actual visibility is verified in the browser.
        assert!(wall.contains(r#"<circle cx="12" cy="12" r="10">"#));
    }

    #[test]
    fn unset_template_file_has_no_override() {
        assert_eq!(load_custom_template(None).unwrap(), None);
    }

    #[test]
    fn custom_template_file_is_loaded() {
        let file = TemporaryTemplate::new(b"<p>{{PAGE_TITLE}}</p>");

        let template = load_custom_template(Some(file.path.clone().into_os_string())).unwrap();

        assert_eq!(template.as_deref(), Some("<p>{{PAGE_TITLE}}</p>"));
    }

    #[test]
    fn explicit_template_uses_configured_text() {
        let values = TemplateValues {
            page_title: "Custom title".to_owned(),
            ..TemplateValues::default()
        };

        let config = Config::from_passwords_address_template_and_values(
            &["hunter2"],
            "http://app:2001",
            DEFAULT_BIND_ADDRESS,
            "<title>{{PAGE_TITLE}}</title>",
            &values,
        )
        .unwrap();

        assert_eq!(config.wall(), "<title>Custom title</title>");
    }

    #[test]
    fn empty_template_file_path_is_rejected() {
        let result = load_custom_template(Some(OsString::new()));

        assert_matches!(
            result,
            Err(ConfigError::InvalidTemplateFile { path, reason })
                if path == PathBuf::new() && reason == "path must not be empty"
        );
    }

    #[test]
    fn missing_template_file_is_rejected() {
        let file = TemporaryTemplate::new(b"temporary");
        let path = file.path.clone();
        std::fs::remove_file(&path).unwrap();

        let result = load_custom_template(Some(path.clone().into_os_string()));

        assert_matches!(
            result,
            Err(ConfigError::InvalidTemplateFile { path: error_path, .. })
                if error_path == path
        );
    }

    #[test]
    fn non_utf8_template_file_is_rejected() {
        let file = TemporaryTemplate::new(&[0xff]);

        let result = load_custom_template(Some(file.path.clone().into_os_string()));

        assert_matches!(result, Err(ConfigError::InvalidTemplateFile { .. }));
    }

    #[test]
    fn empty_template_file_is_rejected() {
        let file = TemporaryTemplate::new(b"");

        let result = load_custom_template(Some(file.path.clone().into_os_string()));

        assert_matches!(
            result,
            Err(ConfigError::InvalidTemplateFile { reason, .. })
                if reason == "template must contain non-whitespace HTML"
        );
    }

    #[test]
    fn whitespace_only_template_file_is_rejected() {
        let file = TemporaryTemplate::new(b" \n\t");

        let result = load_custom_template(Some(file.path.clone().into_os_string()));

        assert_matches!(result, Err(ConfigError::InvalidTemplateFile { .. }));
    }

    #[test]
    fn page_language_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_PAGE_LANGUAGE, "fr")]);
        assert_eq!(text.page_language, "fr");
    }

    #[test]
    fn page_title_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_PAGE_TITLE, "Mon site")]);
        assert_eq!(text.page_title, "Mon site");
    }

    #[test]
    fn icon_variable_overrides_the_default() {
        let values = template_values_from_vars(&[(ENV_TEMPLATE_ICON, "🦖")]);
        assert_eq!(values.icon_html, "🦖");
    }

    #[test]
    fn password_label_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_PASSWORD_LABEL, "Mot de passe")]);
        assert_eq!(text.password_label, "Mot de passe");
    }

    #[test]
    fn password_placeholder_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_PASSWORD_PLACEHOLDER, "Secret")]);
        assert_eq!(text.password_placeholder, "Secret");
    }

    #[test]
    fn wrong_password_message_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(
            ENV_TEMPLATE_WRONG_PASSWORD_MESSAGE,
            "Mot de passe incorrect.",
        )]);
        assert_eq!(text.wrong_password_message, "Mot de passe incorrect.");
    }

    #[test]
    fn throttled_message_variable_overrides_the_rendered_default() {
        let values =
            template_values_from_vars(&[(ENV_TEMPLATE_THROTTLED_MESSAGE, "Réessayez bientôt.")]);
        let rendered = render_template("{{THROTTLED_MESSAGE}}", &values, LoginState::Throttled);

        assert_eq!(rendered, "Réessayez bientôt.");
    }

    #[test]
    fn empty_throttled_message_override_removes_the_text() {
        let values = template_values_from_vars(&[(ENV_TEMPLATE_THROTTLED_MESSAGE, "")]);
        let rendered = render_template(
            "before{{THROTTLED_MESSAGE}}after",
            &values,
            LoginState::Throttled,
        );

        assert_eq!(rendered, "beforeafter");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_throttled_message_is_rejected() {
        use std::os::unix::ffi::OsStringExt;

        let result = TemplateValues::from_env(
            [(
                OsString::from(ENV_TEMPLATE_THROTTLED_MESSAGE),
                OsString::from_vec(vec![0xff]),
            )]
            .into_iter(),
        );

        let Err(error) = result else {
            panic!("non-Unicode throttled message was accepted");
        };
        assert_matches!(error, ConfigError::InvalidTemplateText { variable }
            if variable == ENV_TEMPLATE_THROTTLED_MESSAGE);
    }

    #[test]
    fn submit_button_text_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_SUBMIT_BUTTON_TEXT, "Entrer")]);
        assert_eq!(text.submit_button_text, "Entrer");
    }

    #[test]
    fn empty_template_text_variable_overrides_the_default() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_PAGE_TITLE, "")]);
        assert_eq!(text.page_title, "");
    }

    #[test]
    fn unknown_template_variable_is_ignored() {
        let text = template_values_from_vars(&[(ENV_TEMPLATE_FILE, "/tmp/wall.html")]);
        assert_eq!(text.page_title, "Welcome!");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_template_text_is_rejected() {
        use std::os::unix::ffi::OsStringExt;

        let result = TemplateValues::from_env(
            [(
                OsString::from(ENV_TEMPLATE_PAGE_TITLE),
                OsString::from_vec(vec![0xff]),
            )]
            .into_iter(),
        );

        let Err(error) = result else {
            panic!("non-Unicode template text was accepted");
        };
        assert_matches!(
            error,
            ConfigError::InvalidTemplateText { variable }
                if variable == ENV_TEMPLATE_PAGE_TITLE
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_template_icon_is_rejected() {
        use std::os::unix::ffi::OsStringExt;

        let result = TemplateValues::from_env(
            [(
                OsString::from(ENV_TEMPLATE_ICON),
                OsString::from_vec(vec![0xff]),
            )]
            .into_iter(),
        );

        let Err(error) = result else {
            panic!("non-Unicode template icon was accepted");
        };
        assert_matches!(
            error,
            ConfigError::InvalidTemplateText { variable }
                if variable == ENV_TEMPLATE_ICON
        );
    }

    #[test]
    fn icon_html_is_rendered_verbatim() {
        let values = TemplateValues {
            icon_html: r#"<svg aria-hidden="true"></svg>"#.to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{ICON}}", &values, LoginState::Neutral);

        assert_eq!(rendered, r#"<svg aria-hidden="true"></svg>"#);
    }

    #[test]
    fn empty_icon_html_removes_the_marker() {
        let values = TemplateValues {
            icon_html: String::new(),
            ..TemplateValues::default()
        };

        let rendered = render_template("before{{ICON}}after", &values, LoginState::Neutral);

        assert_eq!(rendered, "beforeafter");
    }

    #[test]
    fn icon_html_is_not_rendered_recursively() {
        let values = TemplateValues {
            icon_html: "{{PAGE_TITLE}}".to_owned(),
            page_title: "Recursive title".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{ICON}}", &values, LoginState::Neutral);

        assert_eq!(rendered, "{{PAGE_TITLE}}");
    }

    #[test]
    fn template_values_are_html_escaped() {
        let text = TemplateValues {
            page_title: "&<>\"'".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{PAGE_TITLE}}", &text, LoginState::Neutral);

        assert_eq!(rendered, "&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn wrong_password_message_is_html_escaped() {
        let text = TemplateValues {
            wrong_password_message: "&<>\"'".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template(
            "{{WRONG_PASSWORD_MESSAGE}}",
            &text,
            LoginState::WrongPassword,
        );

        assert_eq!(rendered, "&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn throttled_message_is_html_escaped() {
        let values = TemplateValues {
            throttled_message: "&<>\"'".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{THROTTLED_MESSAGE}}", &values, LoginState::Throttled);

        assert_eq!(rendered, "&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn throttled_message_is_not_rendered_recursively() {
        let values = TemplateValues {
            throttled_message: "{{WRONG_PASSWORD_MESSAGE}}".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{THROTTLED_MESSAGE}}", &values, LoginState::Throttled);

        assert_eq!(rendered, "{{WRONG_PASSWORD_MESSAGE}}");
    }

    #[test]
    fn template_values_are_not_rendered_recursively() {
        let text = TemplateValues {
            page_title: "{{SUBMIT_BUTTON_TEXT}}".to_owned(),
            submit_button_text: "Submit".to_owned(),
            ..TemplateValues::default()
        };

        let rendered = render_template("{{PAGE_TITLE}}", &text, LoginState::Neutral);

        assert_eq!(rendered, "{{SUBMIT_BUTTON_TEXT}}");
    }

    #[test]
    fn template_without_known_markers_is_unchanged() {
        for state in [
            LoginState::Neutral,
            LoginState::WrongPassword,
            LoginState::Throttled,
        ] {
            let rendered = render_template("<p>{{UNKNOWN}}</p>", &TemplateValues::default(), state);
            assert_eq!(rendered, "<p>{{UNKNOWN}}</p>");
        }
    }

    #[test]
    fn renderer_leaves_an_empty_template_empty() {
        let rendered = render_template("", &TemplateValues::default(), LoginState::Neutral);
        assert!(rendered.is_empty());
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
