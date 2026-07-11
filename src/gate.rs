//! The authentication gate.
//!
//! Wraps the reverse proxy: authenticated requests pass through
//! transparently (body untouched); everything else meets the password
//! wall. The gate reads only the `Cookie` *header* on the fast path, so
//! streaming, `WebSockets`, and SSE are preserved.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::header::{COOKIE, HOST, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use blake3::Hash;
use cookie::Cookie;

use crate::config::Config;

/// Embedded password page. Compiled in via `include_str!`, so the binary
/// carries no runtime asset dependency.
const WALL: &str = include_str!("index.html");

/// Session cookie name. Deliberately not `password`/`wall`: those words
/// trip iOS Safari's Intelligent Tracking Prevention, which silently
/// drops the cookie. `mba` also matches the `MBA_` env prefix.
const COOKIE_NAME: &str = "mba";

/// Session lifetime, in seconds. Bounded (not "forever") because a long
/// `Max-Age` can also trigger iOS ITP.
const SESSION_MAX_AGE_SECS: u64 = 60 * 60 * 24 * 30; // 30 days.

/// Cap on the login form body we buffer. This branch is public and
/// attacker-controlled; a password form is tiny, so 8 KiB is generous.
const MAX_LOGIN_BODY: usize = 8 * 1024;

const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

/// Authenticate, then either transparently proxy or serve the wall.
///
/// The request is split once. On the authenticated path the body is
/// reattached untouched and streamed to the upstream; only the
/// unauthenticated `POST` branch consumes the body, which never reaches
/// the upstream.
pub(crate) async fn gate(State(config): State<Config>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();

    let cookies = parse_cookies(&parts.headers);
    if authenticate(&cookies, config.session()) {
        sanitize_request_headers(&mut parts, &cookies);
        return next.run(Request::from_parts(parts, body)).await;
    }

    if parts.method == Method::POST {
        return handle_login(&parts, body, config.session()).await;
    }

    wall_response()
}

/// Rewrite the outgoing headers of an authenticated request: strip our
/// own `mba` cookie and set the forwarding headers. Header-only, so the
/// body still streams untouched.
fn sanitize_request_headers(parts: &mut Parts, cookies: &[CookiePair]) {
    match sanitized_cookie_header(cookies) {
        Some(value) => parts.headers.insert(COOKIE, value),
        None => parts.headers.remove(COOKIE),
    };
    // For HTTP/2 the authority lives on the URI, not a `Host` header.
    let authority = parts.uri.authority().map(Authority::as_str);
    rewrite_forwarding_headers(&mut parts.headers, authority);
}

/// Handle an unauthenticated `POST`: verify the submitted password and
/// either start a session or re-serve the wall. The body is capped and
/// never forwarded upstream.
async fn handle_login(parts: &Parts, body: Body, session: &Hash) -> Response {
    let Ok(bytes) = to_bytes(body, MAX_LOGIN_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    match extract_submitted_password(&bytes) {
        Some(password) if password_matches(&password, session) => login_success(parts, session),
        _ => wall_response(),
    }
}

/// Session cookie + `303` back to the originally requested URL (Post/
/// Redirect/Get), so the follow-up GET is proxied through.
fn login_success(parts: &Parts, session: &Hash) -> Response {
    let location = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let secure = is_https(&parts.headers);
    (
        [(SET_COOKIE, build_set_cookie(session, secure))],
        Redirect::to(location),
    )
        .into_response()
}

/// The password page: `401` with an explicit HTML content type, and
/// deliberately no `WWW-Authenticate` (which would pop the browser's
/// native Basic-auth dialog — the very UX we're replacing).
fn wall_response() -> Response {
    (StatusCode::UNAUTHORIZED, Html(WALL)).into_response()
}

/// A single parsed request cookie: decoded name/value for classification
/// (matching the same decoding an attacker would exploit) plus the
/// original raw `name=value` substring for byte-faithful forwarding.
struct CookiePair {
    name: String,
    value: String,
    raw: String,
}

/// Parse every `Cookie` header field into ordered pairs.
///
/// Malformed input is silently skipped: a non-UTF-8 field, or a pair
/// `Cookie::parse_encoded` rejects, never authenticates and is never
/// forwarded (we can't prove an undecodable pair isn't a smuggled `mba`).
fn parse_cookies(headers: &HeaderMap) -> Vec<CookiePair> {
    let mut cookies = Vec::new();
    for field in headers.get_all(COOKIE) {
        let Ok(field) = field.to_str() else { continue };
        for raw in field.split(';') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let Ok(parsed) = Cookie::parse_encoded(raw) else {
                continue;
            };
            cookies.push(CookiePair {
                name: parsed.name().to_owned(),
                value: parsed.value().to_owned(),
                raw: raw.to_owned(),
            });
        }
    }
    cookies
}

/// Authenticated iff any `mba` cookie matches the expected digest.
fn authenticate(cookies: &[CookiePair], session: &Hash) -> bool {
    cookies
        .iter()
        .any(|c| c.name == COOKIE_NAME && cookie_matches_session(&c.value, session))
}

/// Constant-time check that a cookie value is the expected session token.
///
/// A non-hex value fails to parse and is rejected; `Hash`'s `==` is
/// constant-time.
fn cookie_matches_session(value: &str, session: &Hash) -> bool {
    Hash::from_hex(value).is_ok_and(|presented| presented == *session)
}

/// Rebuild the outgoing `Cookie` header from the raw non-`mba` pairs, in
/// original order with duplicates kept. `None` when nothing remains (the
/// header is then dropped). Application cookies are forwarded verbatim;
/// only our own `mba` is stripped, using the *same* decoded-name test as
/// authentication so a cookie good enough to authenticate cannot survive.
fn sanitized_cookie_header(cookies: &[CookiePair]) -> Option<HeaderValue> {
    let kept: Vec<&str> = cookies
        .iter()
        .filter(|c| c.name != COOKIE_NAME)
        .map(|c| c.raw.as_str())
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_str(&kept.join("; ")).ok()
}

/// Set the forwarding headers on an outgoing (authenticated) request.
///
/// An upstream may treat us as a proxy and trust our forwarding metadata,
/// so we don't relay client provenance we can't stand behind.
///
/// - **`X-Forwarded-For` / `Forwarded` are stripped.** On the direct-port
///   deployment an inbound value is attacker-controlled, and v0 doesn't
///   synthesize the client IP (that's the front proxy's job). Leaving them
///   would let a client forge the IP that upstream ACLs, rate limits, and
///   audit logs rely on.
/// - **`X-Forwarded-Host`** is cleared, then re-set from the request's own
///   authority: the URI `:authority` **first** (HTTP/2's canonical target
///   field, which hyper parses from the client's `:authority` pseudo-header
///   onto the URI), falling back to the `Host` header (HTTP/1, where the
///   URI has no authority). Both are client-supplied, so this is not a
///   trust boundary — the point is coherence: the upstream gets a single
///   `X-Forwarded-Host` equal to the authority the request actually used,
///   and `:authority` is the authoritative one if an h2 client also sends
///   a conflicting `Host`. Clearing first means a *separate* spoofed inbound
///   `X-Forwarded-Host` (one disagreeing with the request authority) never
///   survives.
/// - **`X-Forwarded-Proto`** is normalized to the effective scheme.
fn rewrite_forwarding_headers(headers: &mut HeaderMap, authority: Option<&str>) {
    headers.remove(&X_FORWARDED_FOR);
    headers.remove(&FORWARDED);

    let observed_host = authority
        .and_then(|a| HeaderValue::from_str(a).ok())
        .or_else(|| headers.get(HOST).cloned());
    headers.remove(&X_FORWARDED_HOST);
    if let Some(value) = observed_host {
        headers.insert(X_FORWARDED_HOST, value);
    }

    let proto = HeaderValue::from_static(forwarded_proto(headers));
    headers.insert(X_FORWARDED_PROTO, proto);
}

/// Whether the effective request scheme is HTTPS. Drives the cookie
/// `Secure` flag and the forwarded proto, so they stay consistent.
fn is_https(headers: &HeaderMap) -> bool {
    forwarded_proto(headers) == "https"
}

/// Effective request scheme, by an exact, conservative rule: `https` only
/// if the inbound `X-Forwarded-Proto` is a *single* value that
/// case-insensitively equals `https`; everything else is `http` (absent,
/// non-UTF-8, any other token, or a comma-joined list like `https, http`).
fn forwarded_proto(headers: &HeaderMap) -> &'static str {
    match headers
        .get(&X_FORWARDED_PROTO)
        .and_then(|v| v.to_str().ok())
    {
        Some(value) if value.trim().eq_ignore_ascii_case("https") => "https",
        _ => "http",
    }
}

/// Extract the `password` field from an `application/x-www-form-urlencoded`
/// body. Lenient: a body that isn't form data simply yields `None`.
fn extract_submitted_password(body: &[u8]) -> Option<String> {
    form_urlencoded::parse(body)
        .find(|(key, _)| key == "password")
        .map(|(_, value)| value.into_owned())
}

/// Constant-time check that the submitted password hashes to the digest.
fn password_matches(password: &str, session: &Hash) -> bool {
    blake3::hash(password.as_bytes()) == *session
}

/// Build the `Set-Cookie` value by hand.
///
/// Every dynamic part is our own hex token, so there is no header-
/// injection surface, and `Max-Age` is a plain integer — no datetime
/// crate needed. `SameSite=Lax` and the bounded `Max-Age` avoid iOS ITP
/// dropping the cookie; `Secure` is set only under HTTPS so the browser
/// doesn't drop the cookie on the plain-HTTP path.
fn build_set_cookie(session: &Hash, secure: bool) -> String {
    let mut cookie = format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_MAX_AGE_SECS}",
        token = session.to_hex(),
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Digest of the password used across the cookie tests.
    fn session() -> Hash {
        blake3::hash(b"hunter2")
    }

    /// The valid session-cookie token for `session()`.
    fn token() -> String {
        session().to_hex().to_string()
    }

    /// Build a `HeaderMap` with a single `Cookie` header.
    fn cookie_header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn valid_token_authenticates() {
        let cookies = parse_cookies(&cookie_header(&format!("mba={}", token())));
        assert!(authenticate(&cookies, &session()));
    }

    #[test]
    fn wrong_token_does_not_authenticate() {
        let wrong = blake3::hash(b"nope").to_hex().to_string();
        let cookies = parse_cookies(&cookie_header(&format!("mba={wrong}")));
        assert!(!authenticate(&cookies, &session()));
    }

    #[test]
    fn non_hex_token_does_not_authenticate() {
        let cookies = parse_cookies(&cookie_header("mba=not-hex"));
        assert!(!authenticate(&cookies, &session()));
    }

    #[test]
    fn missing_cookie_does_not_authenticate() {
        let cookies = parse_cookies(&HeaderMap::new());
        assert!(!authenticate(&cookies, &session()));
    }

    #[test]
    fn percent_encoded_name_still_authenticates() {
        // `m%62a` decodes to `mba` — auth must see it (so stripping does too).
        let cookies = parse_cookies(&cookie_header(&format!("m%62a={}", token())));
        assert!(authenticate(&cookies, &session()));
    }

    #[test]
    fn strip_removes_only_mba() {
        let cookies = parse_cookies(&cookie_header(&format!("app=keep; mba={}", token())));
        let header = sanitized_cookie_header(&cookies).unwrap();
        assert_eq!(header, "app=keep");
    }

    #[test]
    fn strip_of_sole_mba_yields_none() {
        let cookies = parse_cookies(&cookie_header(&format!("mba={}", token())));
        assert!(sanitized_cookie_header(&cookies).is_none());
    }

    #[test]
    fn strip_leaves_non_mba_unchanged() {
        let cookies = parse_cookies(&cookie_header("app=keep; other=1"));
        let header = sanitized_cookie_header(&cookies).unwrap();
        assert_eq!(header, "app=keep; other=1");
    }

    #[test]
    fn strip_removes_percent_encoded_mba() {
        let cookies = parse_cookies(&cookie_header(&format!("m%62a={}; app=keep", token())));
        let header = sanitized_cookie_header(&cookies).unwrap();
        assert_eq!(header, "app=keep");
    }

    #[test]
    fn strip_preserves_duplicate_app_cookies_in_order() {
        // The reason we avoid `CookieJar` (which dedups and reorders).
        let cookies = parse_cookies(&cookie_header(&format!(
            "sid=path-specific; mba={}; sid=root",
            token()
        )));
        let header = sanitized_cookie_header(&cookies).unwrap();
        assert_eq!(header, "sid=path-specific; sid=root");
    }

    #[test]
    fn cookies_split_across_fields_are_merged() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("a=1"));
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("mba={}", token())).unwrap(),
        );
        let cookies = parse_cookies(&headers);
        assert!(authenticate(&cookies, &session()));
        assert_eq!(sanitized_cookie_header(&cookies).unwrap(), "a=1");
    }

    #[test]
    fn malformed_pair_does_not_authenticate_and_is_dropped() {
        // `%ff` percent-decodes to byte 0xFF, invalid UTF-8, so
        // `parse_encoded` rejects the pair and it is dropped.
        let cookies = parse_cookies(&cookie_header(&format!(
            "app=keep; bad=%ff; mba={}",
            token()
        )));
        assert!(authenticate(&cookies, &session()));
        let header = sanitized_cookie_header(&cookies).unwrap();
        assert_eq!(header, "app=keep"); // Malformed `bad` and `mba` both gone.
    }

    #[test]
    fn only_malformed_cookies_do_not_authenticate() {
        let cookies = parse_cookies(&cookie_header("bad=%ff"));
        assert!(!authenticate(&cookies, &session()));
        assert!(cookies.is_empty());
    }

    #[test]
    fn non_utf8_cookie_field_is_dropped() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_bytes(b"app=\xff").unwrap());
        assert!(parse_cookies(&headers).is_empty());
    }

    #[test]
    fn forwarded_proto_https_only_for_single_https() {
        let cases = [
            ("https", "https"),
            ("HTTPS", "https"),
            (" https ", "https"),
            ("http", "http"),
            ("ftp", "http"),
            ("https, http", "http"),
        ];
        for (input, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(X_FORWARDED_PROTO, HeaderValue::from_str(input).unwrap());
            assert_eq!(forwarded_proto(&headers), expected, "input: {input:?}");
        }
    }

    #[test]
    fn forwarded_proto_defaults_to_http_when_absent() {
        assert_eq!(forwarded_proto(&HeaderMap::new()), "http");
    }

    #[test]
    fn rewrite_sets_forwarded_host_from_host_overwriting_spoof() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("real.example"));
        headers.insert(X_FORWARDED_HOST, HeaderValue::from_static("evil.example"));
        rewrite_forwarding_headers(&mut headers, None);
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "real.example");
    }

    #[test]
    fn rewrite_drops_spoofed_forwarded_host_when_no_host_or_authority() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_HOST, HeaderValue::from_static("evil.example"));
        rewrite_forwarding_headers(&mut headers, None);
        assert!(headers.get(&X_FORWARDED_HOST).is_none());
    }

    #[test]
    fn rewrite_uses_authority_for_forwarded_host() {
        // HTTP/2: no `Host`, authority on the URI. Spoofed inbound value
        // must still be overwritten by the observed authority.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_HOST, HeaderValue::from_static("evil.example"));
        rewrite_forwarding_headers(&mut headers, Some("h2.example:8443"));
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "h2.example:8443");
    }

    #[test]
    fn rewrite_prefers_authority_over_host() {
        // An h2 client can send a conflicting, forgeable `Host` alongside
        // the `:authority`; the authority (set by hyper) must win.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("evil.example"));
        rewrite_forwarding_headers(&mut headers, Some("authority.example"));
        assert_eq!(headers.get(&X_FORWARDED_HOST).unwrap(), "authority.example");
    }

    #[test]
    fn rewrite_strips_inbound_client_ip_forwarding() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("real.example"));
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("1.2.3.4"));
        headers.insert(FORWARDED, HeaderValue::from_static("for=1.2.3.4"));
        rewrite_forwarding_headers(&mut headers, None);
        assert!(headers.get(&X_FORWARDED_FOR).is_none());
        assert!(headers.get(&FORWARDED).is_none());
    }

    #[test]
    fn extract_submitted_password_reads_the_field() {
        assert_eq!(
            extract_submitted_password(b"password=hunter2").as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn extract_submitted_password_none_when_absent() {
        assert_eq!(extract_submitted_password(b"other=1"), None);
    }

    #[test]
    fn extract_submitted_password_decodes_spaces() {
        // xkcd #936, the memorable half: spaces arrive form-encoded as `+`.
        assert_eq!(
            extract_submitted_password(b"password=correct+horse+battery+staple").as_deref(),
            Some("correct horse battery staple")
        );
    }

    #[test]
    fn extract_submitted_password_decodes_ampersand() {
        // xkcd #936, the other half: `Tr0ub4dor&3`'s `&` must arrive
        // percent-encoded, or it would split the form into two fields.
        assert_eq!(
            extract_submitted_password(b"password=Tr0ub4dor%263").as_deref(),
            Some("Tr0ub4dor&3")
        );
    }

    #[test]
    fn build_set_cookie_has_required_attributes() {
        let cookie = build_set_cookie(&session(), false);
        assert!(cookie.starts_with(&format!("mba={}", token())));
        assert!(cookie.contains("; HttpOnly"));
        assert!(cookie.contains("; SameSite=Lax"));
        assert!(cookie.contains("; Path=/"));
        assert!(cookie.contains("; Max-Age=2592000"));
        assert!(!cookie.contains("; Secure"));
    }

    #[test]
    fn build_set_cookie_adds_secure_under_https() {
        assert!(build_set_cookie(&session(), true).contains("; Secure"));
    }

    #[test]
    fn password_matches_only_the_configured_password() {
        assert!(password_matches("hunter2", &session()));
        assert!(!password_matches("wrong", &session()));
    }
}
