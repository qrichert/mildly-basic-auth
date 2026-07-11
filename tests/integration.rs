//! End-to-end tests: a real gate proxying to a real ephemeral upstream.
//!
//! Each test spins its own upstream + gate on ephemeral ports (so they
//! stay independent) and drives the gate with a redirect-disabled
//! `reqwest` client. The upstream records what it receives, so tests can
//! assert on exactly which headers/body reached the protected app.

// Transitive duplicate crate versions only (see `lib.rs`).
#![allow(clippy::multiple_crate_versions)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method};
use mildly_basic_auth::{Config, build_app};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// `hunter2`: the internet's canonical placeholder password, from
// bash.org IRC quote #244321.
const PASSWORD: &str = "hunter2";
const FORM: &str = "application/x-www-form-urlencoded";

/// The valid session-cookie token for `PASSWORD`.
fn valid_token() -> String {
    blake3::hash(PASSWORD.as_bytes()).to_hex().to_string()
}

/// A URL-encoded login form body (`reqwest`'s `.form()` needs a feature
/// we don't enable, and our passwords are URL-safe).
fn login_body(password: &str) -> String {
    format!("password={password}")
}

/// What the upstream saw on its most recent request.
#[derive(Clone)]
struct Recorded {
    #[allow(dead_code)]
    method: Method,
    #[allow(dead_code)]
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Shared upstream state: a hit counter and the last request received.
#[derive(Default)]
struct Upstream {
    hits: AtomicUsize,
    last: Mutex<Option<Recorded>>,
}

impl Upstream {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn last(&self) -> Recorded {
        self.last.lock().unwrap().clone().expect("upstream not hit")
    }
}

/// Upstream handler: record the request and return a marker body.
async fn record(State(state): State<Arc<Upstream>>, request: Request) -> &'static str {
    state.hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    *state.last.lock().unwrap() = Some(Recorded {
        method: parts.method,
        uri: parts.uri.to_string(),
        headers: parts.headers,
        body,
    });
    "UPSTREAM_OK"
}

/// A running gate + upstream, with a client and their addresses.
struct Harness {
    base: String,
    authority: String,
    upstream: Arc<Upstream>,
    client: reqwest::Client,
}

/// Spin an upstream and a gate on ephemeral ports.
async fn spawn() -> Harness {
    let upstream = Arc::new(Upstream::default());
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    let up_app = Router::new().fallback(record).with_state(upstream.clone());
    tokio::spawn(async move { axum::serve(up_listener, up_app).await.unwrap() });

    let config = Config::from_values(PASSWORD, &format!("http://{up_addr}")).unwrap();
    let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate_addr = gate_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(gate_listener, build_app(config)).await.unwrap() });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    Harness {
        base: format!("http://{gate_addr}"),
        authority: gate_addr.to_string(),
        upstream,
        client,
    }
}

// --- The wall (unauthenticated) ------------------------------------------

#[tokio::test]
async fn unauthenticated_get_serves_the_wall() {
    let h = spawn().await;
    let resp = h.client.get(&h.base).send().await.unwrap();

    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(resp.headers().get("www-authenticate").is_none());
    assert!(resp.text().await.unwrap().contains("</form>"));
    assert_eq!(h.upstream.hits(), 0);
}

#[tokio::test]
async fn wrong_password_serves_the_wall() {
    let h = spawn().await;
    let resp = h
        .client
        .post(&h.base)
        .header("content-type", FORM)
        .body(login_body("wrong"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    assert_eq!(h.upstream.hits(), 0);
}

#[tokio::test]
async fn correct_password_sets_cookie_and_redirects_preserving_query() {
    let h = spawn().await;
    let resp = h
        .client
        .post(format!("{}/docs?section=private", h.base))
        .header("content-type", FORM)
        .body(login_body(PASSWORD))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/docs?section=private"
    );

    let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(set_cookie.starts_with(&format!("mba={}", valid_token())));
    assert!(set_cookie.contains("; HttpOnly"));
    assert!(set_cookie.contains("; SameSite=Lax"));
    assert!(set_cookie.contains("; Path=/"));
    assert!(set_cookie.contains("; Max-Age=2592000"));
    assert_eq!(h.upstream.hits(), 0);
}

#[tokio::test]
async fn secure_flag_absent_over_http() {
    let h = spawn().await;
    let resp = h
        .client
        .post(&h.base)
        .header("content-type", FORM)
        .body(login_body(PASSWORD))
        .send()
        .await
        .unwrap();
    let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(!set_cookie.contains("; Secure"));
}

#[tokio::test]
async fn secure_flag_present_under_forwarded_https() {
    let h = spawn().await;
    let resp = h
        .client
        .post(&h.base)
        .header("x-forwarded-proto", "https")
        .header("content-type", FORM)
        .body(login_body(PASSWORD))
        .send()
        .await
        .unwrap();
    let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(set_cookie.contains("; Secure"));
}

#[tokio::test]
async fn oversized_login_body_is_rejected() {
    let h = spawn().await;
    let resp = h
        .client
        .post(&h.base)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(vec![b'a'; 9000])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
    assert_eq!(h.upstream.hits(), 0);
}

// --- Authenticated passthrough -------------------------------------------

#[tokio::test]
async fn authenticated_get_is_proxied() {
    let h = spawn().await;
    let resp = h
        .client
        .get(&h.base)
        .header("cookie", format!("mba={}", valid_token()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "UPSTREAM_OK");
    assert_eq!(h.upstream.hits(), 1);
}

#[tokio::test]
async fn authenticated_post_body_reaches_upstream() {
    let h = spawn().await;
    h.client
        .post(&h.base)
        .header("cookie", format!("mba={}", valid_token()))
        .body("payload-bytes")
        .send()
        .await
        .unwrap();

    assert_eq!(h.upstream.last().body, b"payload-bytes");
}

// --- Cookie stripping ----------------------------------------------------

#[tokio::test]
async fn mba_cookie_is_stripped_but_app_cookies_pass_through() {
    let h = spawn().await;
    h.client
        .get(&h.base)
        .header("cookie", format!("app=keep; mba={}", valid_token()))
        .send()
        .await
        .unwrap();

    let cookie = h.upstream.last();
    assert_eq!(cookie.headers.get("cookie").unwrap(), "app=keep");
}

#[tokio::test]
async fn duplicate_app_cookies_keep_order() {
    let h = spawn().await;
    h.client
        .get(&h.base)
        .header(
            "cookie",
            format!("sid=path-specific; mba={}; sid=root", valid_token()),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(
        h.upstream.last().headers.get("cookie").unwrap(),
        "sid=path-specific; sid=root"
    );
}

#[tokio::test]
async fn percent_encoded_mba_is_also_stripped() {
    let h = spawn().await;
    let resp = h
        .client
        .get(&h.base)
        .header("cookie", format!("keep=1; m%62a={}", valid_token()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200); // The `m%62a` cookie authenticated.
    assert_eq!(h.upstream.last().headers.get("cookie").unwrap(), "keep=1");
}

#[tokio::test]
async fn malformed_cookie_without_valid_mba_serves_the_wall() {
    let h = spawn().await;
    let resp = h
        .client
        .get(&h.base)
        .header("cookie", "bad=%ff")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    assert_eq!(h.upstream.hits(), 0);
}

#[tokio::test]
async fn malformed_cookie_alongside_valid_mba_is_dropped() {
    let h = spawn().await;
    let resp = h
        .client
        .get(&h.base)
        .header(
            "cookie",
            format!("mba={}; app=keep; bad=%ff", valid_token()),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(h.upstream.last().headers.get("cookie").unwrap(), "app=keep");
}

// --- Forwarding headers --------------------------------------------------

#[tokio::test]
async fn forwarded_host_overwrites_spoofed_value() {
    let h = spawn().await;
    h.client
        .get(&h.base)
        .header("cookie", format!("mba={}", valid_token()))
        .header("x-forwarded-host", "evil.example")
        .send()
        .await
        .unwrap();

    let last = h.upstream.last();
    assert_eq!(last.headers.get("x-forwarded-host").unwrap(), &h.authority);
    assert_eq!(last.headers.get("x-forwarded-proto").unwrap(), "http");
}

#[tokio::test]
async fn spoofed_client_ip_forwarding_is_stripped() {
    let h = spawn().await;
    h.client
        .get(&h.base)
        .header("cookie", format!("mba={}", valid_token()))
        .header("x-forwarded-for", "9.9.9.9")
        .header("forwarded", "for=9.9.9.9")
        .send()
        .await
        .unwrap();

    let last = h.upstream.last();
    assert!(last.headers.get("x-forwarded-for").is_none());
    assert!(last.headers.get("forwarded").is_none());
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped() {
    let h = spawn().await;
    // Raw request so we can inject a `Connection`-listed hop-by-hop header
    // that a normal HTTP client would manage itself. `close` lets us read
    // the gate response to EOF.
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nCookie: mba={token}\r\n\
         Connection: close, x-remove\r\nX-Remove: 1\r\n\r\n",
        host = h.authority,
        token = valid_token(),
    );
    let response = raw_request(&h.authority, &request).await;
    assert!(response.contains("UPSTREAM_OK"));

    let last = h.upstream.last();
    assert!(last.headers.get("x-remove").is_none());
    assert!(last.headers.get("connection").is_none());
}

/// Send a raw HTTP/1.1 request and read the full response (needs the
/// request to signal `Connection: close`).
async fn raw_request(authority: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(authority).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

// --- Fail-fast startup (child process) -----------------------------------

#[test]
fn missing_password_fails_fast() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mildly-basic-auth"))
        .env_remove("MBA_PASSWORD")
        .env("MBA_UPSTREAM", "http://127.0.0.1:9")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_PASSWORD"), "stderr: {stderr}");
}

#[test]
fn missing_upstream_fails_fast() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mildly-basic-auth"))
        .env("MBA_PASSWORD", PASSWORD)
        .env_remove("MBA_UPSTREAM")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_UPSTREAM"), "stderr: {stderr}");
}
