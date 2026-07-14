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
    spawn_with_passwords(&[PASSWORD]).await
}

/// Spin an upstream and a gate configured with the given passwords.
async fn spawn_with_passwords(passwords: &[&str]) -> Harness {
    let upstream = Arc::new(Upstream::default());
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    let up_app = Router::new().fallback(record).with_state(upstream.clone());
    tokio::spawn(async move { axum::serve(up_listener, up_app).await.unwrap() });

    let config = Config::from_passwords(passwords, &format!("http://{up_addr}")).unwrap();
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
async fn each_configured_password_logs_in_with_its_own_cookie() {
    let h = spawn_with_passwords(&["hunter2", "swordfish"]).await;

    for password in ["hunter2", "swordfish"] {
        let resp = h
            .client
            .post(&h.base)
            .header("content-type", FORM)
            .body(login_body(password))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 303, "password: {password}");
        // The cookie carries the digest of the password actually used.
        let token = blake3::hash(password.as_bytes()).to_hex().to_string();
        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(
            set_cookie.starts_with(&format!("mba={token}")),
            "password: {password}"
        );
    }
}

#[tokio::test]
async fn cookie_from_a_non_primary_password_is_proxied() {
    let h = spawn_with_passwords(&["hunter2", "swordfish"]).await;
    // A cookie minted from the second configured password authenticates a
    // proxied request, not just the login.
    let token = blake3::hash(b"swordfish").to_hex().to_string();
    let resp = h
        .client
        .get(&h.base)
        .header("cookie", format!("mba={token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "UPSTREAM_OK");
    assert_eq!(h.upstream.hits(), 1);
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

#[test]
fn template_text_variables_customize_every_wall_response() {
    let password = format!("template-text-test-{}", std::process::id());
    let mut failures = Vec::new();

    // Retry the complete attempt if another process wins the allocation-to-
    // bind gap (same reason as `custom_address_is_bound`).
    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD", &password)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .env("MBA_TEMPLATE_PAGE_LANGUAGE", "fr")
            .env("MBA_TEMPLATE_PAGE_TITLE", "Mon site")
            .env("MBA_TEMPLATE_PASSWORD_LABEL", "Mot de passe")
            .env("MBA_TEMPLATE_PASSWORD_PLACEHOLDER", "Votre mot de passe")
            .env("MBA_TEMPLATE_SUBMIT_BUTTON_TEXT", "Entrer")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let get_request = format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut get_response = None;
        while std::time::Instant::now() < deadline {
            if let Some(response) = blocking_request(address, &get_request)
                && response.starts_with("HTTP/1.1 401 Unauthorized")
            {
                get_response = Some(response);
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let post_response = get_response.as_ref().and_then(|_| {
            let body = "password=wrong";
            let request = format!(
                "POST / HTTP/1.1\r\nHost: {address}\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            blocking_request(address, &request)
        });

        _ = child.kill();
        let output = child.wait_with_output().unwrap();

        if let (Some(get_response), Some(post_response)) = (get_response, post_response) {
            assert!(post_response.starts_with("HTTP/1.1 401 Unauthorized"));
            let get_body = get_response.split_once("\r\n\r\n").unwrap().1;
            let post_body = post_response.split_once("\r\n\r\n").unwrap().1;
            assert_eq!(get_body, post_body);
            assert!(get_body.contains("<html lang=\"fr\">"));
            assert!(get_body.contains("<title>Mon site</title>"));
            assert!(get_body.contains(">Mot de passe</label>"));
            assert!(get_body.contains("placeholder=\"Votre mot de passe\""));
            assert!(get_body.contains(">Entrer</button>"));
            return;
        }
        failures.push(format!(
            "`{address}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    panic!(
        "service did not serve the customized wall after five attempts:\n{}",
        failures.join("\n")
    );
}

#[test]
fn template_file_customizes_every_wall_response() {
    let template = TemporaryTemplate::new(
        b"<!doctype html><title>{{PAGE_TITLE}}</title><p>CUSTOM_TEMPLATE</p>",
    );
    let gate = TemplateGate::spawn(template.path(), PASSWORD);

    let get_response = gate.get();
    let post_response = gate.post_password("wrong", "/");

    assert!(get_response.starts_with("HTTP/1.1 401 Unauthorized"));
    assert!(post_response.starts_with("HTTP/1.1 401 Unauthorized"));
    let get_body = response_body(&get_response);
    let post_body = response_body(&post_response);
    assert_eq!(get_body, post_body);
    assert!(get_body.contains("<title>Welcome!</title>"));
    assert!(get_body.contains("CUSTOM_TEMPLATE"));
    assert!(!get_body.contains("{{PAGE_TITLE}}"));
}

#[test]
fn password_field_authenticates_with_a_custom_template_configured() {
    let template = TemporaryTemplate::new(b"<p>CUSTOM_TEMPLATE</p>");
    let gate = TemplateGate::spawn(template.path(), PASSWORD);

    let response = gate.post_password(PASSWORD, "/private?section=docs");

    assert!(response.starts_with("HTTP/1.1 303 See Other"));
    assert!(response.contains("location: /private?section=docs"));
    assert!(response.contains(&format!("set-cookie: mba={}", valid_token())));
}

#[test]
fn template_file_is_loaded_only_at_startup() {
    let template = TemporaryTemplate::new(b"<p>VERSION_ONE</p>");
    let gate = TemplateGate::spawn(template.path(), PASSWORD);

    template.overwrite(b"<p>VERSION_TWO</p>");
    let changed_response = gate.get();
    assert!(response_body(&changed_response).contains("VERSION_ONE"));
    assert!(!response_body(&changed_response).contains("VERSION_TWO"));

    template.remove();
    let removed_response = gate.get();
    assert!(response_body(&removed_response).contains("VERSION_ONE"));
}

#[cfg(unix)]
#[test]
fn non_unicode_template_file_path_is_supported() {
    // Skip where the filesystem can't hold a non-Unicode name (e.g.,
    // APFS on macOS enforces UTF-8): there is no such path to exercise.
    let Some(template) = TemporaryTemplate::with_non_unicode_name(b"<p>NON_UNICODE_PATH</p>")
    else {
        return;
    };
    let gate = TemplateGate::spawn(template.path(), PASSWORD);

    let response = gate.get();

    assert!(response_body(&response).contains("NON_UNICODE_PATH"));
}

#[test]
fn missing_template_file_fails_fast() {
    let template = TemporaryTemplate::new(b"temporary");
    let path = template.path().to_owned();
    template.remove();

    let output = binary_without_mba_environment()
        .env("MBA_PASSWORD", PASSWORD)
        .env("MBA_UPSTREAM", "http://127.0.0.1:9")
        .env("MBA_TEMPLATE_FILE", &path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_TEMPLATE_FILE"), "stderr: {stderr}");
    assert!(
        stderr.contains(&path.to_string_lossy().into_owned()),
        "stderr: {stderr}"
    );
}

/// Send one blocking request to a child-process gate, returning its full
/// response when the listener is available.
fn blocking_request(address: std::net::SocketAddr, request: &str) -> Option<String> {
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(50))
            .ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .ok()?;
    std::io::Write::write_all(&mut stream, request.as_bytes()).ok()?;

    let mut response = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut response).ok()?;
    Some(String::from_utf8_lossy(&response).into_owned())
}

/// The response body after the HTTP header block.
fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").unwrap().1
}

/// A custom template file removed when its test ends.
struct TemporaryTemplate {
    path: std::path::PathBuf,
}

impl TemporaryTemplate {
    /// Write `contents` to a uniquely named temporary template.
    fn new(contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(unique_template_name());
        Self::write_new(path, contents)
    }

    /// Write a template whose path is not valid Unicode, if the
    /// filesystem accepts such a name.
    ///
    /// Returns `None` where the filesystem enforces UTF-8 names (e.g.,
    /// APFS on macOS rejects the trailing `0xff` byte with `EILSEQ`),
    /// letting callers skip rather than fail on a fixture the platform
    /// cannot represent.
    #[cfg(unix)]
    fn with_non_unicode_name(contents: &[u8]) -> Option<Self> {
        use std::os::unix::ffi::OsStringExt;

        let mut name = unique_template_name().into_bytes();
        name.push(0xff);
        let path = std::env::temp_dir().join(std::ffi::OsString::from_vec(name));
        // Not `write_new`: this write is expected to fail where the
        // filesystem rejects non-Unicode names, so we skip instead of
        // panicking.
        std::fs::write(&path, contents).ok()?;
        Some(Self { path })
    }

    /// Write the initial contents at `path`.
    fn write_new(path: std::path::PathBuf, contents: &[u8]) -> Self {
        std::fs::write(&path, contents).unwrap();
        Self { path }
    }

    /// Filesystem path passed to `MBA_TEMPLATE_FILE`.
    fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Replace the template source after the service has started.
    fn overwrite(&self, contents: &[u8]) {
        std::fs::write(&self.path, contents).unwrap();
    }

    /// Remove the template source after the service has started.
    fn remove(&self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}

impl Drop for TemporaryTemplate {
    fn drop(&mut self) {
        _ = std::fs::remove_file(&self.path);
    }
}

/// A unique filename for child-process template tests.
fn unique_template_name() -> String {
    static NEXT_TEMPLATE: AtomicUsize = AtomicUsize::new(0);

    let sequence = NEXT_TEMPLATE.fetch_add(1, Ordering::Relaxed);
    format!(
        "mildly-basic-auth-integration-test-{}-{sequence}",
        std::process::id(),
    )
}

/// A child-process gate configured with a custom template.
struct TemplateGate {
    address: std::net::SocketAddr,
    child: std::process::Child,
}

impl TemplateGate {
    /// Start the binary and wait until it serves the custom wall.
    fn spawn(template_path: &std::path::Path, password: &str) -> Self {
        let mut failures = Vec::new();

        // Retry if another process wins the allocation-to-bind gap.
        for _ in 0..5 {
            let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = available.local_addr().unwrap();
            drop(available);

            let mut child = binary_without_mba_environment()
                .env("MBA_ADDRESS", address.to_string())
                .env("MBA_PASSWORD", password)
                .env("MBA_UPSTREAM", "http://127.0.0.1:9")
                .env("MBA_TEMPLATE_FILE", template_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if blocking_request(address, &Self::get_request(address))
                    .is_some_and(|response| response.starts_with("HTTP/1.1 401 Unauthorized"))
                {
                    return Self { address, child };
                }
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            _ = child.kill();
            let output = child.wait_with_output().unwrap();
            failures.push(format!(
                "`{address}`: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        panic!(
            "service did not serve the custom template after five attempts:\n{}",
            failures.join("\n")
        );
    }

    /// Request the configured wall.
    fn get(&self) -> String {
        blocking_request(self.address, &Self::get_request(self.address)).unwrap()
    }

    /// Submit a form-encoded `password` field to `target`.
    fn post_password(&self, password: &str, target: &str) -> String {
        let body = login_body(password);
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.address,
            body.len(),
        );
        blocking_request(self.address, &request).unwrap()
    }

    /// HTTP request used to wait for and retrieve the wall.
    fn get_request(address: std::net::SocketAddr) -> String {
        format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
    }
}

impl Drop for TemplateGate {
    fn drop(&mut self) {
        _ = self.child.kill();
        _ = self.child.wait();
    }
}

// --- Fail-fast startup (child process) -----------------------------------

/// Command for the binary with every inherited `MBA_*` variable removed.
/// Every child-process test must start here so ambient configuration cannot
/// change the behavior or startup error the test is exercising.
fn binary_without_mba_environment() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_mildly-basic-auth"));
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("MBA_")) {
            command.env_remove(name);
        }
    }
    command
}

#[test]
fn missing_password_fails_fast() {
    let output = binary_without_mba_environment()
        .env_remove("MBA_ADDRESS")
        .env("MBA_UPSTREAM", "http://127.0.0.1:9")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_PASSWORD"), "stderr: {stderr}");
}

#[test]
fn missing_upstream_fails_fast() {
    let output = binary_without_mba_environment()
        .env_remove("MBA_ADDRESS")
        .env("MBA_PASSWORD", PASSWORD)
        .env_remove("MBA_UPSTREAM")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_UPSTREAM"), "stderr: {stderr}");
}

#[test]
fn invalid_address_fails_fast() {
    let output = binary_without_mba_environment()
        .env("MBA_ADDRESS", "localhost:4630")
        .env("MBA_PASSWORD", PASSWORD)
        .env("MBA_UPSTREAM", "http://127.0.0.1:9")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MBA_ADDRESS"), "stderr: {stderr}");
}

#[test]
fn custom_address_is_bound() {
    let password = format!("custom-address-test-{}", std::process::id());
    let mut failures = Vec::new();

    // Passing an inherited listener would require a production API solely
    // for this test. Retry the complete attempt if another process wins the
    // allocation-to-bind gap, and authenticate with a per-process password
    // so another listener cannot produce a false positive.
    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD", &password)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut is_serving = false;
        while std::time::Instant::now() < deadline {
            if authenticates_at(address, &password) {
                is_serving = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        _ = child.kill();
        let output = child.wait_with_output().unwrap();
        if is_serving {
            return;
        }
        failures.push(format!(
            "`{address}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    panic!(
        "service did not bind after five attempts:\n{}",
        failures.join("\n")
    );
}

#[test]
fn suffixed_password_variables_each_authenticate() {
    // Only suffixed vars, no base `MBA_PASSWORD`: one test proving suffix
    // discovery, multiple passwords, environment isolation, and that no
    // base variable is privileged (the child would fail to start if the
    // base were required).
    let alice = format!("alice-{}", std::process::id());
    let bob = format!("bob-{}", std::process::id());
    let mut failures = Vec::new();

    // Retry the whole attempt if another process wins the allocation-to-bind
    // gap (same reason as `custom_address_is_bound`).
    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD_ALICE", &alice)
            .env("MBA_PASSWORD_BOB", &bob)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut is_serving = false;
        while std::time::Instant::now() < deadline {
            if authenticates_at(address, &alice) {
                is_serving = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Capture every result before killing, so a failed assertion never
        // leaves the child process running.
        let outcome = is_serving.then(|| {
            (
                authenticates_at(address, &alice),
                authenticates_at(address, &bob),
                !authenticates_at(address, "charlie"),
            )
        });

        _ = child.kill();
        let output = child.wait_with_output().unwrap();

        if let Some((alice_ok, bob_ok, wrong_rejected)) = outcome {
            assert!(
                alice_ok,
                "the `MBA_PASSWORD_ALICE` password did not authenticate"
            );
            assert!(
                bob_ok,
                "the `MBA_PASSWORD_BOB` password did not authenticate"
            );
            assert!(wrong_rejected, "an unconfigured password authenticated");
            return;
        }
        failures.push(format!(
            "`{address}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    panic!(
        "service did not serve after five attempts:\n{}",
        failures.join("\n")
    );
}

/// Submit `password` and verify the listener is this test's service.
fn authenticates_at(address: std::net::SocketAddr, password: &str) -> bool {
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(50))
    else {
        return false;
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .unwrap();

    let body = format!("password={password}");
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {address}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if std::io::Write::write_all(&mut stream, request.as_bytes()).is_err() {
        return false;
    }

    let mut response = Vec::new();
    _ = std::io::Read::read_to_end(&mut stream, &mut response);
    let response = String::from_utf8_lossy(&response);
    let token = blake3::hash(password.as_bytes()).to_hex();
    response.starts_with("HTTP/1.1 303 See Other")
        && response.contains(&format!("set-cookie: mba={token}"))
}

#[test]
fn startup_announces_it_is_listening() {
    // A per-process password so a port-race squatter answering `401`
    // cannot masquerade as this child; retry the whole attempt if we
    // lose the allocation-to-bind gap.
    let password = format!("startup-announce-test-{}", std::process::id());
    let mut failures = Vec::new();

    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD", &password)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut is_serving = false;
        while std::time::Instant::now() < deadline {
            if authenticates_at(address, &password) {
                is_serving = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        _ = child.kill();
        let output = child.wait_with_output().unwrap();
        if is_serving {
            // Printed before `serve`, so it is on stdout by the time
            // the child authenticates.
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(stdout, format!("Listening on {address}.\n"));
            return;
        }
        failures.push(format!(
            "`{address}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    panic!(
        "service did not announce itself after five attempts:\n{}",
        failures.join("\n")
    );
}

#[test]
fn startup_announcement_write_failure_does_not_crash() {
    let password = format!("startup-announce-epipe-test-{}", std::process::id());
    let mut failures = Vec::new();

    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        // Pre-broken pipe: close the read end before the child runs so
        // its announcement write fails with `EPIPE` (deterministic, no
        // spawn/write race). Rust ignores `SIGPIPE`, so the write
        // returns `Err` instead of killing the process.
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD", &password)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .stdout(writer)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut is_serving = false;
        while std::time::Instant::now() < deadline {
            if authenticates_at(address, &password) {
                is_serving = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        _ = child.kill();
        let output = child.wait_with_output().unwrap();
        if is_serving {
            // The fallible write must have failed and warned, not
            // panicked the process.
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("warning: could not write startup announcement"),
                "stderr: {stderr}"
            );
            return;
        }
        failures.push(format!(
            "`{address}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    panic!(
        "service did not survive a failed announcement after five attempts:\n{}",
        failures.join("\n")
    );
}

#[test]
fn startup_announcement_survives_broken_stdout_and_stderr() {
    let password = format!("startup-announce-noio-test-{}", std::process::id());
    let mut failures = Vec::new();

    for _ in 0..5 {
        let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = available.local_addr().unwrap();
        drop(available);

        // Pre-break both pipes: when the announcement write fails and the
        // fallback stderr warning would fail too, the server must keep
        // serving — a courtesy line must never kill an already-bound
        // process. A `println!`/`eprintln!` pair would panic here.
        let (stdout_reader, stdout_writer) = std::io::pipe().unwrap();
        drop(stdout_reader);
        let (stderr_reader, stderr_writer) = std::io::pipe().unwrap();
        drop(stderr_reader);

        let mut child = binary_without_mba_environment()
            .env("MBA_ADDRESS", address.to_string())
            .env("MBA_PASSWORD", &password)
            .env("MBA_UPSTREAM", "http://127.0.0.1:9")
            .stdout(stdout_writer)
            .stderr(stderr_writer)
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut is_serving = false;
        while std::time::Instant::now() < deadline {
            if authenticates_at(address, &password) {
                is_serving = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        _ = child.kill();
        _ = child.wait();
        if is_serving {
            return;
        }
        failures.push(format!("`{address}`: child did not survive"));
    }

    panic!(
        "service did not survive broken stdout+stderr after five attempts:\n{}",
        failures.join("\n")
    );
}
