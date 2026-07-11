//! Transparent password-wall reverse proxy.
//!
//! [`build_app`] assembles the whole service: a reverse proxy to the
//! configured upstream, wrapped by the authentication gate. The binary
//! (`main.rs`) and the integration tests both build on this single seam.

// The only duplicate crate versions come from transitive dependencies we
// don't control (WebSocket libs pulled by the proxy, `windows-sys`), so
// `multiple_crate_versions` here is pure noise under the `clippy::cargo`
// gate.
#![allow(clippy::multiple_crate_versions)]

mod config;
mod gate;

pub use config::{Config, ConfigError};

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum_reverse_proxy::{ReverseProxy, Rfc9110Layer};

/// Build the application: the reverse proxy wrapped by the gate.
///
/// The proxy is mounted at `/` so every path is forwarded. `Rfc9110Layer`
/// strips hop-by-hop headers (the base proxy does not) while preserving
/// the WebSocket upgrade handshake. The gate is the outermost layer, so it
/// decides passthrough-vs-wall before the proxy ever sees a request.
pub fn build_app(config: Config) -> Router {
    // `config.upstream()` is borrowed only for this statement; `config`
    // is then moved into the gate's state below.
    let proxy: Router = ReverseProxy::new("/", config.upstream()).into();
    proxy
        .layer(Rfc9110Layer::new())
        .layer(from_fn_with_state(config, gate::gate))
}
