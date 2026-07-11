//! Binary entry point: build the app from the environment and serve.
//!
//! Kept intentionally thin — all logic lives in the library so it stays
//! testable. A missing or invalid configuration fails fast with a clear
//! message.

// See `lib.rs`: the duplicate crate versions are all transitive and
// outside our control.
#![allow(clippy::multiple_crate_versions)]

use std::process::ExitCode;

use mildly_basic_auth::{Config, build_app};

/// Fixed bind address (v0 has no config).
const BIND_ADDRESS: &str = "0.0.0.0:8000";

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match tokio::net::TcpListener::bind(BIND_ADDRESS).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("error: cannot bind `{BIND_ADDRESS}`: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = axum::serve(listener, build_app(config)).await {
        eprintln!("error: server failed: {error}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
