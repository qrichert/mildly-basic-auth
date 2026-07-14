//! Binary entry point: build the app from the environment and serve.
//!
//! Kept intentionally thin — all logic lives in the library so it stays
//! testable. A missing or invalid configuration fails fast with a clear
//! message.

// See `lib.rs`: the duplicate crate versions are all transitive and
// outside our control.
#![allow(clippy::multiple_crate_versions)]

use std::io::Write;
use std::process::ExitCode;

use mildly_basic_auth::{Config, build_app};

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let address = config.bind_address();
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("error: cannot bind `{address}`: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Startup announcement. A closed stdout must not kill a server
    // that already bound, so write fallibly (unlike `println!`) and
    // flush so the line reaches `docker logs` / a pipe promptly. The
    // fallback warning is best-effort too: if stderr is also broken,
    // drop it rather than panic.
    {
        let mut stdout = std::io::stdout().lock();
        let result = writeln!(stdout, "Listening on {address}.").and_then(|()| stdout.flush());
        if let Err(error) = result {
            let _ = writeln!(
                std::io::stderr(),
                "warning: could not write startup announcement: {error}"
            );
        }
    }

    if let Err(error) = axum::serve(listener, build_app(config)).await {
        eprintln!("error: server failed: {error}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
