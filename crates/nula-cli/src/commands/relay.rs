//! `nula relay run` — start an in-process mock relay and block on
//! Ctrl-C.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use nula_relay::server::{MockRelayBuilder, MockRelayOptions};
use serde_json::json;

use crate::output::write_json;

/// Run a local mock relay until the process receives `SIGINT`
/// (Ctrl-C on POSIX, Ctrl-Break on Windows).
///
/// Emits one JSON object on `stdout` describing the listening
/// address as soon as the bind succeeds; subsequent traffic is
/// logged to `stderr` via `tracing`.
///
/// # Errors
///
/// - I/O errors when the socket cannot be bound.
/// - Tokio runtime errors when the `ctrl_c` future fails to
///   register a signal handler (effectively unreachable).
pub(crate) async fn run(bind: SocketAddr) -> Result<()> {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().bind_addr(bind))
        .run()
        .await
        .with_context(|| format!("bind mock relay on {bind}"))?;

    let listening = json!({
        "kind": "relay_listening",
        "url": relay.url().as_str(),
        "addr": relay.addr().to_string(),
    });
    write_json(&listening)?;

    tracing::info!(
        url = %relay.url(),
        addr = %relay.addr(),
        "nula relay run — listening; press Ctrl-C to stop",
    );

    tokio::signal::ctrl_c()
        .await
        .context("install Ctrl-C handler")?;

    tracing::info!("shutdown signal received, draining relay…");
    relay.shutdown();
    Ok(())
}
