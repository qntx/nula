//! `nula` — command-line interface for the
//! [nula](https://github.com/qntx/nula) workspace.
//!
//! Wraps `nula-sdk` and `nula-relay-builder` into a single binary
//! with subcommand groups: `keys`, `relay`, `event` (publish /
//! fetch), `dm` (NIP-17 send / recv), and `relays` (NIP-65 set /
//! get). See the crate README for examples.

use anyhow::Result;
use clap::Parser;

mod cli;
mod commands;
mod output;

// Dev-only deps consumed by `tests/cli.rs` once compiled with
// `cargo test`. Pin them under `cfg(test)` so the production bin
// target doesn't trip `unused_crate_dependencies`.
#[cfg(test)]
use assert_cmd as _;
#[cfg(test)]
use predicates as _;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = cli::Cli::parse();
    cli.run().await
}

/// Wire `tracing-subscriber` to `stderr` so subcommand `stdout`
/// stays pure JSON.
///
/// Honours `RUST_LOG`; default level is `info`. Disabled entirely
/// when `--quiet` is passed (handled by the subcommand layer).
fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}
