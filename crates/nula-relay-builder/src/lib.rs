//! In-process programmable Nostr relay server.
//!
//! `nula-relay-builder` is Layer 4 of the `nula` workspace. It binds
//! a real [`tokio::net::TcpListener`], speaks NIP-01 over WebSocket
//! via `tokio-tungstenite`, persists events through any
//! [`nula_storage::NostrDatabase`] backend, and accepts pluggable
//! [`WritePolicy`] / [`ReadPolicy`] hooks for filtering inbound
//! traffic.
//!
//! # Why a real server?
//!
//! - **End-to-end integration tests** for upper layers
//!   (`nula-relay-pool`, `nula-gossip`, `nula-sdk`).
//! - **Local development** — running a full Nostr stack against a
//!   throw-away relay on `127.0.0.1:0` avoids depending on the
//!   public relay graph for fast iteration.
//!
//! TLS, multi-host routing, and production-grade rate limiting are
//! deliberately out of scope. Reach for `nostr-rs-relay` when those
//! are needed.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use nula_relay_builder::MockRelayBuilder;
//!
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! let relay = MockRelayBuilder::new().run().await?;
//! println!("listening on {}", relay.url());
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature   | Default | Description                                                                                        |
//! | --------- | :-----: | -------------------------------------------------------------------------------------------------- |
//! | `memory`  |   ✅    | Pull `nula-storage-memory` so [`MockRelayBuilder::run`] supplies a default `MemoryDatabase`.       |
//! | `tracing` |   ❌    | Emit `tracing` spans on connection lifecycle and policy verdicts.                                  |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-relay-builder")]
#![forbid(unsafe_code)]

// Reference optional crates so the workspace `unused_crate_dependencies`
// lint stays quiet when their feature flags are off.
// dev-dependency that integration tests pull in but the lib does not.
#[cfg(test)]
use nula_relay as _;
#[cfg(feature = "tracing")]
use tracing as _;

pub mod error;
pub mod options;
pub mod policy;

mod builder;
mod connection;
mod server;

pub use self::builder::MockRelayBuilder;
pub use self::error::Error;
pub use self::options::MockRelayOptions;
pub use self::policy::{AcceptAllReads, AcceptAllWrites, AdmitVerdict, ReadPolicy, WritePolicy};
pub use self::server::MockRelay;
