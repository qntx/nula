//! In-process programmable Nostr relay server.
//!
//! This module (the `server` feature) binds
//! a real [`tokio::net::TcpListener`], speaks NIP-01 over WebSocket
//! via `tokio-tungstenite`, persists events through any
//! [`nula_storage::NostrDatabase`] backend, and accepts pluggable
//! [`WritePolicy`] / [`QueryPolicy`] hooks for filtering inbound
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
//! use nula_relay::server::MockRelayBuilder;
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
//! | `server`  |   ❌    | Enable this module; supplies a default `nula_storage::memory::MemoryDatabase` for [`MockRelayBuilder::run`]. |
//! | `tracing` |   ❌    | Emit `tracing` spans on connection lifecycle and policy verdicts.                                  |

pub mod error;
pub mod options;
pub mod policy;

mod builder;
mod connection;
mod relay;

pub use self::builder::MockRelayBuilder;
pub use self::error::Error;
pub use self::options::{MockRelayOptions, Nip42Mode, RateLimit};
pub use self::policy::{
    AcceptAllQueries, AcceptAllWrites, AdmitVerdict, AuthorAllowlist, QueryPolicy, WritePolicy,
};
pub use self::relay::MockRelay;
