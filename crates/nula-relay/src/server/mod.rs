//! In-process programmable Nostr relay server.
//!
//! This module (the `server` feature) binds a real
//! [`tokio::net::TcpListener`] and speaks Nostr over WebSocket via
//! `tokio-tungstenite`, persisting events through any
//! [`nula_storage::NostrDatabase`] backend. It serves a NIP-11 relay
//! information document over HTTP, dispatches NIP-01
//! `EVENT` / `REQ` / `CLOSE`, NIP-42 `AUTH`, NIP-45 `COUNT`, and
//! NIP-77 `NEG-*`, and enforces NIP-09 deletion, NIP-40 expiration, and
//! NIP-70 protected events. Admission is further shaped by pluggable
//! [`WritePolicy`] / [`QueryPolicy`] hooks and the caps on
//! [`MockRelayOptions`] (connections, active subscriptions, filter
//! limits, proof-of-work, and per-connection rate limits).
//!
//! An optional NIP-86 management API ([`MockRelayBuilder::management`])
//! exposes runtime moderation (ban / allow pubkeys, allowed kinds,
//! blocked IPs, relay metadata) over an HTTP `POST` endpoint authorized
//! by NIP-98.
//!
//! # Why a real server?
//!
//! - **End-to-end integration tests** for upper layers
//!   (`nula-relay-pool`, `nula-gossip`, `nula`).
//! - **Local development** — running a full Nostr stack against a
//!   throw-away relay on `127.0.0.1:0` avoids depending on the
//!   public relay graph for fast iteration.
//!
//! TLS, multi-host routing, and a deployable production binary are
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
pub mod management;
pub mod options;
pub mod policy;

mod builder;
mod connection;
mod relay;

pub use nula_core::nips::nip11::{RelayInformation, RelayLimitation};

pub use self::builder::MockRelayBuilder;
pub use self::error::Error;
pub use self::management::ManagementState;
pub use self::options::{MockRelayOptions, Nip42Mode, RateLimit};
pub use self::policy::{
    AcceptAllQueries, AcceptAllWrites, AdmitVerdict, AuthorAllowlist, QueryPolicy, WritePolicy,
};
pub use self::relay::MockRelay;
