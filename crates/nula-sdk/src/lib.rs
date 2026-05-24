//! Layer-5 Nostr SDK facade for the `nula` workspace.
//!
//! [`Client`] composes the lower layers — `nula-core` (events,
//! filters, signers), `nula-relay-pool` (multi-relay coordinator),
//! `nula-gossip` (NIP-65 outbox routing), `nula-sync` (NIP-77
//! Negentropy), `nula-signer-connect` (NIP-46 remote signer) — into
//! a single ergonomic surface modelled on
//! [`nostr_sdk::Client`](https://docs.rs/nostr-sdk/latest/nostr_sdk/client/struct.Client.html)
//! from the upstream `rust-nostr` reference.
//!
//! See [ADR-0011](../../docs/adr/0011-layer5-sdk-facade.md) for the
//! public-surface decisions, the deliberate departures from upstream
//! (no implicit `RelayUrlArg` polymorphism, no deprecated
//! `add_*_relay` shorthands, builder-pattern call sites replaced by
//! plain async methods), and the feature-flag layout.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use nula_core::{EventBuilder, Filter, Keys, Kind};
//! use nula_sdk::Client;
//!
//! # async fn doc() -> Result<(), nula_sdk::Error> {
//! let keys = Keys::generate().expect("OS RNG");
//! let client = Client::builder().signer(keys).build()?;
//!
//! client.add_relay("wss://relay.example.com").await?;
//! client.connect().await;
//!
//! client.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature             | Default | Description                                                                       |
//! | ------------------- | :-----: | --------------------------------------------------------------------------------- |
//! | `gossip`            |   ✅    | NIP-65 outbox routing helpers (re-export [`nula_gossip::Gossip`]).                |
//! | `sync`              |   ✅    | NIP-77 reconciliation via [`nula_sync`].                                          |
//! | `memory-fallback`   |   ✅    | Default to [`nula_storage_memory::MemoryDatabase`] when no database is configured.|
//! | `default-transport` |   ✅    | Pull a tokio-tungstenite WebSocket transport from `nula-relay-pool`.              |
//! | `nip46`             |   ❌    | NIP-46 remote signer integration via [`nula_signer_connect`].                     |
//! | `tracing`           |   ❌    | Emit `tracing` spans on every public `Client` method (ADR-0005 field names).      |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-sdk")]
#![forbid(unsafe_code)]

pub mod builder;
pub mod client;
pub mod error;
pub mod util;

// Pin optional or "still-to-be-wired" crates so the workspace
// `unused_crate_dependencies` lint stays quiet. The publishing /
// fetching / sync methods in the next Phase 6.4 commits will start
// consuming `futures` and `tokio_stream` directly.
use futures as _;
// Re-export the most-needed Layer-1/4 types so common workflows do
// not need a parallel `nula-core` / `nula-relay-pool` import line.
pub use nula_core::{
    Event, EventBuilder, EventId, Filter, Keys, Kind, NostrSigner, PublicKey, RelayUrl, SecretKey,
    SubscriptionId, Tag, Timestamp,
};
#[cfg(feature = "gossip")]
#[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
pub use nula_gossip::Gossip;
// Dev-only dependencies consumed by the integration tests under
// `tests/` once they land.
#[cfg(test)]
use nula_relay_builder as _;
pub use nula_relay_pool::{Output, PoolNotification, RelayCapabilities, RelayPoolOptions};
#[cfg(feature = "nip46")]
use nula_signer_connect as _;
#[cfg(test)]
use nula_sync as _;
#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub use nula_sync::{ReconcileOutcome, Reconciliation};
use tokio_stream as _;
#[cfg(feature = "tracing")]
use tracing as _;

pub use self::builder::ClientBuilder;
pub use self::client::Client;
pub use self::error::Error;
pub use self::util::IntoRelayUrl;
