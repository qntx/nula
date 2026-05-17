//! Multi-relay orchestration on top of [`nula_relay::Relay`].
//!
//! `nula-relay-pool` is Layer 4 of the `nula` workspace: it manages a
//! set of single-relay clients, dispatches each `publish` /
//! `subscribe` operation across the configured fan-out, and
//! deduplicates events so callers never observe the same `EventId`
//! twice.
//!
//! # Architecture
//!
//! Every [`RelayPool`] is an `Arc<Inner>` over a
//! `RwLock<HashMap<RelayUrl, Relay>>` plus a broadcast notification
//! channel. There is **no second actor task** — coordination happens
//! on the caller's runtime, while every per-relay state machine still
//! runs in [`nula_relay::Relay`]'s own actor (see
//! [ADR-0006](../../docs/adr/0006-single-relay-actor-model.md)).
//!
//! The handle is `Send + Sync + Clone`; cloning costs one `Arc`
//! bump. Dropping the last clone signals every relay to disconnect
//! and emits a final [`PoolNotification::Shutdown`]. See
//! [ADR-0008](../../docs/adr/0008-multi-relay-orchestration.md) for
//! the full design record.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_core::{Filter, Kind, RelayUrl};
//! use nula_relay_pool::{RelayCapabilities, RelayPool};
//! use nula_storage::NostrDatabase;
//!
//! # async fn doc(db: Arc<dyn NostrDatabase>) -> Result<(), Box<dyn std::error::Error>> {
//! let pool = RelayPool::builder().database(db).build()?;
//! pool.add_relay(
//!     RelayUrl::parse("wss://relay.damus.io")?,
//!     RelayCapabilities::READ | RelayCapabilities::WRITE,
//! )
//! .await?;
//! pool.connect().await;
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature             | Default | Description                                                        |
//! | ------------------- | :-----: | ------------------------------------------------------------------ |
//! | `default-transport` |   ✅    | Re-export `nula-relay/default-transport` so [`RelayPool::builder`] is sufficient. |
//! | `tracing`           |   ❌    | Emit `tracing` spans on every fan-out operation.                   |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-relay-pool")]
#![forbid(unsafe_code)]

// `tracing` is wired through the `tracing` feature gate; reference
// the crate so the workspace `unused_crate_dependencies` lint stays
// quiet when the feature is off.
// dev-dependencies that the lib itself does not touch but every
// integration-test binary pulls in on demand. Without these hedges
// the workspace `unused_crate_dependencies` lint flags them at the
// lib root.
#[cfg(test)]
use nula_relay_builder as _;
#[cfg(test)]
use nula_storage_memory as _;
#[cfg(test)]
use serde_json as _;
#[cfg(feature = "tracing")]
use tracing as _;

pub mod capabilities;
pub mod error;
pub mod notification;
pub mod options;
pub mod output;

mod inner;
mod pool;
mod state;
mod stream;

pub use self::capabilities::{AtomicRelayCapabilities, RelayCapabilities};
pub use self::error::Error;
pub use self::notification::PoolNotification;
pub use self::options::RelayPoolOptions;
pub use self::output::Output;
pub use self::pool::{RelayPool, RelayPoolBuilder};
