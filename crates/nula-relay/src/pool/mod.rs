//! Multi-relay orchestration on top of [`crate::Relay`].
//!
//! This module manages a
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
//! use nula_relay::pool::{RelayCapabilities, RelayPool};
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
//! | `default-transport` |   ✅    | Ship the tokio-tungstenite transport so [`RelayPool::builder`] is sufficient. |
//! | `tracing`           |   ✅    | Emit `tracing` spans on every fan-out operation.                   |

pub mod capabilities;
pub mod error;
pub mod notification;
pub mod options;
pub mod output;

mod handle;
mod inner;
mod state;
mod stream;

pub use self::capabilities::{AtomicRelayCapabilities, RelayCapabilities};
pub use self::error::Error;
pub use self::handle::{RelayPool, RelayPoolBuilder};
pub use self::notification::PoolNotification;
pub use self::options::RelayPoolOptions;
pub use self::output::Output;
