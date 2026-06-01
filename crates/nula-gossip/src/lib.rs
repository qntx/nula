//! NIP-65 / NIP-17 multi-relay routing graph.
//!
//! `nula-gossip` is Layer 4 of the `nula` workspace. It turns a
//! stream of Nostr events into a routing table:
//!
//! - which relays the user **writes** to (NIP-65 outbox + hints +
//!   most-received),
//! - which relays the user **reads** from (NIP-65 inbox + hints +
//!   most-received),
//! - which relays the user prefers for **direct messages**
//!   ([NIP-17] `kind:10050`).
//!
//! The crate also breaks every outgoing [`Filter`] into the per-relay
//! sub-filters [`crate::Gossip::break_down_filter`] returns. The
//! actual fan-out lives one layer up in [`nula_relay::pool::RelayPool`].
//!
//! See [ADR-0009](../../docs/adr/0009-multi-relay-routing-remote-signer.md)
//! for the full design record.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_core::PublicKey;
//! use nula_gossip::Gossip;
//! use nula_storage::NostrDatabase;
//!
//! # async fn doc(db: Arc<dyn NostrDatabase>, user: PublicKey) -> Result<(), Box<dyn std::error::Error>> {
//! let gossip = Gossip::builder().database(db).build()?;
//! gossip.warm_up([user]).await?;
//! let outbox = gossip.outbox_relays(&user).await;
//! let _ = outbox;
//! # Ok(()) }
//! ```
//!
//! # Persistence
//!
//! `nula-gossip` keeps its routing graph in memory but writes every
//! ingested NIP-65 / NIP-17 event back through the configured
//! [`nula_storage::NostrDatabase`]. On startup the caller invokes
//! [`Gossip::warm_up`] for the public keys they care about and the
//! cache rebuilds itself from disk. There is **no** dedicated
//! `nula-gossip-sqlite` crate -- pick the backend you already use
//! for events (`nula-storage-sqlite` for survive-a-reboot,
//! `nula-storage-lmdb` for high-throughput, `nula-storage-memory`
//! for ephemeral processes) and the gossip layer inherits its
//! durability story for free.
//!
//! # Feature flags
//!
//! | Feature   | Default | Description                                      |
//! | --------- | :-----: | ------------------------------------------------ |
//! | `tracing` |   ❌    | Emit structured spans on selection / refresh.    |
//!
//! [NIP-17]: https://github.com/nostr-protocol/nips/blob/master/17.md
//! [`Filter`]: nula_core::Filter
//! [`Gossip::warm_up`]: crate::Gossip::warm_up

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-gossip")]
#![forbid(unsafe_code)]

// `tempfile` is a dev-dependency consumed only by integration tests;
// the workspace `unused_crate_dependencies` lint fires at the lib
// root for test-only deps, so hedge it here.
#[cfg(test)]
use tempfile as _;
#[cfg(feature = "tracing")]
use tracing as _;

pub mod error;
pub mod options;
pub mod routes;
pub mod ttl;

mod event;
mod filter;
mod gossip;
mod inner;
mod refresher;
mod selection;

pub use self::error::Error;
pub use self::event::EventRoute;
pub use self::filter::BrokenDownFilters;
pub use self::gossip::{Gossip, GossipBuilder};
pub use self::options::{AllowedRelays, GossipLimits, GossipOptions, ListKind};
pub use self::refresher::RefresherHandle;
pub use self::routes::UserRoutes;
pub use self::ttl::{OutdatedKey, PublicKeyStatus};
