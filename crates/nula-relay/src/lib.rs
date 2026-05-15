//! Single-relay [NIP-01] state machine.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md
//!
//! `nula-relay` is Layer 3 of the `nula` workspace: it wraps a
//! [`nula_net::WebSocketTransport`] with the protocol state
//! machine — connection lifecycle, automatic reconnect with full
//! jitter exponential backoff, REQ/CLOSE subscription tracking,
//! EVENT/EOSE/CLOSED dispatch, publish ACK correlation, and an
//! optional NIP-42 AUTH challenge handler.
//!
//! Multi-relay orchestration lives one layer up in `nula-relay-pool`;
//! this crate operates against exactly one URL.
//!
//! # Architecture
//!
//! Every [`Relay`] is a thin `Arc<Inner>` over a `tokio::spawn`ed
//! actor task. The public handle is `Send + Sync + Clone`; cloning
//! costs one `Arc` bump. Dropping the last clone signals the actor
//! to shut down — there is no manual `close()` to forget.
//!
//! See [ADR-0006](../../docs/adr/0006-single-relay-actor-model.md) for
//! the design record.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use futures::StreamExt;
//! use nula_core::{Filter, Kind, RelayUrl, SubscriptionId};
//! use nula_relay::{Relay, SubscribeOptions};
//!
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! let url = RelayUrl::parse("wss://relay.damus.io")?;
//! let relay = Relay::new(url);
//! relay.connect().await?;
//!
//! let id = SubscriptionId::generate()?;
//! let filters = vec![Filter::new().kind(Kind::TEXT_NOTE).limit(10)];
//! let mut sub = relay.subscribe(id, filters, SubscribeOptions::default()).await?;
//!
//! while let Some(item) = sub.next().await {
//!     println!("{item:?}");
//! }
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature             | Default | Description                                                                |
//! | ------------------- | :-----: | -------------------------------------------------------------------------- |
//! | `default-transport` |   ✅    | Re-export `nula-net/default-transport` so [`Relay::new`] is available.     |
//! | `nip42`             |   ✅    | NIP-42 AUTH challenge handler + [`Relay::authenticate`] hook.              |
//! | `tracing`           |   ❌    | Emit `tracing` spans on every state transition / dispatch decision.        |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-relay")]
#![forbid(unsafe_code)]

pub mod error;
pub mod limits;
pub mod notification;
pub mod options;
pub mod policy;
pub mod stats;
pub mod status;
pub mod subscription;

mod inner;
mod relay;

pub use self::error::Error;
pub use self::limits::RelayLimits;
pub use self::notification::RelayNotification;
pub use self::options::{PublishOptions, RelayOptions, SubscribeOptions};
pub use self::policy::ReconnectPolicy;
pub use self::relay::{Relay, RelayBuilder};
pub use self::stats::RelayStats;
pub use self::status::RelayStatus;
pub use self::subscription::{SubscriptionHandle, SubscriptionItem};
