//! NIP-46 (Nostr Connect) remote signer client.
//!
//! `nula-signer-connect` is Layer 4 of the `nula` workspace. It
//! bridges a [`nula_relay_pool::RelayPool`] to a remote NIP-46
//! signer (a "bunker") and exposes the resulting handle as a
//! [`nula_core::NostrSigner`].
//!
//! See [ADR-0009](../../docs/adr/0009-multi-relay-routing-remote-signer.md)
//! for the full design record.
//!
//! # Quickstart (`bunker://`)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_core::nips::nip46::Uri;
//! use nula_signer_connect::NostrConnect;
//! use nula_relay_pool::RelayPool;
//! use nula_storage::NostrDatabase;
//!
//! # async fn doc(db: Arc<dyn NostrDatabase>) -> Result<(), Box<dyn std::error::Error>> {
//! let uri: Uri = "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.example.com".parse()?;
//! let pool = RelayPool::builder().database(db).build();
//! let client = NostrConnect::builder()
//!     .uri(uri)
//!     .embedded_pool(pool)
//!     .build()
//!     .await?;
//! let user_pk = client.get_public_key().await?;
//! let _ = user_pk;
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature             | Default | Description                                         |
//! | ------------------- | :-----: | --------------------------------------------------- |
//! | `nip04`             |   ✅    | Bridge the legacy NIP-04 RPCs.                      |
//! | `default-transport` |   ❌    | Ship the embedded pool with a working transport.    |
//! | `tracing`           |   ❌    | Emit structured spans on every dispatch.            |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-signer-connect")]
#![forbid(unsafe_code)]

// Dev-dependencies pulled in only by integration tests.
#[cfg(test)]
use nula_relay_builder as _;
// `nula-storage` is referenced by transitive `RelayPool::database()`
// signatures and is part of the public surface every consumer
// already pulls in; keep the dep so the API stays stable when we
// add storage-aware helpers later. Hedge silences the workspace's
// `unused_crate_dependencies` lint without forcing every `lib.rs`
// reader to wonder why we depend on it.
use nula_storage as _;
#[cfg(test)]
use nula_storage_memory as _;
#[cfg(feature = "tracing")]
use tracing as _;

pub mod auth;
pub mod error;
pub mod options;

mod client;
mod dispatcher;
mod inner;
mod pending;
mod pool_handle;
mod signer_impl;

pub use self::auth::{AuthUrlHandler, IntoAuthUrlHandler, RejectAuthUrl};
pub use self::client::{NostrConnect, NostrConnectBuilder};
pub use self::error::Error;
pub use self::options::NostrConnectOptions;
pub use self::pool_handle::PoolMode;
