//! NIP-77 Negentropy reconciliation sessions for the `nula` stack.
//!
//! `nula-sync` is Layer 3 of the workspace. It wraps the upstream
//! [`negentropy`] state machine in two role-specific session types
//! ([`Reconciliation`] for initiators, [`Responder`] for relays /
//! test harnesses) and provides the
//! `(EventId, Timestamp)` ↔ [`negentropy::Id`] glue plus an optional
//! [`nula_storage::NostrDatabase`] adapter.
//!
//! What this crate explicitly does **not** do:
//!
//! - No transport. The wire frames live in
//!   [`nula_core::ClientMessage`] / [`nula_core::RelayMessage`]
//!   (`NegOpen` / `NegMsg` / `NegClose` / `NegErr`); the SDK in
//!   [`nula_sdk`](https://docs.rs/nula-sdk) drives the loop across a
//!   `nula_relay_pool::RelayPool`.
//! - No event download. Once [`ReconcileOutcome::need`] tells you
//!   which event ids the peer holds, you fetch them via your usual
//!   subscription path.
//!
//! See [ADR-0010](../../docs/adr/0010-nip77-negentropy-as-standalone-crate.md)
//! for the rationale behind keeping this crate separate from
//! `nula-core` and `nula-relay-pool`.
//!
//! # Quickstart
//!
//! ```rust
//! use nula_core::event::EventId;
//! use nula_core::types::Timestamp;
//! use nula_sync::{prepare_storage, Reconciliation, Responder};
//!
//! # fn doc() -> Result<(), nula_sync::Error> {
//! let mine: Vec<(EventId, Timestamp)> = Vec::new();
//! let theirs: Vec<(EventId, Timestamp)> = Vec::new();
//!
//! let mut initiator = Reconciliation::with_defaults(prepare_storage(mine)?)?;
//! let mut responder = Responder::with_defaults(prepare_storage(theirs)?)?;
//!
//! // 1. Send `initiator.opening_message()` to the peer.
//! let mut next = initiator.opening_message().to_vec();
//! // 2. Each round, feed the responder reply back to the initiator
//! //    until `is_complete()` is true.
//! loop {
//!     let reply = responder.reconcile(&next)?;
//!     let outcome = initiator.reconcile(&reply)?;
//!     if let Some(msg) = outcome.next_message {
//!         next = msg;
//!     } else {
//!         break;
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! # Feature flags
//!
//! | Feature   | Default | Description                                                                          |
//! | --------- | :-----: | ------------------------------------------------------------------------------------ |
//! | `storage` |   ❌    | Add [`from_database`] adapter pulling items from a [`nula_storage::NostrDatabase`].  |
//! | `tracing` |   ❌    | Emit `tracing` spans per reconciliation step (field names per ADR-0005).             |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-sync")]
#![forbid(unsafe_code)]

pub mod error;
pub mod session;
pub mod storage_vec;

#[cfg(feature = "storage")]
#[cfg_attr(docsrs, doc(cfg(feature = "storage")))]
pub mod storage_db;

#[cfg(feature = "tracing")]
use tracing as _;

pub use self::error::Error;
pub use self::session::{DEFAULT_FRAME_SIZE_LIMIT, ReconcileOutcome, Reconciliation, Responder};
#[cfg(feature = "storage")]
#[cfg_attr(docsrs, doc(cfg(feature = "storage")))]
pub use self::storage_db::from_database;
pub use self::storage_vec::{event_id_to_neg_id, neg_id_to_event_id, prepare_storage};
