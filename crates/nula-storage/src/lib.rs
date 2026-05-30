//! Layer-3 event-store trait surface for the `nula` workspace.
//!
//! `nula-storage` defines [`NostrDatabase`] — a runtime-agnostic,
//! `dyn`-safe trait every Nostr event store implements — plus the
//! protocol semantics shared by every backend (NIP-09 deletion,
//! NIP-40 expiration, replaceable / addressable / ephemeral kind
//! routing, NIP-62 vanish).
//!
//! Backends ship as feature-gated modules so callers compile only
//! what they enable:
//!
//! | Feature      | Module             | Storage              | Persistence |
//! | ------------ | ------------------ | -------------------- | :--------:  |
//! | `memory`     | [`memory`]         | `BTreeMap` + indexes |     —       |
//! | `lmdb`       | [`lmdb`]           | LMDB (`heed`)        |     ✅      |
//! | `sqlite`     | [`sqlite`]         | `SQLite` log + replica |   ✅      |
//! | `test-suite` | [`test_suite`]     | conformance harness  |     —       |
//!
//! `memory` is on by default; the persistent backends and the
//! conformance suite are opt-in.
//!
//! # Trait shape
//!
//! Every method returns a [`nula_core::BoxFuture`] rather than an
//! `impl Future`, so the trait stays `dyn`-safe and callers can own a
//! backend through `Arc<dyn NostrDatabase>`. This is the same seam
//! shape used by the relay-layer `WebSocketTransport` one layer down —
//! see ADR-0003 for the runtime-agnostic rationale.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_core::event::Event;
//! use nula_storage::{Error, NostrDatabase, SaveEventStatus};
//!
//! async fn ingest(db: Arc<dyn NostrDatabase>, event: &Event) -> Result<(), Error> {
//!     match db.save_event(event).await? {
//!         SaveEventStatus::Success => Ok(()),
//!         SaveEventStatus::Rejected(_reason) => Ok(()),
//!         _ => Ok(()),
//!     }
//! }
//! ```
//!
//! # Workspace ADRs
//!
//! - [ADR-0001](../../docs/adr/0001-workspace-architecture.md) records
//!   the workspace crate layout.
//! - [ADR-0003](../../docs/adr/0003-async-runtime-strategy.md) records
//!   why the trait uses [`nula_core::BoxFuture`] rather than `async fn`.
//! - [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md)
//!   describes the [`Error`] enum shape.
//! - [ADR-0007](../../docs/adr/0007-storage-layer-architecture.md)
//!   records the trait surface, backend selection, and the encoding
//!   choice (`postcard` for binary backends).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-storage")]
// `deny` (not `forbid`) so the LMDB backend can carry a single
// localized `#[allow(unsafe_code, ...)]` over `heed`'s mmap open;
// see `lmdb::store` and ADR-0007.
#![deny(unsafe_code)]

// `tracing` is an optional dependency wired for future hot-path
// instrumentation in the persistent backends; no span call site
// exists yet. Bind it `as _` so the workspace
// `unused_crate_dependencies` lint stays quiet when the feature is on.
#[cfg(feature = "tracing")]
use tracing as _;

// `tempfile` is a dev-dependency consumed only by the `lmdb` /
// `sqlite` persistence integration tests; hedge it so the lib's
// test build stays quiet under `unused_crate_dependencies`.
#[cfg(test)]
use tempfile as _;

pub mod database;
pub mod error;
pub mod events;
pub mod ext;
pub mod features;
pub mod profile;
pub mod status;

#[cfg(feature = "lmdb")]
pub mod lmdb;
#[cfg(feature = "memory")]
pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "test-suite")]
pub mod test_suite;

pub use self::database::NostrDatabase;
pub use self::error::Error;
pub use self::events::Events;
pub use self::ext::NostrDatabaseExt;
pub use self::features::{Backend, Features};
pub use self::profile::Profile;
pub use self::status::{DatabaseEventStatus, RejectedReason, SaveEventStatus};
