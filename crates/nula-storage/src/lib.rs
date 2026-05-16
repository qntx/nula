//! Layer-3 event-store trait surface for the `nula` workspace.
//!
//! `nula-storage` defines [`NostrDatabase`] — a runtime-agnostic,
//! `dyn`-safe trait every Nostr event store implements — plus the
//! protocol semantics shared by every backend (NIP-09 deletion,
//! NIP-40 expiration, replaceable / addressable / ephemeral kind
//! routing, NIP-62 vanish).
//!
//! Backends live in sibling crates so callers depend only on what
//! they need:
//!
//! | Crate                 | Storage                | Persistence |
//! | --------------------- | ---------------------- | :--------:  |
//! | `nula-storage-memory` | `BTreeSet` + indexes   |     —       |
//! | `nula-storage-lmdb`   | LMDB (`heed`)          |     ✅      |
//!
//! # Trait shape
//!
//! Every method returns a [`nula_net::BoxFuture`] rather than an
//! `impl Future`, so the trait stays `dyn`-safe and callers can own a
//! backend through `Arc<dyn NostrDatabase>`. This is the same seam
//! shape used by [`nula_net::WebSocketTransport`] one layer down — see
//! ADR-0003 for the runtime-agnostic rationale.
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
//!   why storage is split into a trait crate plus per-backend crates.
//! - [ADR-0003](../../docs/adr/0003-async-runtime-strategy.md) records
//!   why the trait uses [`nula_net::BoxFuture`] rather than `async fn`.
//! - [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md)
//!   describes the [`Error`] enum shape.
//! - [ADR-0007](../../docs/adr/0007-storage-layer-architecture.md)
//!   records the trait surface, backend selection, and the encoding
//!   choice (`postcard` for binary backends).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-storage")]
#![forbid(unsafe_code)]

pub mod database;
pub mod error;
pub mod events;
pub mod ext;
pub mod features;
pub mod profile;
pub mod status;

pub use self::database::NostrDatabase;
pub use self::error::Error;
pub use self::events::Events;
pub use self::ext::NostrDatabaseExt;
pub use self::features::{Backend, Features};
pub use self::profile::Profile;
pub use self::status::{DatabaseEventStatus, RejectedReason, SaveEventStatus};
