//! SQLite-backed [`nula_storage::NostrDatabase`] implementation.
//!
//! `nula-storage-sqlite` pairs a vendored [`SQLite`] file (used as a
//! durable append-only event log) with an in-process
//! [`nula_storage_memory::MemoryDatabase`] (hot read path + protocol
//! enforcement). On startup the crate replays every record from the
//! `SQLite` log into the memory replica; the memory backend's
//! NIP-01 / NIP-09 / NIP-40 / NIP-62 / replaceable / addressable
//! routing rules then determine the final state.
//!
//! This split is intentional: `SQLite` is excellent at durability
//! and crash-safety but a poor index for the multi-clause filter
//! shapes NIP-01 demands. The memory replica handles the hot read
//! path; `SQLite` handles "survive a reboot".
//!
//! # Quickstart
//!
//! ```rust,no_run
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! use nula_storage::NostrDatabase;
//! use nula_storage_sqlite::SqliteDatabase;
//!
//! let db = SqliteDatabase::open("./events.sqlite").await?;
//! let count = db.count(nula_core::Filter::new()).await?;
//! println!("stored events: {count}");
//! # Ok(()) }
//! ```
//!
//! [`SQLite`]: https://www.sqlite.org/index.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-storage-sqlite")]
#![forbid(unsafe_code)]
#![allow(
    clippy::excessive_nesting,
    clippy::significant_drop_tightening,
    reason = "Both lints fire on every `spawn_blocking` + `MutexGuard<Connection>` site -- intrinsic to the rusqlite API + tokio blocking-pool pattern. The guard is held for at most one SQL statement at a time, so early-drop would not actually shorten lock durations meaningfully."
)]

// `tracing` is wired up for future hot-path instrumentation but no
// span call site exists today. Bind it `as _` so the workspace
// `unused_crate_dependencies` lint stays quiet.
#[cfg(feature = "tracing")]
use tracing as _;

// Dev-only deps consumed by the integration tests under tests/.
#[cfg(test)]
use nula_storage_test_suite as _;
#[cfg(test)]
use tempfile as _;

mod codec;
mod database;
mod error;

pub use self::database::SqliteDatabase;
pub use self::error::Error;
