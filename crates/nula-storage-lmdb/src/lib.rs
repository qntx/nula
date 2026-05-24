//! LMDB-backed [`nula_storage::NostrDatabase`] implementation.
//!
//! `nula-storage-lmdb` wraps a [`heed`](https://docs.rs/heed) LMDB
//! environment with seven secondary indexes covering the common
//! NIP-01 filter shapes. Events are encoded with `postcard`, prefixed
//! with a single version byte so schema changes can be detected at
//! read time.
//!
//! # Concurrency
//!
//! LMDB is single-writer / multi-reader at the env level. Every
//! mutation runs through a dedicated ingester worker thread
//! (`std::thread::Thread`), while reads run on tokio's blocking
//! thread pool. Cloning [`LmdbDatabase`] is `Arc`-cheap; the last
//! drop sends a `Shutdown` command to the ingester and joins it.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! use nula_storage::NostrDatabase;
//! use nula_storage_lmdb::LmdbDatabase;
//!
//! let db = LmdbDatabase::builder("./data/nula").build().await?;
//! let count = db.count(nula_core::Filter::new()).await?;
//! println!("stored events: {count}");
//! # Ok(()) }
//! ```
//!
//! # Workspace ADRs
//!
//! - [ADR-0007](../../docs/adr/0007-storage-layer-architecture.md)
//!   records the trait surface, the choice of `heed` + `postcard`,
//!   the secondary-index schema, and the `unsafe_code` exemption
//!   required by `heed`'s mmap-based API.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-storage-lmdb")]
// ADR-0007: `heed::EnvOpenOptions::open` is unsafe because it mmaps
// the database file. Every unsafe block is annotated with a SAFETY
// comment in `store.rs`; no other unsafe code lives in this crate.
#![deny(unsafe_code)]

// `tracing` is wired up for future hot-path instrumentation but no
// span call site exists today. Bind it `as _` so the workspace
// `unused_crate_dependencies` lint stays quiet.
// `tempfile` is a dev-dependency consumed by tests under `tests/`;
// pin it `as _` so cargo's unused_crate_dependencies lint does not
// fire against the library build.
// Shared conformance suite is only consumed by `tests/suite.rs`.
#[cfg(test)]
use nula_storage_test_suite as _;
#[cfg(test)]
use tempfile as _;
#[cfg(feature = "tracing")]
use tracing as _;

mod builder;
mod codec;
mod database;
mod error;
mod ingester;
mod keys;
mod options;
mod store;

pub use self::builder::LmdbDatabaseBuilder;
pub use self::database::LmdbDatabase;
pub use self::error::Error;
pub use self::options::LmdbDatabaseOptions;
