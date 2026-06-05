//! redb-backed [`crate::NostrDatabase`] implementation.
//!
//! `RedbDatabase` wraps a [`redb`](https://docs.rs/redb) database with
//! seven secondary indexes covering the common NIP-01 filter shapes.
//! Events are encoded with `postcard`, prefixed with a single version
//! byte so schema changes can be detected at read time.
//!
//! redb is a pure-Rust, ACID, copy-on-write B-tree store — no C
//! dependency and no `unsafe` at the engine boundary, unlike the LMDB
//! backend it replaces.
//!
//! # Concurrency
//!
//! redb is MVCC: readers run lock-free against a snapshot while a
//! single writer is serialised internally by the engine. Reads and
//! writes run on tokio's blocking thread pool. Cloning [`RedbDatabase`]
//! is `Arc`-cheap and every clone shares the same database file.
//!
//! # Quickstart
//!
//! ```rust,no_run
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! use nula_storage::NostrDatabase;
//! use nula_storage::redb::RedbDatabase;
//!
//! let db = RedbDatabase::builder("./data/nula.redb").build().await?;
//! let count = db.count(nula_core::Filter::new()).await?;
//! println!("stored events: {count}");
//! # Ok(()) }
//! ```

mod builder;
mod codec;
mod database;
mod error;
mod keys;
mod options;
mod store;

pub use self::builder::RedbDatabaseBuilder;
pub use self::database::RedbDatabase;
pub use self::error::Error;
pub use self::options::RedbDatabaseOptions;
