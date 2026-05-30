//! In-memory backend for `nula-storage`.
//!
//! This module implements [`crate::NostrDatabase`]
//! against a `BTreeMap` / `HashMap` core. The store is ideal for
//! tests, ephemeral relay pools, and any caller that does not need
//! on-disk persistence.
//!
//! # Quickstart
//!
//! ```rust
//! use nula_storage::NostrDatabase;
//! use nula_storage::memory::MemoryDatabase;
//!
//! # async fn doc() -> Result<(), nula_storage::Error> {
//! let db = MemoryDatabase::new();
//! assert!(db.wipe().await.is_ok()); // empty store, no-op
//! # Ok(()) }
//! ```
//!
//! # Layering
//!
//! The handle is `Send + Sync + Clone`; cloning is `Arc`-cheap and
//! every clone shares the same backing store. The store is wrapped in
//! a `std::sync::RwLock`, so readers scale and writers serialise.
//! Lock guards never cross an `await`, so every returned future is
//! `Send`.
//!
//! ## Capacity & semantics
//!
//! The store honours the protocol-level write rules out of the box:
//!
//! - **NIP-09**: kind-5 deletion events tombstone their targets.
//! - **NIP-40**: events past their expiration tag are rejected with
//!   [`crate::RejectedReason::Expired`].
//! - **NIP-62**: kind-62 vanish requests purge prior writes from the
//!   same author and reject future writes.
//! - **Kind ranges**: ephemeral kinds (20000..30000) are dropped;
//!   replaceable (10000..20000) and addressable (30000..40000) kinds
//!   keep only the newest event per `(kind, author)` /
//!   `(kind, author, d)`.

mod builder;
mod database;
mod options;
mod query;
mod store;

pub use self::builder::MemoryDatabaseBuilder;
pub use self::database::MemoryDatabase;
pub use self::options::MemoryDatabaseOptions;
