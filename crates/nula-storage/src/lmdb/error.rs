//! Crate-local error type.
//!
//! `Error` wraps every failure path the LMDB backend can produce:
//! heed I/O, postcard encode/decode, codec-version mismatches, missing
//! envs, channel shutdowns. The variants are concrete enough to be
//! actionable; they convert into `nula_storage::Error::Backend` at the
//! trait boundary so consumers do not have to learn the LMDB
//! vocabulary unless they want to.

use std::io;

use thiserror::Error;

/// Errors emitted by the LMDB backend.
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic crate-level error name (matches io::Error)"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// LMDB env / txn / dbi operation failed.
    #[error("LMDB engine error: {0}")]
    Heed(#[from] heed::Error),

    /// Filesystem operation around the LMDB directory failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// `postcard` failed to encode an event before writing it.
    #[error("event encode failed: {0}")]
    Encode(postcard::Error),

    /// `postcard` failed to decode a record off disk; the database
    /// is either corrupt or stored under a schema version this
    /// build does not understand.
    #[error("event decode failed: {0}")]
    Decode(postcard::Error),

    /// On-disk record carries a version byte newer than the
    /// running binary understands. Bump the crate version or run a
    /// migration.
    #[error("unsupported on-disk codec version: {0}")]
    UnsupportedCodecVersion(u8),

    /// Stored payload is empty / truncated — never produced by a
    /// healthy writer.
    #[error("stored event payload is empty")]
    EmptyPayload,

    /// A record decoded structurally but a field violated an invariant
    /// the writer guarantees (e.g. a non-hex id / pubkey in the borrowed
    /// match projection). Indicates on-disk corruption or an
    /// incompatible writer.
    #[error("corrupt stored record: {0}")]
    CorruptRecord(&'static str),

    /// Writer thread has exited; subsequent operations cannot make
    /// progress. The handle should be dropped.
    #[error("writer thread is gone")]
    WriterGone,

    /// Caller tried to use the database after [`crate::lmdb::LmdbDatabase`]
    /// shutdown completed.
    #[error("database is closed")]
    Closed,

    /// Catch-all for blocking-task scheduling failures.
    #[error("blocking task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

impl From<Error> for crate::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Closed => Self::Closed,
            other => Self::backend(other),
        }
    }
}
