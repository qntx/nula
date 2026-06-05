//! Crate-local error type for the redb backend.
//!
//! `Error` wraps every failure path the redb backend can produce:
//! redb engine errors, filesystem I/O, postcard encode/decode,
//! codec-version mismatches, and blocking-task join failures. The
//! variants are concrete enough to be actionable; they convert into
//! `nula_storage::Error::Backend` at the trait boundary so consumers
//! do not have to learn the redb vocabulary unless they want to.

use std::io;

use thiserror::Error;

/// Errors emitted by the redb backend.
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic crate-level error name (matches io::Error)"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// redb engine operation failed (transaction / table / storage /
    /// commit).
    #[error("redb engine error: {0}")]
    Redb(#[from] ::redb::Error),

    /// Filesystem operation around the database file failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// `postcard` failed to encode an event before writing it.
    #[error("event encode failed: {0}")]
    Encode(postcard::Error),

    /// `postcard` failed to decode a record off disk; the database is
    /// either corrupt or stored under a schema version this build does
    /// not understand.
    #[error("event decode failed: {0}")]
    Decode(postcard::Error),

    /// On-disk record carries a version byte newer than the running
    /// binary understands. Bump the crate version or run a migration.
    #[error("unsupported on-disk codec version: {0}")]
    UnsupportedCodecVersion(u8),

    /// Stored payload is empty / truncated — never produced by a
    /// healthy writer.
    #[error("stored event payload is empty")]
    EmptyPayload,

    /// A record decoded structurally but a field violated an invariant
    /// the writer guarantees (e.g. a non-hex id / pubkey in the
    /// borrowed match projection). Indicates on-disk corruption or an
    /// incompatible writer.
    #[error("corrupt stored record: {0}")]
    CorruptRecord(&'static str),

    /// Catch-all for blocking-task scheduling failures.
    #[error("blocking task join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// redb splits its failures across several concrete error types, each
/// of which converts into the catch-all [`redb::Error`]. Funnel them
/// all into [`Error::Redb`] so `?` works directly on every redb call.
macro_rules! from_redb_error {
    ($($ty:ty),+ $(,)?) => {
        $(impl From<$ty> for Error {
            fn from(value: $ty) -> Self {
                Self::Redb(::redb::Error::from(value))
            }
        })+
    };
}

from_redb_error!(
    ::redb::DatabaseError,
    ::redb::TransactionError,
    ::redb::TableError,
    ::redb::StorageError,
    ::redb::CommitError,
);

impl From<Error> for crate::Error {
    fn from(value: Error) -> Self {
        Self::backend(value)
    }
}
