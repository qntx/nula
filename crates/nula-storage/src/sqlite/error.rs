//! Error surface for the `SQLite` backend.

use thiserror::Error;

/// Errors raised by [`crate::sqlite::SqliteDatabase`].
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// `rusqlite` returned a backend-specific failure (I/O, schema
    /// mismatch, lock contention, …).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Filesystem I/O failed while creating the `SQLite` parent
    /// directory.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// `postcard` failed to encode an outbound event payload. Should
    /// not happen for round-trip-safe [`nula_core::Event`] values; if
    /// it does, it points at a bug in `nula-core`'s `Serialize` impl.
    #[error("encode error: {0}")]
    Encode(postcard::Error),

    /// `postcard` failed to decode an on-disk payload. Indicates
    /// either a corrupted database file or a forward-incompatible
    /// codec change.
    #[error("decode error: {0}")]
    Decode(postcard::Error),

    /// Stored payload is empty -- never written by this crate, so a
    /// hit usually means the `SQLite` file was truncated mid-write.
    #[error("stored payload was empty (corrupted database?)")]
    EmptyPayload,

    /// Stored payload's version byte is not one this build knows
    /// about. The caller should upgrade the binary or migrate the
    /// database before retrying.
    #[error("unsupported on-disk codec version: {0}")]
    UnsupportedCodecVersion(u8),

    /// The thread the `SQLite` operation was scheduled on panicked.
    /// Should not happen in normal operation; a hit indicates a bug
    /// in `tokio`'s `spawn_blocking`.
    #[error("background SQLite worker panicked: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// Inner [`crate::memory::MemoryDatabase`] backend rejected an
    /// operation (effectively unreachable for memory-backed code
    /// paths, but surfaced here so the public method signatures match
    /// the [`crate::NostrDatabase`] contract).
    #[error(transparent)]
    Memory(#[from] crate::Error),
}
