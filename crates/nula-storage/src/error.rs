//! Crate-level error surface.
//!
//! Follows ADR-0004: every variant is `#[non_exhaustive]` so we can
//! extend the enum without a major bump, every boxed source is
//! `Send + Sync + 'static`, and the wrapped types stay opaque enough
//! that downstream callers cannot pattern-match on the concrete backend.

use std::error::Error as StdError;

use thiserror::Error;

/// Errors emitted by any [`crate::NostrDatabase`] implementation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Backend-specific failure.
    ///
    /// Backends wrap their own concrete error types here so the trait
    /// surface stays uniform. The inner error stays `dyn`-erased; if a
    /// caller really needs the concrete type they downcast.
    #[error(transparent)]
    Backend(Box<dyn StdError + Send + Sync + 'static>),

    /// Database has been closed and can no longer serve requests.
    ///
    /// Returned after [`crate::NostrDatabase::wipe`] semantics or an
    /// explicit shutdown path. Future calls must construct a new
    /// handle.
    #[error("database is closed")]
    Closed,

    /// The requested record did not exist.
    ///
    /// Backends use this variant for explicit lookups where "not
    /// found" is an error rather than `Ok(None)`. Most lookup methods
    /// return `Ok(None)` instead; this variant exists for the few
    /// places that semantically require presence.
    #[error("record not found")]
    NotFound,

    /// The filter would expand to an unbounded scan and was rejected.
    ///
    /// Backends are free to enforce a maximum-result-set policy. The
    /// in-memory backend never raises this; the redb backend raises it
    /// when the filter cannot be served by any secondary index and the
    /// caller did not supply a `limit`.
    #[error("query would scan the entire store; supply a filter or limit")]
    QueryTooBroad,
}

impl Error {
    /// Wrap an arbitrary backend error in [`Error::Backend`].
    ///
    /// This is the canonical conversion path from a backend-specific
    /// error type to the trait-level surface. Backends with their own
    /// concrete error enum should expose a `From<MyError> for nula_storage::Error`
    /// impl that calls this constructor.
    pub fn backend<E>(source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Backend(Box::new(source))
    }
}
