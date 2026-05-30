//! Error surface for [`crate::pool::RelayPool`].
//!
//! Follows the workspace error contract from
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, every variant carries typed data, every boxed
//! source is `Send + Sync + 'static`. The variant set is deliberately
//! small — most multi-relay failures are *partial* successes that
//! end up in [`crate::pool::Output::failed`] rather than bubbling up here.

use nula_core::RelayUrl;
use thiserror::Error;

/// Errors raised by [`crate::pool::RelayPool`] operations.
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name (matches std::io::Error)"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The pool has been shut down. Either an explicit
    /// [`crate::pool::RelayPool::shutdown`] call or the last clone of the
    /// pool handle being dropped.
    #[error("relay pool has been shut down")]
    Shutdown,

    /// The caller referenced a relay url that is not in the pool.
    #[error("relay '{0}' not found in pool")]
    RelayNotFound(RelayUrl),

    /// The pool already holds [`crate::pool::RelayPoolOptions::max_relays`]
    /// relays. Drop one before adding another.
    #[error("relay pool is full: limit {limit}")]
    TooManyRelays {
        /// The configured cap.
        limit: usize,
    },

    /// The caller invoked a fan-out operation (`send_event_to`,
    /// `subscribe_to`, `stream_events_to`, …) with an empty url set.
    /// This is treated as caller error rather than a 0-of-0
    /// successful fan-out so the mistake surfaces immediately.
    #[error("no relays specified for fan-out operation")]
    NoRelaysSpecified,

    /// A single-relay operation surfaced an error before the pool
    /// could route it into [`crate::pool::Output::failed`]. In practice
    /// this only fires when the pool itself cannot perform the
    /// dispatch (e.g. `Relay::subscribe` returns
    /// [`crate::Error::Shutdown`] for the picked relay).
    #[error(transparent)]
    Relay(#[from] crate::Error),

    /// The pool's auto-save event hook (see
    /// [`crate::pool::RelayPoolOptions::auto_save_events`]) bubbled up an
    /// error from the underlying database. Most callers should treat
    /// this as advisory — the relay still received the event and
    /// other consumers can still observe it.
    #[error(transparent)]
    Storage(#[from] nula_storage::Error),

    /// [`crate::pool::RelayPoolBuilder::build`] was called without a prior
    /// [`crate::pool::RelayPoolBuilder::database`] invocation.
    #[error("RelayPoolBuilder requires a NostrDatabase (call `.database(...)` before `.build()`)")]
    MissingDatabase,

    /// [`crate::pool::RelayPoolBuilder::build`] was called without a prior
    /// [`crate::pool::RelayPoolBuilder::transport`] invocation **and** the
    /// `default-transport` feature is off, so the builder cannot
    /// default the transport for the caller.
    #[error(
        "RelayPoolBuilder requires a WebSocketTransport (call `.transport(...)` or enable the `default-transport` feature)"
    )]
    MissingTransport,
}
