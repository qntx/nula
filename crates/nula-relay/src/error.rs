//! Top-level error surface for `nula-relay`.
//!
//! Follows the workspace error contract from
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, every variant carries typed data, every boxed
//! source is `Send + Sync + 'static`. Variants are organised by who
//! caused the failure — the transport, the protocol, the caller, or
//! the relay itself — so callers can decide between retry, give-up,
//! and bubble-up branches without string-matching.

use std::time::Duration;

use nula_core::message::{ClientMessageError, RelayMessageError};
use nula_core::{EventId, SubscriptionId};
use thiserror::Error;

use crate::transport as net;

/// Errors raised by [`crate::Relay`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The transport layer raised an error during connect, send, or
    /// receive. The original [`net::Error`] is preserved.
    #[error("transport error: {0}")]
    Transport(#[from] net::Error),

    /// The relay sent a frame this client could not parse as a valid
    /// NIP-01 [`RelayMessage`].
    ///
    /// [`RelayMessage`]: nula_core::RelayMessage
    #[error("malformed relay message: {0}")]
    MalformedRelayMessage(#[from] RelayMessageError),

    /// Internal serialisation of an outbound [`ClientMessage`] failed.
    /// This indicates a bug in this crate or in `nula-core`; it is
    /// not a network condition the caller can recover from by
    /// retrying.
    ///
    /// [`ClientMessage`]: nula_core::ClientMessage
    #[error("failed to serialise outbound message: {0}")]
    SerializeClientMessage(#[from] ClientMessageError),

    /// JSON encoding of an outbound message failed. Same caveat as
    /// [`Self::SerializeClientMessage`].
    #[error("JSON encoding error: {0}")]
    Json(#[from] serde_json::Error),

    /// The relay rejected an event with `OK <id> false <message>`.
    #[error("relay rejected event {event_id}: {message}")]
    PublishRejected {
        /// The event id the relay refused.
        event_id: EventId,
        /// The reason string the relay returned. Use
        /// [`nula_core::message::MachineReadablePrefix::from_reason`]
        /// to recover a structured prefix.
        message: String,
    },

    /// A `publish()` call did not receive an `OK` frame within its
    /// configured deadline.
    #[error("publish of event {event_id} timed out after {timeout:?}")]
    PublishTimeout {
        /// The event id whose `OK` reply never arrived.
        event_id: EventId,
        /// The deadline the caller configured.
        timeout: Duration,
    },

    /// A subscription was closed by the relay with a `CLOSED` frame.
    #[error("subscription {subscription_id} closed by relay: {message}")]
    SubscriptionClosed {
        /// The subscription that was closed.
        subscription_id: SubscriptionId,
        /// The CLOSED frame's reason string.
        message: String,
    },

    /// The relay actor is no longer running. The last [`Relay`]
    /// handle was dropped (`Inner::Drop` fires the actor's
    /// `Shutdown` command) while a borrowed reference was still in
    /// flight.
    ///
    /// [`Relay`]: crate::Relay
    #[error("relay has been shut down")]
    Shutdown,

    /// A `connect()` call did not transition into the `Connected`
    /// state within the configured deadline.
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// The caller asked for an operation that requires the relay to
    /// be connected (e.g. `publish` with `skip_when_disconnected =
    /// false`) but the connection is currently down.
    #[error("relay is not connected")]
    NotConnected,

    /// The caller exceeded
    /// [`crate::RelayLimits::max_subscriptions`].
    #[error("too many in-flight subscriptions: {limit}")]
    TooManySubscriptions {
        /// The configured cap.
        limit: usize,
    },

    /// The caller exceeded
    /// [`crate::RelayLimits::max_pending_publishes`].
    #[error("too many in-flight publishes: {limit}")]
    TooManyPendingPublishes {
        /// The configured cap.
        limit: usize,
    },

    /// A subscription was started against an id that is already
    /// in flight on this relay.
    #[error("subscription id {0} is already active")]
    DuplicateSubscription(SubscriptionId),

    /// [`crate::RelayBuilder::build`] was called without a prior
    /// [`crate::RelayBuilder::transport`] invocation **and** the
    /// `default-transport` feature is off, so the builder cannot
    /// default the transport for the caller.
    #[error(
        "RelayBuilder requires a WebSocketTransport (call `.transport(...)` or enable the `default-transport` feature)"
    )]
    MissingTransport,
}
