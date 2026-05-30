//! Pool-wide notification stream.
//!
//! Carried over a [`tokio::sync::broadcast`] channel: **multi
//! consumer, lossy on slow consumers**. The broadcast trade-off is
//! deliberate — pool consumers (UI, logs, metrics, replicators) all
//! want their own copy of every notification, and a slow consumer
//! getting a `RecvError::Lagged` is preferable to back-pressuring the
//! pool's hot path.
//!
//! Subscription events do **not** flow through this channel. They
//! arrive on the [`nula_relay::SubscriptionHandle`] returned by the
//! per-relay subscribe path, and the pool surfaces them
//! cross-relay-deduplicated via
//! [`crate::pool::RelayPool::stream_events`].

use crate::RelayStatus;
use nula_core::RelayUrl;

/// Cross-cutting notification emitted by a [`crate::pool::RelayPool`].
///
/// Subscribe via [`crate::pool::RelayPool::notifications`]. Fan-out happens
/// at the broadcast layer: every concurrent caller gets every
/// notification, modulo lag drops on slow consumers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PoolNotification {
    /// A relay was added to the pool. Fired for the first
    /// [`crate::pool::RelayPool::add_relay`] of a given url; **not** fired
    /// when an existing relay's capabilities are merged.
    RelayAdded {
        /// The added relay's url.
        url: RelayUrl,
    },

    /// A relay was removed from the pool, either by
    /// [`crate::pool::RelayPool::remove_relay`] or by the pool being shut
    /// down. The relay's actor will already have been told to
    /// disconnect by the time this is fired.
    RelayRemoved {
        /// The removed relay's url.
        url: RelayUrl,
    },

    /// A relay's status transitioned.
    Status {
        /// The relay whose status changed.
        url: RelayUrl,
        /// The new status.
        status: RelayStatus,
    },

    /// A relay sent a free-form `["NOTICE", <msg>]` diagnostic.
    Notice {
        /// The relay that emitted the notice.
        url: RelayUrl,
        /// The notice payload.
        message: String,
    },

    /// The pool has been shut down. No further notifications will
    /// arrive on this stream.
    Shutdown,
}
