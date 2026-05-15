//! Per-relay protocol-wide notification stream.
//!
//! Carried over an unbounded tokio mpsc channel: **single consumer,
//! lossless**. Subscription events do **not** flow through this
//! channel — they are routed to the subscription's
//! [`crate::SubscriptionHandle`] for ergonomic per-call consumption.
//! What lives here is the cross-cutting protocol signal a caller
//! cannot infer from a single subscription:
//!
//! - status transitions (Connecting → Connected → …),
//! - `NOTICE` frames (free-form relay diagnostics),
//! - NIP-42 AUTH challenges (when the `nip42` feature is on),
//! - the actor-shutdown sentinel.
//!
//! The mpsc choice is deliberate. A broadcast channel would drop
//! frames on a slow consumer; we never want to silently lose a
//! NOTICE or AUTH challenge. Callers that need fan-out wrap the
//! receiver in their own broadcast / watch on top.

use crate::status::RelayStatus;

/// Cross-cutting notification emitted by a [`crate::Relay`].
///
/// Stream this over [`crate::Relay::notifications`]; subscription
/// events are *not* in here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RelayNotification {
    /// The relay's [`RelayStatus`] changed.
    Status(RelayStatus),

    /// The relay sent a free-form `["NOTICE", <message>]` diagnostic.
    Notice(String),

    /// The relay sent a NIP-42 `["AUTH", <challenge>]` frame. The
    /// caller is expected to respond with a signed challenge
    /// event via [`crate::Relay::authenticate`] (or the
    /// `nip42::AuthHandler` hook if installed).
    #[cfg(feature = "nip42")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip42")))]
    AuthChallenge {
        /// The challenge string the relay supplied.
        challenge: String,
    },

    /// The actor task has terminated and no further notifications
    /// will arrive on this stream.
    Shutdown,
}
