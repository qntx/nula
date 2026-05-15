//! Lock-free per-relay counters surfaced via [`crate::Relay::stats`].
//!
//! Every counter uses `AtomicU64` with `Relaxed` ordering — these
//! values are observability data, not control-flow inputs, so the
//! cheapest ordering is correct.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Cumulative counters for one relay handle.
///
/// Read via [`crate::Relay::stats`]; the actor mutates them
/// internally on every transition.
#[derive(Debug, Default)]
pub struct RelayStats {
    pub(crate) connect_attempts: AtomicU64,
    pub(crate) connect_successes: AtomicU64,
    pub(crate) bytes_sent: AtomicU64,
    pub(crate) bytes_received: AtomicU64,
    pub(crate) events_published: AtomicU64,
    pub(crate) events_received: AtomicU64,
    /// Last successful handshake duration in nanoseconds. `0` when
    /// no successful handshake has happened yet.
    pub(crate) last_handshake_nanos: AtomicU64,
}

impl RelayStats {
    /// Number of times the actor has attempted a connect (successful
    /// or failed). One per `connect_async` invocation.
    #[must_use]
    pub fn connect_attempts(&self) -> u64 {
        self.connect_attempts.load(Ordering::Relaxed)
    }

    /// Number of successful handshakes.
    #[must_use]
    pub fn connect_successes(&self) -> u64 {
        self.connect_successes.load(Ordering::Relaxed)
    }

    /// Total bytes sent on the wire (UTF-8 byte length of every text
    /// frame plus binary payload bytes).
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Total bytes received.
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Total `EVENT` frames the caller submitted via
    /// [`crate::Relay::publish`] (regardless of whether the relay
    /// accepted them).
    #[must_use]
    pub fn events_published(&self) -> u64 {
        self.events_published.load(Ordering::Relaxed)
    }

    /// Total `EVENT` frames received from the relay (across every
    /// subscription).
    #[must_use]
    pub fn events_received(&self) -> u64 {
        self.events_received.load(Ordering::Relaxed)
    }

    /// Duration of the most recent successful handshake. `None` if
    /// no successful handshake has happened on this relay handle.
    #[must_use]
    pub fn last_handshake(&self) -> Option<Duration> {
        let nanos = self.last_handshake_nanos.load(Ordering::Relaxed);
        if nanos == 0 {
            None
        } else {
            Some(Duration::from_nanos(nanos))
        }
    }
}
