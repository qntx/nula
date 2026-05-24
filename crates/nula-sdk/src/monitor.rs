//! Relay-status monitor broadcaster.
//!
//! [`Client::monitor`] returns a [`Monitor`] handle that streams a
//! filtered, status-only projection of the underlying
//! [`PoolNotification`] channel: every relay's [`RelayStatus`]
//! transition fans out as a [`MonitorNotification::StatusChanged`]
//! frame, with the relay url attached.
//!
//! The monitor is **opt-in** -- callers must invoke
//! [`crate::ClientBuilder::monitor`] (or
//! [`crate::ClientBuilder::monitor_with_capacity`]) before
//! `build()` to spin up the forwarder. Without that, `Client::monitor`
//! returns `None` and no per-relay status state is retained.
//!
//! [`Client::monitor`]: crate::Client::monitor
//! [`PoolNotification`]: nula_relay_pool::PoolNotification
//! [`RelayStatus`]: nula_relay::RelayStatus

use nula_core::types::RelayUrl;
use nula_relay::RelayStatus;
use tokio::sync::broadcast;

/// Default monitor channel capacity. Slow consumers see
/// `RecvError::Lagged` once they fall behind by this many notices.
pub(crate) const DEFAULT_MONITOR_CAPACITY: usize = 64;

/// One frame on a [`Monitor`] subscription.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MonitorNotification {
    /// A relay transitioned to a new [`RelayStatus`].
    StatusChanged {
        /// The relay url that observed the transition.
        relay_url: RelayUrl,
        /// The new status.
        status: RelayStatus,
    },
}

/// Status-only broadcast handle. Cheap to clone; every clone shares
/// the same channel so multiple subscribers can observe the same
/// transitions.
#[derive(Debug, Clone)]
pub struct Monitor {
    sender: broadcast::Sender<MonitorNotification>,
}

impl Monitor {
    /// Construct a fresh monitor with the supplied channel capacity.
    #[must_use]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let (sender, _rx) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Borrow the underlying sender so the forwarder can push
    /// notifications.
    pub(crate) const fn sender(&self) -> &broadcast::Sender<MonitorNotification> {
        &self.sender
    }

    /// Subscribe to the broadcast channel. Returns a fresh
    /// `broadcast::Receiver`; receivers observe only frames sent
    /// after the call.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<MonitorNotification> {
        self.sender.subscribe()
    }
}
