//! Connection status for a [`crate::Relay`] and the lock-free
//! atomic helper used by the inner actor.
//!
//! The five states are deliberately fewer than rust-nostr's
//! upstream model. `Banned`, `Sleeping`, and `Pending` are concerns
//! of higher layers (relay-pool, idle-energy management) and have no
//! place inside a single-relay state machine.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

/// Where the relay's connection currently stands.
///
/// State graph:
///
/// ```text
/// Initialized ──► Connecting ──► Connected ──► Disconnected ──► Connecting ─►…
///                     │                              │
///                     └──────────────────────────────┴──► Terminated (terminal)
/// ```
///
/// `Disconnected` is transient — the actor reconnects from it under
/// the configured [`crate::ReconnectPolicy`]. `Terminated` is
/// terminal: it is reached when the caller explicitly shuts the
/// relay down or when reconnection is disabled and the connection
/// drops.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayStatus {
    /// Relay handle has been constructed but no connect attempt has
    /// been made yet.
    Initialized = 0,
    /// A connect attempt is in flight.
    Connecting = 1,
    /// The handshake completed and the socket is currently open.
    Connected = 2,
    /// The socket dropped; the actor is sleeping until the
    /// reconnect timer fires.
    Disconnected = 3,
    /// The actor has been shut down. No further state transitions
    /// are possible.
    Terminated = 4,
}

impl RelayStatus {
    /// `true` when the relay can serve subscribe/publish calls right
    /// now. Equivalent to `self == Connected`.
    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }

    /// `true` when the actor is in a terminal state and will not
    /// recover.
    #[must_use]
    pub const fn is_terminated(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

impl fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Initialized => "initialized",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Terminated => "terminated",
        })
    }
}

/// Lock-free [`RelayStatus`] cell shared between the actor task and
/// public reader API.
///
/// The encoding stores the variant's discriminant in an [`AtomicU8`]
/// so reads from external observers (e.g. `Relay::status()`) cost a
/// single relaxed load.
#[derive(Debug)]
pub(crate) struct AtomicRelayStatus(AtomicU8);

impl AtomicRelayStatus {
    pub(crate) const fn new(initial: RelayStatus) -> Self {
        Self(AtomicU8::new(initial as u8))
    }

    pub(crate) fn load(&self) -> RelayStatus {
        match self.0.load(Ordering::Acquire) {
            0 => RelayStatus::Initialized,
            1 => RelayStatus::Connecting,
            2 => RelayStatus::Connected,
            3 => RelayStatus::Disconnected,
            4 => RelayStatus::Terminated,
            // SAFETY: the only writer is `set`, which always stores
            // a valid discriminant. An unknown value would indicate
            // memory corruption; aborting via `unreachable!` is the
            // correct response.
            other => unreachable!("invalid RelayStatus discriminant: {other}"),
        }
    }

    pub(crate) fn set(&self, status: RelayStatus) {
        self.0.store(status as u8, Ordering::Release);
    }
}

impl Default for AtomicRelayStatus {
    fn default() -> Self {
        Self::new(RelayStatus::Initialized)
    }
}
