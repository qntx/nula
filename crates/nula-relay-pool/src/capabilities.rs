//! Per-relay capability bitflags used to scope fan-out operations.
//!
//! A relay is added with one or more capabilities; each pool
//! operation picks the relays whose capability set overlaps with the
//! operation's required capability. For example,
//! [`crate::RelayPool::send_event`] picks relays with
//! [`RelayCapabilities::WRITE`], while a future inbox-aware fetch
//! would pick relays with [`RelayCapabilities::DISCOVERY`].
//!
//! Capabilities can be mutated at runtime via
//! [`AtomicRelayCapabilities`] without dropping the relay's actor; the
//! pool's `RwLock` guards the relay map, not the capability bits.

use std::sync::atomic::{AtomicU8, Ordering};

use bitflags::bitflags;

bitflags! {
    /// Roles a relay can play within the pool.
    ///
    /// `READ | WRITE` is the most common combination for a
    /// general-purpose relay. `DISCOVERY` marks a relay listed in a
    /// peer's NIP-65 inbox/outbox event so the pool knows it should
    /// be queried when looking up that peer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RelayCapabilities: u8 {
        /// Pull events out (subscribe / stream).
        const READ      = 0b0000_0001;
        /// Push events in (publish).
        const WRITE     = 0b0000_0010;
        /// Listed in a peer's NIP-65 outbox/inbox metadata.
        const DISCOVERY = 0b0000_0100;
        /// Relay added explicitly for NIP-65 gossip routing
        /// (outbox/inbox/dm relay aggregation). Distinguishes a
        /// user-pinned gossip relay from a relay merely seen on a
        /// peer's published NIP-65 list (`DISCOVERY`).
        const GOSSIP    = 0b0000_1000;
    }
}

impl Default for RelayCapabilities {
    /// `READ | WRITE` — what most callers add a relay for.
    fn default() -> Self {
        Self::READ | Self::WRITE
    }
}

impl RelayCapabilities {
    /// Returns `true` when at least one bit in `other` is also set
    /// here. Differs from [`Self::contains`], which requires every
    /// bit of `other` to be set.
    #[must_use]
    pub const fn has_any(self, other: Self) -> bool {
        self.intersects(other)
    }
}

/// Atomic wrapper around [`RelayCapabilities`] for runtime mutation.
#[derive(Debug)]
pub struct AtomicRelayCapabilities {
    bits: AtomicU8,
}

impl AtomicRelayCapabilities {
    /// Construct with an initial capability set.
    #[must_use]
    pub const fn new(initial: RelayCapabilities) -> Self {
        Self {
            bits: AtomicU8::new(initial.bits()),
        }
    }

    /// Read the current capability set.
    #[must_use]
    pub fn load(&self) -> RelayCapabilities {
        // `from_bits_truncate` discards unknown bits, which keeps us
        // forward-compatible if a future minor adds a flag and an
        // older binary observes the new bit.
        RelayCapabilities::from_bits_truncate(self.bits.load(Ordering::Acquire))
    }

    /// Replace the capability set with `new`. Returns the previous
    /// value.
    pub fn store(&self, new: RelayCapabilities) -> RelayCapabilities {
        RelayCapabilities::from_bits_truncate(self.bits.swap(new.bits(), Ordering::AcqRel))
    }

    /// Set every bit in `add` in addition to the current set.
    pub fn add(&self, add: RelayCapabilities) {
        self.bits.fetch_or(add.bits(), Ordering::AcqRel);
    }

    /// Clear every bit in `remove` from the current set.
    pub fn remove(&self, remove: RelayCapabilities) {
        self.bits.fetch_and(!remove.bits(), Ordering::AcqRel);
    }
}

impl Default for AtomicRelayCapabilities {
    fn default() -> Self {
        Self::new(RelayCapabilities::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_read_write() {
        let caps = RelayCapabilities::default();
        assert!(caps.contains(RelayCapabilities::READ));
        assert!(caps.contains(RelayCapabilities::WRITE));
        assert!(!caps.contains(RelayCapabilities::DISCOVERY));
    }

    #[test]
    fn has_any_overlaps() {
        let caps = RelayCapabilities::READ | RelayCapabilities::DISCOVERY;
        assert!(caps.has_any(RelayCapabilities::READ));
        assert!(caps.has_any(RelayCapabilities::WRITE | RelayCapabilities::DISCOVERY));
        assert!(!caps.has_any(RelayCapabilities::WRITE));
    }

    #[test]
    fn atomic_round_trip() {
        let atomic = AtomicRelayCapabilities::new(RelayCapabilities::READ);
        assert_eq!(atomic.load(), RelayCapabilities::READ);

        atomic.add(RelayCapabilities::WRITE);
        assert_eq!(
            atomic.load(),
            RelayCapabilities::READ | RelayCapabilities::WRITE
        );

        atomic.remove(RelayCapabilities::READ);
        assert_eq!(atomic.load(), RelayCapabilities::WRITE);

        let prev = atomic.store(RelayCapabilities::DISCOVERY);
        assert_eq!(prev, RelayCapabilities::WRITE);
        assert_eq!(atomic.load(), RelayCapabilities::DISCOVERY);
    }
}
