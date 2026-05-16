//! Freshness / outdated-key bookkeeping.
//!
//! The gossip layer treats a stored NIP-65 / NIP-17 list as one of
//! three states:
//!
//! - **Missing** — no list event has ever been observed, so we have
//!   nothing to serve out of the cache.
//! - **Updated** — the stored event is younger than
//!   [`crate::GossipOptions::list_ttl`].
//! - **Outdated** — we have a list, but it is older than the TTL and
//!   the background refresher is allowed to re-pull it.

use std::cmp::Ordering;

use nula_core::PublicKey;
use nula_core::types::Timestamp;

/// Tri-state freshness verdict for a stored list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyStatus {
    /// The cache has no event for this `(user, list_kind)` pair.
    Missing,
    /// The stored event is younger than the configured TTL.
    Updated,
    /// The stored event has crossed the TTL threshold.
    Outdated {
        /// Wire timestamp of the still-current event in the cache.
        observed_at: Timestamp,
    },
}

impl PublicKeyStatus {
    /// `true` when no event is stored.
    #[must_use]
    pub const fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }

    /// `true` when the cached event is still fresh.
    #[must_use]
    pub const fn is_updated(self) -> bool {
        matches!(self, Self::Updated)
    }

    /// `true` when the cached event has expired.
    #[must_use]
    pub const fn is_outdated(self) -> bool {
        matches!(self, Self::Outdated { .. })
    }
}

/// A `(public_key, observed_at)` pair returned by
/// [`crate::Gossip::outdated`]. Sorted by ascending timestamp so the
/// caller can refresh the staleest keys first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutdatedKey {
    /// User whose list is past TTL.
    pub public_key: PublicKey,
    /// `created_at` of the most recent event the cache holds. `None`
    /// signals "we have never seen any event for this user".
    pub observed_at: Option<Timestamp>,
}

impl OutdatedKey {
    /// Construct an `OutdatedKey` straight from raw fields.
    #[must_use]
    pub const fn new(public_key: PublicKey, observed_at: Option<Timestamp>) -> Self {
        Self {
            public_key,
            observed_at,
        }
    }
}

impl PartialOrd for OutdatedKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OutdatedKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Missing keys (`None` timestamp) sort first; among Some
        // timestamps the older event sorts first.
        match (self.observed_at, other.observed_at) {
            (None, None) => self.public_key.cmp(&other.public_key),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a
                .cmp(&b)
                .then_with(|| self.public_key.cmp(&other.public_key)),
        }
    }
}

#[cfg(test)]
mod tests {
    use nula_core::Keys;

    use super::*;

    fn pk(seed: u8) -> PublicKey {
        let mut hex = [b'0'; 64];
        hex[63] = b'0' + seed;
        let s = std::str::from_utf8(&hex).expect("ascii hex");
        *Keys::parse(s).expect("valid hex").public_key()
    }

    #[test]
    fn status_helpers() {
        assert!(PublicKeyStatus::Missing.is_missing());
        assert!(PublicKeyStatus::Updated.is_updated());
        assert!(
            PublicKeyStatus::Outdated {
                observed_at: Timestamp::from_secs(0)
            }
            .is_outdated()
        );
    }

    #[test]
    fn outdated_key_orders_missing_first_then_oldest() {
        let mut keys = [
            OutdatedKey::new(pk(1), Some(Timestamp::from_secs(100))),
            OutdatedKey::new(pk(2), None),
            OutdatedKey::new(pk(3), Some(Timestamp::from_secs(50))),
        ];
        keys.sort();
        let mut iter = keys.into_iter();
        let first = iter.next().expect("3 keys");
        let second = iter.next().expect("3 keys");
        let third = iter.next().expect("3 keys");
        assert!(first.observed_at.is_none(), "missing key sorts first");
        assert_eq!(second.observed_at, Some(Timestamp::from_secs(50)));
        assert_eq!(third.observed_at, Some(Timestamp::from_secs(100)));
    }
}
