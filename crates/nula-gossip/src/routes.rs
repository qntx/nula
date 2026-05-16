//! Per-user route aggregation.
//!
//! [`UserRoutes`] is the in-memory shape of one user's routing
//! signals. The fields are deliberately public so consumers can
//! inspect the routing graph in tests and observability code without
//! hitting the public selection API every time.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use nula_core::RelayUrl;
use nula_core::nips::nip65::RelayList;
use nula_core::types::Timestamp;

/// Aggregated routing signals for a single Nostr user.
///
/// Updated by [`crate::Gossip::process`] every time an event flows
/// in (NIP-65, NIP-17, or any other event carrying `r` tag hints).
#[derive(Debug, Clone, Default)]
pub struct UserRoutes {
    /// NIP-65 relay list (read / write / both markers).
    pub nip65: Option<RelayList>,
    /// `created_at` of the NIP-65 event. Used for TTL freshness.
    pub nip65_event_at: Option<Timestamp>,
    /// Last time the gossip layer attempted to fetch the NIP-65
    /// list, regardless of whether it returned anything. Used by
    /// [`crate::GossipOptions::min_fetch_interval`] to debounce.
    pub nip65_fetched_at: Option<Timestamp>,

    /// NIP-17 DM relay list.
    pub nip17: Vec<RelayUrl>,
    /// `created_at` of the NIP-17 event.
    pub nip17_event_at: Option<Timestamp>,
    /// Last NIP-17 fetch attempt timestamp.
    pub nip17_fetched_at: Option<Timestamp>,

    /// Inline `r` tag hints aggregated across all events authored by
    /// this user. Counts how many events advertised each relay.
    pub hints: BTreeMap<RelayUrl, NonZeroU32>,
    /// Per-relay event histogram for this user. Counts how many
    /// events the relay actually delivered.
    pub most_received: BTreeMap<RelayUrl, NonZeroU32>,
}

impl UserRoutes {
    /// Returns the timestamp of the stored NIP-65 / NIP-17 event,
    /// whichever the caller asked for.
    #[must_use]
    pub const fn list_event_at(&self, kind: crate::ListKind) -> Option<Timestamp> {
        match kind {
            crate::ListKind::Nip65 => self.nip65_event_at,
            crate::ListKind::Nip17 => self.nip17_event_at,
        }
    }

    /// Returns the last fetch-attempt timestamp for the requested
    /// list kind.
    #[must_use]
    pub const fn list_fetched_at(&self, kind: crate::ListKind) -> Option<Timestamp> {
        match kind {
            crate::ListKind::Nip65 => self.nip65_fetched_at,
            crate::ListKind::Nip17 => self.nip17_fetched_at,
        }
    }

    /// Increment the hint counter for `relay` (saturating at
    /// `u32::MAX`).
    pub fn bump_hint(&mut self, relay: RelayUrl) {
        bump(&mut self.hints, relay);
    }

    /// Increment the most-received counter for `relay` (saturating
    /// at `u32::MAX`).
    pub fn bump_most_received(&mut self, relay: RelayUrl) {
        bump(&mut self.most_received, relay);
    }
}

fn bump(map: &mut BTreeMap<RelayUrl, NonZeroU32>, relay: RelayUrl) {
    // Saturate at u32::MAX so a relay that returns billions of
    // events does not overflow the counter. The `unwrap` on the
    // saturating_add is unreachable because saturating_add never
    // returns 0 starting from a non-zero value.
    let one = const { NonZeroU32::new(1).expect("1 is non-zero") };
    map.entry(relay)
        .and_modify(|n| {
            if let Some(next) = NonZeroU32::new(n.get().saturating_add(1)) {
                *n = next;
            }
        })
        .or_insert(one);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).expect("hardcoded test url")
    }

    #[test]
    fn bump_starts_at_one() {
        let mut routes = UserRoutes::default();
        routes.bump_hint(url("wss://relay.example/"));
        assert_eq!(
            routes.hints.get(&url("wss://relay.example/")).copied(),
            NonZeroU32::new(1)
        );
    }

    #[test]
    fn bump_increments_existing_entry() {
        let mut routes = UserRoutes::default();
        let url = url("wss://relay.example/");
        routes.bump_most_received(url.clone());
        routes.bump_most_received(url.clone());
        routes.bump_most_received(url.clone());
        assert_eq!(routes.most_received.get(&url).copied(), NonZeroU32::new(3));
    }

    #[test]
    fn list_event_at_dispatches_per_kind() {
        let routes = UserRoutes {
            nip65_event_at: Some(Timestamp::from_secs(7)),
            nip17_event_at: Some(Timestamp::from_secs(11)),
            ..UserRoutes::default()
        };
        assert_eq!(
            routes.list_event_at(crate::ListKind::Nip65),
            Some(Timestamp::from_secs(7))
        );
        assert_eq!(
            routes.list_event_at(crate::ListKind::Nip17),
            Some(Timestamp::from_secs(11))
        );
    }
}
