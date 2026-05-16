//! Relay-set selection algorithm.
//!
//! `outbox` and `inbox` walk the user's NIP-65 list, hint histogram,
//! and most-received histogram, taking the top-`limit` slots from
//! each bucket and returning the [`AllowedRelays`]-filtered union.
//!
//! Hints and most-received are sorted by descending count to bias
//! toward heavily-used relays. NIP-65 entries are returned in the
//! list's natural [`BTreeMap`] iteration order — that order is
//! deterministic across runs and we do not have any per-entry weight
//! to sort by.
//!
//! [`BTreeMap`]: std::collections::BTreeMap

use std::collections::{BTreeMap, HashSet};
use std::num::{NonZeroU8, NonZeroU32};

use nula_core::RelayUrl;
use nula_core::nips::nip65::RelayMarker;

use crate::options::AllowedRelays;
use crate::routes::UserRoutes;

/// Pick the top-`limit` relays from `routes`'s NIP-65 *write* bucket
/// plus the per-user histograms, filter through `policy`, and return
/// the resulting set.
pub(crate) fn outbox(
    routes: &UserRoutes,
    limits: Limits,
    policy: AllowedRelays,
) -> HashSet<RelayUrl> {
    let mut out: HashSet<RelayUrl> = HashSet::new();
    if let Some(list) = &routes.nip65 {
        for (url, marker) in list.iter() {
            if marker.is_write() {
                out.insert(url.clone());
            }
            if out.len() >= limits.write.get() as usize {
                break;
            }
        }
    }
    extend_from_histogram(&mut out, &routes.hints, limits.hint);
    extend_from_histogram(&mut out, &routes.most_received, limits.most_received);
    apply_policy(out, policy)
}

/// Pick the top-`limit` relays from `routes`'s NIP-65 *read* bucket
/// plus the per-user histograms.
pub(crate) fn inbox(
    routes: &UserRoutes,
    limits: Limits,
    policy: AllowedRelays,
) -> HashSet<RelayUrl> {
    let mut out: HashSet<RelayUrl> = HashSet::new();
    if let Some(list) = &routes.nip65 {
        for (url, marker) in list.iter() {
            if marker.is_read() || matches!(marker, RelayMarker::ReadWrite) {
                out.insert(url.clone());
            }
            if out.len() >= limits.read.get() as usize {
                break;
            }
        }
    }
    extend_from_histogram(&mut out, &routes.hints, limits.hint);
    extend_from_histogram(&mut out, &routes.most_received, limits.most_received);
    apply_policy(out, policy)
}

/// Pick the user's NIP-17 DM relays (already an ordered list per
/// spec).
pub(crate) fn dm_relays(
    routes: &UserRoutes,
    limit: NonZeroU8,
    policy: AllowedRelays,
) -> HashSet<RelayUrl> {
    let mut out: HashSet<RelayUrl> = HashSet::new();
    for url in routes.nip17.iter().take(limit.get() as usize) {
        out.insert(url.clone());
    }
    apply_policy(out, policy)
}

/// Per-bucket caps used by [`outbox`] / [`inbox`]. We pass the
/// caps as a tiny inline struct rather than ferry the whole
/// [`crate::GossipLimits`] so the function signatures stay tight.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) read: NonZeroU8,
    pub(crate) write: NonZeroU8,
    pub(crate) hint: NonZeroU8,
    pub(crate) most_received: NonZeroU8,
}

impl Limits {
    pub(crate) const fn from_gossip(g: crate::GossipLimits) -> Self {
        Self {
            read: g.read_relays_per_user,
            write: g.write_relays_per_user,
            hint: g.hint_relays_per_user,
            most_received: g.most_received_per_user,
        }
    }
}

fn extend_from_histogram(
    out: &mut HashSet<RelayUrl>,
    histogram: &BTreeMap<RelayUrl, NonZeroU32>,
    limit: NonZeroU8,
) {
    if histogram.is_empty() {
        return;
    }
    // Collect into a Vec so we can sort by descending count without
    // disturbing the BTreeMap.
    let mut ranked: Vec<(&RelayUrl, NonZeroU32)> =
        histogram.iter().map(|(url, n)| (url, *n)).collect();
    ranked.sort_by(|a, b| b.1.get().cmp(&a.1.get()).then_with(|| a.0.cmp(b.0)));
    for (url, _) in ranked.into_iter().take(limit.get() as usize) {
        out.insert(url.clone());
    }
}

fn apply_policy(set: HashSet<RelayUrl>, policy: AllowedRelays) -> HashSet<RelayUrl> {
    set.into_iter()
        .filter(|url| policy.is_allowed(url))
        .collect()
}

#[cfg(test)]
mod tests {
    use nula_core::nips::nip65::{RelayList, RelayMarker};

    use super::*;

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).expect("hardcoded test url")
    }

    fn limits() -> Limits {
        Limits::from_gossip(crate::GossipLimits::default())
    }

    fn routes_with_nip65() -> UserRoutes {
        let mut list = RelayList::new();
        list.insert(url("wss://write.example/"), RelayMarker::Write);
        list.insert(url("wss://read.example/"), RelayMarker::Read);
        list.insert(url("wss://both.example/"), RelayMarker::ReadWrite);
        UserRoutes {
            nip65: Some(list),
            ..UserRoutes::default()
        }
    }

    #[test]
    fn outbox_collects_write_and_readwrite() {
        let routes = routes_with_nip65();
        let out = outbox(&routes, limits(), AllowedRelays::default());
        assert!(out.contains(&url("wss://write.example/")));
        assert!(out.contains(&url("wss://both.example/")));
        assert!(!out.contains(&url("wss://read.example/")));
    }

    #[test]
    fn inbox_collects_read_and_readwrite() {
        let routes = routes_with_nip65();
        let in_ = inbox(&routes, limits(), AllowedRelays::default());
        assert!(in_.contains(&url("wss://read.example/")));
        assert!(in_.contains(&url("wss://both.example/")));
        assert!(!in_.contains(&url("wss://write.example/")));
    }

    #[test]
    fn outbox_includes_hints_and_most_received() {
        let mut routes = routes_with_nip65();
        routes.bump_hint(url("wss://hint.example/"));
        routes.bump_most_received(url("wss://stats.example/"));

        let out = outbox(&routes, limits(), AllowedRelays::default());
        assert!(out.contains(&url("wss://hint.example/")));
        assert!(out.contains(&url("wss://stats.example/")));
    }

    #[test]
    fn dm_relays_is_ordered_take() {
        let routes = UserRoutes {
            nip17: vec![
                url("wss://a.example/"),
                url("wss://b.example/"),
                url("wss://c.example/"),
                url("wss://d.example/"),
            ],
            ..UserRoutes::default()
        };
        let limit = NonZeroU8::new(2).expect("2 != 0");
        let result = dm_relays(&routes, limit, AllowedRelays::default());
        assert_eq!(result.len(), 2);
        assert!(result.contains(&url("wss://a.example/")));
        assert!(result.contains(&url("wss://b.example/")));
    }

    fn routes_with_local_and_public() -> UserRoutes {
        let mut list = RelayList::new();
        list.insert(url("wss://public.example/"), RelayMarker::Write);
        list.insert(url("ws://127.0.0.1:7777"), RelayMarker::Write);
        UserRoutes {
            nip65: Some(list),
            ..UserRoutes::default()
        }
    }

    #[test]
    fn policy_filters_local_relays_by_default() {
        let routes = routes_with_local_and_public();
        let out = outbox(&routes, limits(), AllowedRelays::default());
        assert!(out.contains(&url("wss://public.example/")));
        assert!(!out.contains(&url("ws://127.0.0.1:7777")));
    }

    #[test]
    fn permissive_policy_keeps_everything() {
        let routes = routes_with_local_and_public();
        let out = outbox(&routes, limits(), AllowedRelays::permissive());
        assert!(out.contains(&url("wss://public.example/")));
        assert!(out.contains(&url("ws://127.0.0.1:7777")));
    }

    #[test]
    fn histogram_sort_prefers_higher_counts() {
        let mut routes = UserRoutes::default();
        let high = url("wss://high.example/");
        let med = url("wss://med.example/");
        let low = url("wss://low.example/");
        for _ in 0..5 {
            routes.bump_hint(high.clone());
        }
        for _ in 0..3 {
            routes.bump_hint(med.clone());
        }
        routes.bump_hint(low.clone());

        let mut limits = limits();
        limits.hint = NonZeroU8::new(2).expect("2 != 0");
        let out = outbox(&routes, limits, AllowedRelays::default());
        // Only the top two hints survive even though three are
        // populated.
        assert!(out.contains(&high));
        assert!(out.contains(&med));
        assert!(!out.contains(&low));
    }
}
