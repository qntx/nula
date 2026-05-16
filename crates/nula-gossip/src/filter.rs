//! Filter break-down: turn a single user-facing [`Filter`] into the
//! per-relay sub-filters [`crate::Gossip::break_down_filter`]
//! returns.
//!
//! Algorithm (mirrors `rust-nostr`'s gossip resolver, but emits a
//! tri-state result instead of a duo):
//!
//! | `filter.authors` | `#p` set | NIP-17? | branch                         |
//! |------------------|----------|---------|--------------------------------|
//! | `Some`           | `None`   | maybe   | `PerRelay` from outbox + dm    |
//! | `None`           | `Some`   | maybe   | `PerRelay` from inbox + dm     |
//! | `Some`           | `Some`   | maybe   | `PerRelay` from union          |
//! | `None`           | `None`   | —       | `Generic` (caller picks pool)  |
//!
//! Within each branch the per-pubkey relay sets are computed by
//! [`crate::selection`]; if the union of per-pubkey relays is empty
//! the result is `Orphan(filter)` instead.

use std::collections::{BTreeSet, HashMap, HashSet};

use nula_core::event::Alphabet;
use nula_core::event::SingleLetterTag;
use nula_core::{Filter, Kind, PublicKey, RelayUrl};

use crate::inner::Inner;
use crate::selection::{self, Limits};

/// Outcome of [`crate::Gossip::break_down_filter`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokenDownFilters {
    /// One sub-filter per relay; each sub-filter is the original
    /// filter narrowed to the public keys served by the relay.
    PerRelay(HashMap<RelayUrl, Filter>),

    /// Filter targeted public keys (via `authors` or `#p`) but no
    /// stored route covers any of them. Caller may still send the
    /// filter to a generic discovery pool, but routing alone cannot
    /// pick relays.
    Orphan(Filter),

    /// Filter has neither `authors` nor `#p` (e.g. a search-only
    /// filter). The caller should run it against a generic READ
    /// pool — gossip cannot help.
    Generic(Filter),
}

/// Break a single filter into per-relay sub-filters.
pub(crate) async fn break_down(inner: &Inner, filter: Filter) -> BrokenDownFilters {
    let p_tag = SingleLetterTag::lowercase(Alphabet::P);
    let authors: Option<BTreeSet<PublicKey>> =
        filter.authors.as_ref().map(|v| v.iter().copied().collect());
    let p_pubkeys: Option<BTreeSet<PublicKey>> = filter.generic_tags.get(&p_tag).map(|values| {
        values
            .iter()
            .filter_map(|s| PublicKey::parse(s).ok())
            .collect()
    });

    let needs_dm = pattern_needs_dm(&filter);

    match (authors, p_pubkeys) {
        (Some(authors), None) => {
            let mut per_relay: HashMap<RelayUrl, BTreeSet<PublicKey>> = HashMap::new();
            collect_outbox(inner, &authors, needs_dm, &mut per_relay).await;
            if per_relay.is_empty() {
                return BrokenDownFilters::Orphan(filter);
            }
            BrokenDownFilters::PerRelay(narrow_authors(&filter, per_relay))
        }
        (None, Some(p_set)) => {
            let mut per_relay: HashMap<RelayUrl, BTreeSet<PublicKey>> = HashMap::new();
            collect_inbox(inner, &p_set, needs_dm, &mut per_relay).await;
            if per_relay.is_empty() {
                return BrokenDownFilters::Orphan(filter);
            }
            BrokenDownFilters::PerRelay(narrow_p_tags(&filter, per_relay, p_tag))
        }
        (Some(authors), Some(p_set)) => {
            let union: BTreeSet<PublicKey> = authors.union(&p_set).copied().collect();
            let mut relays: BTreeSet<RelayUrl> = BTreeSet::new();
            collect_union_relays(inner, &union, needs_dm, &mut relays).await;
            if relays.is_empty() {
                return BrokenDownFilters::Orphan(filter);
            }
            // Both author and p slots are populated: every relay
            // gets the full filter. We cannot meaningfully split
            // either side without changing the user's intent.
            let map = relays
                .into_iter()
                .map(|url| (url, filter.clone()))
                .collect();
            BrokenDownFilters::PerRelay(map)
        }
        (None, None) => BrokenDownFilters::Generic(filter),
    }
}

/// NIP-17 trigger: filter explicitly asks for gift wraps, or it has
/// `#p` but does not pin a kind set (so any inbound DM kind could
/// satisfy it).
fn pattern_needs_dm(filter: &Filter) -> bool {
    let p_present = filter
        .generic_tags
        .get(&SingleLetterTag::lowercase(Alphabet::P))
        .is_some_and(|v| !v.is_empty());
    match (&filter.kinds, p_present) {
        (Some(kinds), _) if kinds.contains(&Kind::GIFT_WRAP) => true,
        (Some(kinds), _) if kinds.is_empty() && p_present => true,
        (None, true) => true,
        _ => false,
    }
}

/// Direction of the per-user routing collection.
#[derive(Clone, Copy)]
enum Direction {
    Outbox,
    Inbox,
}

async fn collect_outbox(
    inner: &Inner,
    authors: &BTreeSet<PublicKey>,
    needs_dm: bool,
    out: &mut HashMap<RelayUrl, BTreeSet<PublicKey>>,
) {
    collect_directional(inner, authors, needs_dm, out, Direction::Outbox).await;
}

async fn collect_inbox(
    inner: &Inner,
    targets: &BTreeSet<PublicKey>,
    needs_dm: bool,
    out: &mut HashMap<RelayUrl, BTreeSet<PublicKey>>,
) {
    collect_directional(inner, targets, needs_dm, out, Direction::Inbox).await;
}

async fn collect_directional(
    inner: &Inner,
    keys: &BTreeSet<PublicKey>,
    needs_dm: bool,
    out: &mut HashMap<RelayUrl, BTreeSet<PublicKey>>,
    direction: Direction,
) {
    let limits = Limits::from_gossip(inner.options.limits);
    let allowed = inner.options.allowed;
    let dm_limit = inner.options.limits.dm_relays_per_user;
    let snapshot: Vec<(PublicKey, HashSet<RelayUrl>)> = {
        let routes = inner.routes.read().await;
        keys.iter()
            .filter_map(|pk| routes.get(pk).map(|r| (*pk, r)))
            .map(|(pk, user_routes)| {
                let mut relays = match direction {
                    Direction::Outbox => selection::outbox(user_routes, limits, allowed),
                    Direction::Inbox => selection::inbox(user_routes, limits, allowed),
                };
                if needs_dm {
                    relays.extend(selection::dm_relays(user_routes, dm_limit, allowed));
                }
                (pk, relays)
            })
            .collect()
    };
    for (pk, relays) in snapshot {
        for url in relays {
            out.entry(url).or_default().insert(pk);
        }
    }
}

async fn collect_union_relays(
    inner: &Inner,
    targets: &BTreeSet<PublicKey>,
    needs_dm: bool,
    out: &mut BTreeSet<RelayUrl>,
) {
    let limits = Limits::from_gossip(inner.options.limits);
    let allowed = inner.options.allowed;
    let dm_limit = inner.options.limits.dm_relays_per_user;
    let routes = inner.routes.read().await;
    let mut acc: Vec<RelayUrl> = Vec::new();
    for pk in targets {
        let Some(user_routes) = routes.get(pk) else {
            continue;
        };
        acc.extend(selection::outbox(user_routes, limits, allowed));
        acc.extend(selection::inbox(user_routes, limits, allowed));
        if needs_dm {
            acc.extend(selection::dm_relays(user_routes, dm_limit, allowed));
        }
    }
    drop(routes);
    out.extend(acc);
}

fn narrow_authors(
    filter: &Filter,
    per_relay: HashMap<RelayUrl, BTreeSet<PublicKey>>,
) -> HashMap<RelayUrl, Filter> {
    per_relay
        .into_iter()
        .map(|(url, pks)| {
            let mut narrowed = filter.clone();
            narrowed.authors = Some(pks.into_iter().collect());
            (url, narrowed)
        })
        .collect()
}

fn narrow_p_tags(
    filter: &Filter,
    per_relay: HashMap<RelayUrl, BTreeSet<PublicKey>>,
    p_tag: SingleLetterTag,
) -> HashMap<RelayUrl, Filter> {
    per_relay
        .into_iter()
        .map(|(url, pks)| {
            let mut narrowed = filter.clone();
            narrowed
                .generic_tags
                .insert(p_tag, pks.into_iter().map(PublicKey::to_hex).collect());
            (url, narrowed)
        })
        .collect()
}
