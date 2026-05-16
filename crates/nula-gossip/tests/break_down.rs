//! `break_down_filter` four-way pattern matching.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use nula_core::nips::nip65::RelayMarker;
use nula_core::{Filter, Kind, Timestamp};
use nula_gossip::BrokenDownFilters;

mod helpers;
use helpers::{
    build_dm_relays_event, build_relay_list, keys, make_gossip, relay_list_from_iter, url,
};

#[tokio::test]
async fn generic_filter_falls_through() {
    let (gossip, _db) = make_gossip();
    let filter = Filter::new().search("rust");
    let result = gossip.break_down_filter(filter.clone()).await;
    assert!(matches!(result, BrokenDownFilters::Generic(f) if f == filter));
}

#[tokio::test]
async fn authors_only_yields_per_relay_outbox() {
    let (gossip, _db) = make_gossip();
    let alice = keys(1);
    let list = relay_list_from_iter([("wss://alice-out.example/", RelayMarker::Write)]);
    gossip
        .process(
            &build_relay_list(&alice, &list, Timestamp::from_secs(100)),
            None,
        )
        .await;

    let filter = Filter::new().author(*alice.public_key());
    let result = gossip.break_down_filter(filter).await;
    let map = match result {
        BrokenDownFilters::PerRelay(map) => map,
        other => panic!("expected PerRelay, got {other:?}"),
    };
    let narrowed = map
        .get(&url("wss://alice-out.example/"))
        .expect("alice's outbox relay must be in the per-relay map");
    assert_eq!(
        narrowed.authors.as_deref(),
        Some(&[*alice.public_key()][..]),
    );
}

#[tokio::test]
async fn p_tag_only_yields_per_relay_inbox() {
    let (gossip, _db) = make_gossip();
    let bob = keys(2);
    let list = relay_list_from_iter([("wss://bob-in.example/", RelayMarker::Read)]);
    gossip
        .process(
            &build_relay_list(&bob, &list, Timestamp::from_secs(100)),
            None,
        )
        .await;

    let filter = Filter::new().pubkey(*bob.public_key());
    let result = gossip.break_down_filter(filter).await;
    let map = match result {
        BrokenDownFilters::PerRelay(map) => map,
        other => panic!("expected PerRelay, got {other:?}"),
    };
    assert!(map.contains_key(&url("wss://bob-in.example/")));
}

#[tokio::test]
async fn unknown_pubkeys_yield_orphan() {
    let (gossip, _db) = make_gossip();
    let unknown = *keys(7).public_key();
    let filter = Filter::new().author(unknown);
    let result = gossip.break_down_filter(filter.clone()).await;
    assert!(matches!(result, BrokenDownFilters::Orphan(f) if f == filter));
}

#[tokio::test]
async fn gift_wrap_kind_includes_dm_relays() {
    let (gossip, _db) = make_gossip();
    let alice = keys(3);
    // Outbox via NIP-65.
    let list = relay_list_from_iter([("wss://write.example/", RelayMarker::Write)]);
    gossip
        .process(
            &build_relay_list(&alice, &list, Timestamp::from_secs(100)),
            None,
        )
        .await;
    // DM relays via NIP-17.
    let dm_relays = vec![url("wss://dm.example/")];
    gossip
        .process(
            &build_dm_relays_event(&alice, &dm_relays, Timestamp::from_secs(101)),
            None,
        )
        .await;

    let filter = Filter::new()
        .author(*alice.public_key())
        .kind(Kind::GIFT_WRAP);
    let result = gossip.break_down_filter(filter).await;
    let map = match result {
        BrokenDownFilters::PerRelay(map) => map,
        other => panic!("expected PerRelay, got {other:?}"),
    };
    assert!(map.contains_key(&url("wss://write.example/")));
    assert!(map.contains_key(&url("wss://dm.example/")));
}

#[tokio::test]
async fn both_authors_and_p_yield_union() {
    let (gossip, _db) = make_gossip();
    let alice = keys(3);
    let bob = keys(4);

    let alice_list = relay_list_from_iter([("wss://alice-out.example/", RelayMarker::Write)]);
    let bob_list = relay_list_from_iter([("wss://bob-in.example/", RelayMarker::Read)]);
    gossip
        .process(
            &build_relay_list(&alice, &alice_list, Timestamp::from_secs(100)),
            None,
        )
        .await;
    gossip
        .process(
            &build_relay_list(&bob, &bob_list, Timestamp::from_secs(100)),
            None,
        )
        .await;

    let filter = Filter::new()
        .author(*alice.public_key())
        .pubkey(*bob.public_key());
    let result = gossip.break_down_filter(filter.clone()).await;
    let map = match result {
        BrokenDownFilters::PerRelay(map) => map,
        other => panic!("expected PerRelay, got {other:?}"),
    };
    // Union: both alice's outbox and bob's inbox carry the full
    // filter unchanged.
    let alice_filter = map
        .get(&url("wss://alice-out.example/"))
        .expect("alice's outbox relay must be in the per-relay map");
    let bob_filter = map
        .get(&url("wss://bob-in.example/"))
        .expect("bob's inbox relay must be in the per-relay map");
    assert_eq!(*alice_filter, filter);
    assert_eq!(*bob_filter, filter);
}
