//! Event ingestion: NIP-65 / NIP-17 / hints / most-received.

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
use nula_core::{Kind, Timestamp};

mod helpers;
use helpers::{
    build_dm_relays_event, build_relay_list, build_text_with_relay_hints, keys, make_gossip,
    relay_list_from_iter, url,
};

#[tokio::test]
async fn process_nip65_populates_outbox_and_inbox() {
    let (gossip, _db) = make_gossip();
    let alice = keys(1);
    let list = relay_list_from_iter([
        ("wss://write.example/", RelayMarker::Write),
        ("wss://read.example/", RelayMarker::Read),
        ("wss://both.example/", RelayMarker::ReadWrite),
    ]);
    let event = build_relay_list(&alice, &list, Timestamp::from_secs(100));
    gossip.process(&event, None).await;

    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&url("wss://write.example/")));
    assert!(outbox.contains(&url("wss://both.example/")));
    assert!(!outbox.contains(&url("wss://read.example/")));

    let inbox = gossip.inbox_relays(alice.public_key()).await;
    assert!(inbox.contains(&url("wss://read.example/")));
    assert!(inbox.contains(&url("wss://both.example/")));
    assert!(!inbox.contains(&url("wss://write.example/")));
}

#[tokio::test]
async fn process_nip65_keeps_newest_event() {
    let (gossip, _db) = make_gossip();
    let alice = keys(1);
    let old = relay_list_from_iter([("wss://old.example/", RelayMarker::Write)]);
    let new = relay_list_from_iter([("wss://new.example/", RelayMarker::Write)]);
    gossip
        .process(
            &build_relay_list(&alice, &old, Timestamp::from_secs(50)),
            None,
        )
        .await;
    gossip
        .process(
            &build_relay_list(&alice, &new, Timestamp::from_secs(100)),
            None,
        )
        .await;

    // Out-of-order older event must not overwrite the newer state.
    let older = relay_list_from_iter([("wss://older.example/", RelayMarker::Write)]);
    gossip
        .process(
            &build_relay_list(&alice, &older, Timestamp::from_secs(20)),
            None,
        )
        .await;

    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&url("wss://new.example/")));
    assert!(!outbox.contains(&url("wss://old.example/")));
    assert!(!outbox.contains(&url("wss://older.example/")));
}

#[tokio::test]
async fn process_nip17_populates_dm_relays() {
    let (gossip, _db) = make_gossip();
    let alice = keys(2);
    let relays = vec![url("wss://dm-a.example/"), url("wss://dm-b.example/")];
    let event = build_dm_relays_event(&alice, &relays, Timestamp::from_secs(10));
    gossip.process(&event, None).await;

    let dm = gossip.dm_relays(alice.public_key()).await;
    assert!(dm.contains(&url("wss://dm-a.example/")));
    assert!(dm.contains(&url("wss://dm-b.example/")));
}

#[tokio::test]
async fn process_text_event_collects_relay_hints() {
    let (gossip, _db) = make_gossip();
    let alice = keys(3);
    let hints = vec![url("wss://hint-1.example/"), url("wss://hint-2.example/")];
    let event = build_text_with_relay_hints(&alice, &hints);
    gossip.process(&event, None).await;

    // Hints fold into outbox via the histogram bucket.
    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&url("wss://hint-1.example/")));
    assert!(outbox.contains(&url("wss://hint-2.example/")));
}

#[tokio::test]
async fn process_with_source_relay_bumps_most_received() {
    let (gossip, _db) = make_gossip();
    let alice = keys(4);
    let event = build_text_with_relay_hints(&alice, &[]);
    let observed_relay = url("wss://stats.example/");
    gossip.process(&event, Some(&observed_relay)).await;
    gossip.process(&event, Some(&observed_relay)).await;

    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&observed_relay));
}

#[tokio::test]
async fn nip65_event_persists_to_database() {
    let (gossip, db) = make_gossip();
    let alice = keys(5);
    let list = relay_list_from_iter([("wss://persist.example/", RelayMarker::Write)]);
    let event = build_relay_list(&alice, &list, Timestamp::from_secs(200));
    gossip.process(&event, None).await;

    let stored = db.event_by_id(&event.id).await.expect("db lookup");
    assert!(stored.is_some(), "kind:10002 must persist for warm_up");
    let stored = stored.expect("present");
    assert_eq!(stored.kind, Kind::RELAY_LIST);
}
