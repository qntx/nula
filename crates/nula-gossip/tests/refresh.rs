//! End-to-end refresh path: pull a NIP-65 / NIP-17 event from a
//! `MockRelay` and verify the gossip cache picks it up.

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

use std::sync::Arc;
use std::time::Duration;

use nula_core::Timestamp;
use nula_core::nips::nip65::RelayMarker;
use nula_gossip::ListKind;
use nula_relay::pool::{RelayCapabilities, RelayPool};
use nula_relay::server::MockRelayBuilder;
use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;

mod helpers;
use helpers::{build_relay_list, keys, make_gossip, relay_list_from_iter, url};

#[tokio::test]
async fn refresh_pulls_nip65_event_from_pool() {
    // Stand up a single MockRelay and seed it with Alice's NIP-65
    // event by publishing through the pool.
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let server_url = server.url().clone();

    let pool_db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let pool = RelayPool::builder()
        .database(pool_db)
        .build()
        .expect("database supplied to builder");
    pool.add_relay(
        server_url.clone(),
        RelayCapabilities::READ | RelayCapabilities::WRITE,
    )
    .await
    .expect("add_relay");
    pool.try_connect(Duration::from_secs(2)).await;

    let alice = keys(1);
    let list = relay_list_from_iter([
        ("wss://write.example/", RelayMarker::Write),
        ("wss://read.example/", RelayMarker::Read),
    ]);
    let event = build_relay_list(&alice, &list, Timestamp::from_secs(1_000));
    pool.send_event_to([server_url.clone()], event)
        .await
        .expect("publish");

    // Now build a *separate* gossip instance with empty cache and
    // refresh through the same pool.
    let (gossip, _db) = make_gossip();
    gossip
        .refresh(
            &pool,
            alice.public_key(),
            ListKind::Nip65,
            [server_url.clone()],
            Duration::from_secs(3),
        )
        .await
        .expect("refresh");

    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&url("wss://write.example/")));
}

#[tokio::test]
async fn refresh_with_no_discovery_relays_errors() {
    let (gossip, _db) = make_gossip();
    let pool_db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let pool = RelayPool::builder()
        .database(pool_db)
        .build()
        .expect("database supplied to builder");
    let alice = keys(2);
    let err = gossip
        .refresh(
            &pool,
            alice.public_key(),
            ListKind::Nip65,
            std::iter::empty(),
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected NoDiscoveryRelays");
    assert!(matches!(err, nula_gossip::Error::NoDiscoveryRelays));
}

#[tokio::test]
async fn warm_up_rehydrates_from_database() {
    // Seed the database with Alice's NIP-65 event directly.
    let alice = keys(3);
    let list = relay_list_from_iter([("wss://warm.example/", RelayMarker::Write)]);
    let event = build_relay_list(&alice, &list, Timestamp::from_secs(2_000));

    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    db.save_event(&event).await.expect("seed db");

    let gossip = nula_gossip::Gossip::builder()
        .database(Arc::clone(&db))
        .build()
        .expect("database supplied to builder");
    gossip
        .warm_up([*alice.public_key()])
        .await
        .expect("warm_up");

    let outbox = gossip.outbox_relays(alice.public_key()).await;
    assert!(outbox.contains(&url("wss://warm.example/")));
}
