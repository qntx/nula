//! Gossip + persistent storage integration: ingest NIP-65, drop the
//! handle, rebuild, and verify `warm_up` recovers the route table.
//!
//! `nula-gossip` does not own its own persistence layer -- it is
//! delegated to whatever `nula_storage::NostrDatabase` the builder
//! was constructed with. This test exercises that contract end-to-
//! end with the `redb` backend, the one production apps would pick for
//! survive-a-reboot behaviour.

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

use nula_core::nips::nip65::RelayMarker;
use nula_core::{Keys, RelayUrl, Timestamp};
use nula_gossip::Gossip;
use nula_storage::NostrDatabase;
use nula_storage::redb::RedbDatabase;

mod helpers;
use helpers::{build_relay_list, relay_list_from_iter};

fn keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000020")
        .expect("hardcoded hex")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warm_up_rehydrates_routes_from_redb_after_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("gossip.redb");
    let alice = *keys().public_key();

    // First run: stand up gossip backed by RedbDatabase, ingest an
    // NIP-65 list, drop everything. The list is persisted to the redb
    // file by Gossip::process -> NostrDatabase::save_event.
    {
        let db: Arc<dyn NostrDatabase> = Arc::new(
            RedbDatabase::builder(&path)
                .build()
                .await
                .expect("open redb for first run"),
        );
        let gossip = Gossip::builder()
            .database(Arc::clone(&db))
            .build()
            .expect("gossip build #1");

        let list = relay_list_from_iter([
            ("wss://write.example/", RelayMarker::Write),
            ("wss://read.example/", RelayMarker::Read),
            ("wss://both.example/", RelayMarker::ReadWrite),
        ]);
        let event = build_relay_list(&keys(), &list, Timestamp::from_secs(1_700_000_000));
        gossip.process(&event, None).await;

        // Sanity: in-memory routes are populated before the drop.
        let outbox_before = gossip.outbox_relays(&alice).await;
        assert!(
            outbox_before.contains(&RelayUrl::parse("wss://write.example/").expect("url")),
            "process must populate the in-memory cache",
        );
    }

    // Second run: reopen the SAME redb file, build a fresh Gossip
    // handle, and warm_up. The route table must come back from disk.
    let db: Arc<dyn NostrDatabase> = Arc::new(
        RedbDatabase::builder(&path)
            .build()
            .await
            .expect("open redb for second run"),
    );
    let gossip = Gossip::builder()
        .database(Arc::clone(&db))
        .build()
        .expect("gossip build #2");

    // warm_up must re-ingest the persisted NIP-65 event.
    gossip.warm_up([alice]).await.expect("warm_up");

    let outbox = gossip.outbox_relays(&alice).await;
    let inbox = gossip.inbox_relays(&alice).await;
    assert!(
        outbox.contains(&RelayUrl::parse("wss://write.example/").expect("url")),
        "outbox must survive the redb-backed reboot; got {outbox:?}",
    );
    assert!(
        outbox.contains(&RelayUrl::parse("wss://both.example/").expect("url")),
        "outbox (read+write marker) must survive",
    );
    assert!(
        inbox.contains(&RelayUrl::parse("wss://read.example/").expect("url")),
        "inbox must survive; got {inbox:?}",
    );
}
