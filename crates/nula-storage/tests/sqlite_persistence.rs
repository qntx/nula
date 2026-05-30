//! `SQLite`-specific edge cases: surviving a process restart.
//!
//! The shared `nula-storage-test-suite` covers in-process semantics
//! (NIP-09 deletion, replaceable / addressable kinds, expirations,
//! concurrency, query filters). This file complements it with the
//! durability story `SQLite` is the reason we picked: open the
//! file, write events, drop the handle, reopen, observe the same
//! state.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "integration test file, not production code"
)]

use nula_core::event::EventBuilder;
use nula_core::filter::Filter;
use nula_core::key::Keys;
use nula_core::types::Timestamp;
use nula_storage::NostrDatabase;
use nula_storage::sqlite::SqliteDatabase;

fn keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000010")
        .expect("valid hex key")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_survive_a_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("events.sqlite");

    // First run: write two events and drop the handle.
    let db = SqliteDatabase::open(&path).await.expect("open #1");
    let k = keys();
    let e1 = EventBuilder::text_note("first")
        .created_at(Timestamp::from_secs(1_700_000_001))
        .sign_with_keys(&k)
        .expect("sign first");
    let e2 = EventBuilder::text_note("second")
        .created_at(Timestamp::from_secs(1_700_000_002))
        .sign_with_keys(&k)
        .expect("sign second");
    db.save_event(&e1).await.expect("save first");
    db.save_event(&e2).await.expect("save second");
    drop(db);

    // Second run: reopen the same file and expect both events back.
    let reopened = SqliteDatabase::open(&path).await.expect("open #2");
    let count = reopened
        .count(Filter::new())
        .await
        .expect("count after reopen");
    assert_eq!(count, 2, "both events must survive the reopen");

    let by_id_first = reopened
        .event_by_id(&e1.id)
        .await
        .expect("event_by_id first")
        .expect("event present");
    assert_eq!(by_id_first.id, e1.id);
    assert_eq!(by_id_first.content, "first");

    let by_id_second = reopened
        .event_by_id(&e2.id)
        .await
        .expect("event_by_id second")
        .expect("event present");
    assert_eq!(by_id_second.id, e2.id);
    assert_eq!(by_id_second.content, "second");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wipe_persists_across_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("events.sqlite");

    let db = SqliteDatabase::open(&path).await.expect("open #1");
    let k = keys();
    let event = EventBuilder::text_note("doomed")
        .created_at(Timestamp::from_secs(1_700_000_010))
        .sign_with_keys(&k)
        .expect("sign");
    db.save_event(&event).await.expect("save");
    db.wipe().await.expect("wipe");
    drop(db);

    let reopened = SqliteDatabase::open(&path).await.expect("open #2");
    let count = reopened.count(Filter::new()).await.expect("count");
    assert_eq!(count, 0, "wipe must persist across reopen");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_memory_database_does_not_persist() {
    let db = SqliteDatabase::open_in_memory().await.expect("open mem #1");
    let k = keys();
    let event = EventBuilder::text_note("ephemeral")
        .created_at(Timestamp::from_secs(1_700_000_020))
        .sign_with_keys(&k)
        .expect("sign");
    db.save_event(&event).await.expect("save");
    drop(db);

    // A fresh in-memory db is genuinely fresh.
    let fresh = SqliteDatabase::open_in_memory().await.expect("open mem #2");
    let count = fresh.count(Filter::new()).await.expect("count");
    assert_eq!(count, 0);
}
