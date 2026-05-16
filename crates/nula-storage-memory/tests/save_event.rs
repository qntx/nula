//! Save-path semantics: duplicate, ephemeral, expired, deleted,
//! replaced.

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

mod helpers;

use helpers::{event_with_tags, keys, text_note};
use nula_core::event::Kind;
use nula_storage::{DatabaseEventStatus, NostrDatabase, RejectedReason, SaveEventStatus};
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn first_save_succeeds() {
    let db = MemoryDatabase::new();
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Success);
    assert_eq!(db.len(), 1);
}

#[tokio::test]
async fn duplicate_id_is_rejected() {
    let db = MemoryDatabase::new();
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let first = db.save_event(&event).await.expect("save ok");
    let second = db.save_event(&event).await.expect("re-save ok");

    assert_eq!(first, SaveEventStatus::Success);
    assert_eq!(second, SaveEventStatus::Rejected(RejectedReason::Duplicate));
    assert_eq!(db.len(), 1);
}

#[tokio::test]
async fn ephemeral_kind_is_dropped() {
    let db = MemoryDatabase::new();
    // Kind 22242 is NIP-42 AUTHENTICATION, which sits in the ephemeral
    // range (20000..30000).
    let event = event_with_tags(&keys(), Kind::new(22_242), "auth", 1_700_000_000, []);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Ephemeral));
    assert!(db.is_empty());
}

#[tokio::test]
async fn check_id_reports_states() {
    let db = MemoryDatabase::new();
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let initial = db.check_id(&event.id).await.expect("check ok");
    assert_eq!(initial, DatabaseEventStatus::NotExistent);

    db.save_event(&event).await.expect("save ok");

    let after = db.check_id(&event.id).await.expect("check ok");
    assert_eq!(after, DatabaseEventStatus::Saved);
}

#[tokio::test]
async fn event_by_id_round_trips() {
    let db = MemoryDatabase::new();
    let event = text_note(&keys(), "hello", 1_700_000_000);

    db.save_event(&event).await.expect("save ok");

    let fetched = db
        .event_by_id(&event.id)
        .await
        .expect("lookup ok")
        .expect("event present");
    assert_eq!(fetched.id, event.id);
    assert_eq!(fetched.content, event.content);
}

#[tokio::test]
async fn wipe_clears_every_table() {
    let db = MemoryDatabase::new();
    let k = keys();
    db.save_event(&text_note(&k, "a", 100)).await.unwrap();
    db.save_event(&text_note(&k, "b", 200)).await.unwrap();
    assert_eq!(db.len(), 2);

    db.wipe().await.expect("wipe ok");
    assert!(db.is_empty());
}
