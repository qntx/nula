//! Save-path semantics over LMDB: duplicate / ephemeral / expired /
//! replaceable mirror the memory backend's contract.

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

use helpers::{event_with_tags, fresh_db, keys, text_note};
use nula_core::event::Kind;
use nula_storage::{DatabaseEventStatus, NostrDatabase, RejectedReason, SaveEventStatus};

#[tokio::test]
async fn first_save_succeeds_and_round_trips() {
    let (db, _tmp) = fresh_db().await;
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Success);

    let fetched = db
        .event_by_id(&event.id)
        .await
        .expect("lookup ok")
        .expect("event present");
    assert_eq!(fetched.id, event.id);
    assert_eq!(fetched.content, event.content);
}

#[tokio::test]
async fn duplicate_id_is_rejected() {
    let (db, _tmp) = fresh_db().await;
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let first = db.save_event(&event).await.expect("save ok");
    let second = db.save_event(&event).await.expect("re-save ok");

    assert_eq!(first, SaveEventStatus::Success);
    assert_eq!(second, SaveEventStatus::Rejected(RejectedReason::Duplicate));
}

#[tokio::test]
async fn ephemeral_kind_is_dropped() {
    let (db, _tmp) = fresh_db().await;
    let event = event_with_tags(&keys(), Kind::new(22_242), "auth", 1_700_000_000, []);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Ephemeral));

    let status_check = db.check_id(&event.id).await.unwrap();
    assert_eq!(status_check, DatabaseEventStatus::NotExistent);
}
