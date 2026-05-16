//! NIP-09 deletion over LMDB.

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

use helpers::{fresh_db, keys, text_note};
use nula_core::event::{EventBuilder, Kind};
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;
use nula_storage::{DatabaseEventStatus, NostrDatabase, RejectedReason, SaveEventStatus};

#[tokio::test]
async fn deletion_tombstones_event_id() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    let target = text_note(&k, "delete me", 100);
    db.save_event(&target).await.unwrap();

    let request = DeletionRequest::new().delete_event(target.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .unwrap();
    db.save_event(&deletion).await.unwrap();

    assert!(
        db.event_by_id(&target.id).await.unwrap().is_none(),
        "deletion must purge the target"
    );

    let status = db.save_event(&target).await.unwrap();
    assert_eq!(
        status,
        SaveEventStatus::Rejected(RejectedReason::Deleted),
        "tombstone must refuse re-insertion"
    );

    let check = db.check_id(&target.id).await.unwrap();
    assert_eq!(check, DatabaseEventStatus::Deleted);
}

#[tokio::test]
async fn deletion_event_itself_remains() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    let target = text_note(&k, "go away", 100);
    db.save_event(&target).await.unwrap();

    let request = DeletionRequest::new().delete_event(target.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .unwrap();
    db.save_event(&deletion).await.unwrap();

    let events = db
        .query(nula_core::Filter::new().kind(Kind::EVENT_DELETION))
        .await
        .unwrap();
    assert_eq!(events.len(), 1, "deletion event itself is stored");
}
