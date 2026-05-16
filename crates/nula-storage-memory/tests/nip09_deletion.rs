//! NIP-09 deletion: tombstone semantics for both event-id and
//! addressable-coordinate targets.

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
use nula_core::event::{EventBuilder, Kind, Tag};
use nula_core::filter::Filter;
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;
use nula_storage::{DatabaseEventStatus, NostrDatabase, RejectedReason, SaveEventStatus};
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn deletion_removes_event_and_tombstones_id() {
    let db = MemoryDatabase::new();
    let k = keys();
    let target = text_note(&k, "delete me", 100);
    db.save_event(&target).await.unwrap();
    assert_eq!(db.len(), 1);

    let request = DeletionRequest::new().delete_event(target.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .expect("deletion signs");

    let status = db.save_event(&deletion).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Success);

    // The targeted event must be gone.
    assert!(
        db.event_by_id(&target.id).await.unwrap().is_none(),
        "deleted event must not be retrievable"
    );

    // Its id must tombstone for future inserts.
    let again = db.save_event(&target).await.expect("re-save ok");
    assert_eq!(
        again,
        SaveEventStatus::Rejected(RejectedReason::Deleted),
        "tombstone refuses re-insertion"
    );

    let status_after = db.check_id(&target.id).await.unwrap();
    assert_eq!(status_after, DatabaseEventStatus::Deleted);

    // The deletion event itself remains visible so other clients can
    // observe the request.
    let stored = db
        .query(Filter::new().kind(Kind::EVENT_DELETION))
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
}

#[tokio::test]
async fn deletion_only_targets_own_events() {
    let db = MemoryDatabase::new();
    let a = keys();
    let b = keys();
    let theirs = text_note(&b, "not yours", 100);
    db.save_event(&theirs).await.unwrap();

    // `a` tries to delete `b`'s event.
    let request = DeletionRequest::new().delete_event(theirs.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&a)
        .expect("deletion signs");
    db.save_event(&deletion).await.unwrap();

    assert!(
        db.event_by_id(&theirs.id).await.unwrap().is_some(),
        "deletion by another author must be ignored"
    );
}

#[tokio::test]
async fn deletion_tombstones_addressable_coordinate() {
    let db = MemoryDatabase::new();
    let k = keys();
    let d_tag = Tag::new(["d", "post"]).unwrap();
    let v1 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "v1", 100, [d_tag.clone()]);
    db.save_event(&v1).await.unwrap();

    let coord =
        nula_core::event::Coordinate::new(Kind::LONG_FORM_TEXT_NOTE, *k.public_key(), "post");
    let request = DeletionRequest::new().delete_coordinate(coord.clone());
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .expect("deletion signs");
    db.save_event(&deletion).await.unwrap();

    // The addressable event must be gone.
    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post");
    let remaining = db.query(filter.clone()).await.unwrap();
    assert!(remaining.is_empty(), "coordinate target must be removed");

    // An older republish under the same coordinate is refused.
    let v_old = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "old", 50, [d_tag.clone()]);
    let status = db.save_event(&v_old).await.expect("save ok");
    assert_eq!(
        status,
        SaveEventStatus::Rejected(RejectedReason::Deleted),
        "older addressable republish must be refused"
    );

    // A strictly-newer republish at the same coordinate is allowed,
    // matching the rust-nostr reference behaviour.
    let v_new = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "fresh", 300, [d_tag.clone()]);
    let status_new = db.save_event(&v_new).await.expect("save ok");
    assert_eq!(status_new, SaveEventStatus::Success);
}
