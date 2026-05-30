//! NIP-09 deletion: tombstone semantics for both event-id and
//! addressable-coordinate targets.

use crate::{DatabaseEventStatus, RejectedReason, SaveEventStatus};
use nula_core::event::{Coordinate, EventBuilder, Kind, Tag};
use nula_core::filter::Filter;
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;

use crate::test_suite::DatabaseFactory;
use crate::test_suite::helpers::{event_with_tags, keys, text_note};

/// A NIP-09 deletion request from the author removes the target
/// event, tombstones its id, and keeps the deletion event itself
/// queryable.
pub async fn deletion_removes_event_and_tombstones_id<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let target = text_note(&k, "delete me", 100);
    db.save_event(&target).await.expect("save target");

    let request = DeletionRequest::new().delete_event(target.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .expect("deletion signs");

    let status = db.save_event(&deletion).await.expect("save deletion");
    assert_eq!(status, SaveEventStatus::Success);

    assert!(
        db.event_by_id(&target.id)
            .await
            .expect("lookup ok")
            .is_none(),
        "deleted event must not be retrievable"
    );

    let again = db.save_event(&target).await.expect("re-save ok");
    assert_eq!(
        again,
        SaveEventStatus::Rejected(RejectedReason::Deleted),
        "tombstone refuses re-insertion"
    );

    let status_after = db.check_id(&target.id).await.expect("check ok");
    assert_eq!(status_after, DatabaseEventStatus::Deleted);

    let stored = db
        .query(Filter::new().kind(Kind::EVENT_DELETION))
        .await
        .expect("query deletions");
    assert_eq!(stored.len(), 1);
}

/// Deletion requests signed by anyone other than the original
/// author must be ignored.
pub async fn deletion_only_targets_own_events<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let a = keys();
    let b = keys();
    let theirs = text_note(&b, "not yours", 100);
    db.save_event(&theirs).await.expect("save other");

    let request = DeletionRequest::new().delete_event(theirs.id);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&a)
        .expect("deletion signs");
    db.save_event(&deletion).await.expect("save deletion");

    assert!(
        db.event_by_id(&theirs.id)
            .await
            .expect("lookup ok")
            .is_some(),
        "deletion by another author must be ignored"
    );
}

/// Deletion of an addressable coordinate tombstones the entire
/// `(kind, author, d)` triple: republishing an older event at the
/// same coordinate fails, republishing a strictly-newer one
/// succeeds.
pub async fn deletion_tombstones_addressable_coordinate<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let d_tag = Tag::new(["d", "post"]).expect("d tag");
    let v1 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "v1", 100, [d_tag.clone()]);
    db.save_event(&v1).await.expect("save v1");

    let coord = Coordinate::new(Kind::LONG_FORM_TEXT_NOTE, *k.public_key(), "post");
    let request = DeletionRequest::new().delete_coordinate(coord);
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::from_secs(200))
        .sign_with_keys(&k)
        .expect("deletion signs");
    db.save_event(&deletion).await.expect("save deletion");

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post");
    let remaining = db.query(filter).await.expect("query ok");
    assert!(remaining.is_empty(), "coordinate target must be removed");

    // Older republish at the same coordinate is refused.
    let v_old = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "old", 50, [d_tag.clone()]);
    let status = db.save_event(&v_old).await.expect("re-save older");
    assert_eq!(
        status,
        SaveEventStatus::Rejected(RejectedReason::Deleted),
        "older addressable republish must be refused"
    );

    // Strictly-newer republish is allowed (matches rust-nostr semantics).
    let v_new = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "fresh", 300, [d_tag]);
    let status_new = db.save_event(&v_new).await.expect("re-save newer");
    assert_eq!(status_new, SaveEventStatus::Success);
}
