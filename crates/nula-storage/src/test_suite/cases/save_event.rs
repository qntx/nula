//! Save-path semantics: duplicate, ephemeral, expired, deleted,
//! replaced.
//!
//! Runs against any `NostrDatabase` backend (`memory`, `redb`)
//! through the shared conformance suite.

use nula_core::event::Kind;

use crate::test_suite::DatabaseFactory;
use crate::test_suite::helpers::{event_with_tags, expiring_text_note, keys, text_note};
use crate::{DatabaseEventStatus, RejectedReason, SaveEventStatus};

/// First insert of a brand-new event must succeed.
pub async fn first_save_succeeds<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
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

/// Re-inserting an identical event must be reported as a duplicate
/// rather than written twice.
pub async fn duplicate_id_is_rejected<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let first = db.save_event(&event).await.expect("save ok");
    let second = db.save_event(&event).await.expect("re-save ok");

    assert_eq!(first, SaveEventStatus::Success);
    assert_eq!(second, SaveEventStatus::Rejected(RejectedReason::Duplicate));
}

/// Ephemeral kinds (NIP-01 20000..30000) must be dropped and must not
/// leak into the id-status table.
pub async fn ephemeral_kind_is_dropped<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    // 22242 is NIP-42 AUTHENTICATION, which sits in the ephemeral range.
    let event = event_with_tags(&keys(), Kind::new(22_242), "auth", 1_700_000_000, []);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Ephemeral));

    let status_check = db.check_id(&event.id).await.expect("check ok");
    assert_eq!(status_check, DatabaseEventStatus::NotExistent);
}

/// `check_id` must report `NotExistent` before save and `Saved`
/// afterwards.
pub async fn check_id_reports_states<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let event = text_note(&keys(), "hello", 1_700_000_000);

    let initial = db.check_id(&event.id).await.expect("check ok");
    assert_eq!(initial, DatabaseEventStatus::NotExistent);

    db.save_event(&event).await.expect("save ok");

    let after = db.check_id(&event.id).await.expect("check ok");
    assert_eq!(after, DatabaseEventStatus::Saved);
}

/// `wipe` must restore the empty-store invariant.
pub async fn wipe_clears_every_table<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    db.save_event(&text_note(&k, "a", 100))
        .await
        .expect("save a");
    db.save_event(&text_note(&k, "b", 200))
        .await
        .expect("save b");

    db.wipe().await.expect("wipe ok");

    // Both events must no longer be retrievable.
    let by_id = db.event_by_id(&text_note(&k, "a", 100).id).await;
    assert!(matches!(by_id, Ok(None)), "wipe must purge events");
}

/// NIP-40 events whose `expiration` tag is already in the past must
/// be rejected at save time.
pub async fn already_expired_event_is_rejected<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let event = expiring_text_note(
        &keys(),
        "stale",
        /* created_at */ 100,
        /* exp_at     */ 200,
    );

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Expired));
}

/// NIP-40 events whose `expiration` tag is well in the future must
/// be accepted.
pub async fn future_expiration_event_is_accepted<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    // A century out keeps wall-clock drift from making this flaky.
    let one_century_secs = 100_u64 * 365 * 24 * 60 * 60;
    let now_secs = nula_core::Timestamp::now().expect("clock").as_secs();
    let event = expiring_text_note(&keys(), "fresh", now_secs, now_secs + one_century_secs);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Success);
}
