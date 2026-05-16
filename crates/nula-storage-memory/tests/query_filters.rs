//! Query path: each [`QueryPattern`] variant exercised through its
//! corresponding filter shape, plus the global ordering invariant.

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
use nula_core::event::{Kind, Tag};
use nula_core::filter::Filter;
use nula_storage::NostrDatabase;
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn empty_filter_returns_everything_newest_first() {
    let db = MemoryDatabase::new();
    let k = keys();
    db.save_event(&text_note(&k, "old", 100)).await.unwrap();
    db.save_event(&text_note(&k, "new", 200)).await.unwrap();
    db.save_event(&text_note(&k, "middle", 150)).await.unwrap();

    let events = db.query(Filter::new()).await.expect("query ok");
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["new", "middle", "old"]);
}

#[tokio::test]
async fn author_filter_uses_index_and_orders_correctly() {
    let db = MemoryDatabase::new();
    let a = keys();
    let b = keys();
    db.save_event(&text_note(&a, "a1", 100)).await.unwrap();
    db.save_event(&text_note(&b, "b1", 100)).await.unwrap();
    db.save_event(&text_note(&a, "a2", 200)).await.unwrap();

    let filter = Filter::new().author(*a.public_key());
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 2);
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["a2", "a1"]);
}

#[tokio::test]
async fn kind_author_filter_drops_other_kinds() {
    let db = MemoryDatabase::new();
    let k = keys();
    db.save_event(&text_note(&k, "note", 100)).await.unwrap();
    db.save_event(&event_with_tags(&k, Kind::new(6), "repost", 110, []))
        .await
        .unwrap();

    let filter = Filter::new().author(*k.public_key()).kind(Kind::TEXT_NOTE);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().unwrap().content, "note");
}

#[tokio::test]
async fn coordinate_filter_targets_addressable() {
    let db = MemoryDatabase::new();
    let k = keys();
    let d = Tag::new(["d", "post-1"]).unwrap();
    let event = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "v1", 100, [d.clone()]);
    db.save_event(&event).await.unwrap();

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post-1");
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn time_bounds_are_inclusive() {
    let db = MemoryDatabase::new();
    let k = keys();
    db.save_event(&text_note(&k, "earlier", 50)).await.unwrap();
    db.save_event(&text_note(&k, "mid", 100)).await.unwrap();
    db.save_event(&text_note(&k, "later", 150)).await.unwrap();

    let filter = Filter::new()
        .since(nula_core::Timestamp::from_secs(100))
        .until(nula_core::Timestamp::from_secs(100));
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().unwrap().content, "mid");
}

#[tokio::test]
async fn limit_caps_returned_events() {
    let db = MemoryDatabase::new();
    let k = keys();
    for ts in (100..110).step_by(1) {
        db.save_event(&text_note(&k, "x", ts))
            .await
            .expect("save ok");
    }
    let filter = Filter::new().limit(3);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 3);
}

#[tokio::test]
async fn count_matches_query_length() {
    let db = MemoryDatabase::new();
    let k = keys();
    db.save_event(&text_note(&k, "a", 100)).await.unwrap();
    db.save_event(&text_note(&k, "b", 200)).await.unwrap();

    let total = db.count(Filter::new()).await.expect("count ok");
    assert_eq!(total, db.query(Filter::new()).await.unwrap().len());
}

#[tokio::test]
async fn delete_matching_drops_events_without_tombstoning() {
    let db = MemoryDatabase::new();
    let k = keys();
    let evt = text_note(&k, "drop", 100);
    db.save_event(&evt).await.unwrap();

    db.delete(Filter::new().id(evt.id))
        .await
        .expect("delete ok");
    assert!(db.is_empty());

    // The event is not tombstoned — saving the same id again succeeds.
    let status = db.save_event(&evt).await.expect("re-save ok");
    assert_eq!(
        status,
        nula_storage::SaveEventStatus::Success,
        "non-NIP-09 delete must not tombstone"
    );
}
