//! Query-path semantics over LMDB: each index path is exercised.

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
use nula_core::event::{Kind, Tag};
use nula_core::filter::Filter;
use nula_storage::NostrDatabase;

#[tokio::test]
async fn empty_filter_returns_newest_first() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    db.save_event(&text_note(&k, "old", 100)).await.unwrap();
    db.save_event(&text_note(&k, "middle", 150)).await.unwrap();
    db.save_event(&text_note(&k, "new", 200)).await.unwrap();

    let events = db.query(Filter::new()).await.expect("query");
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["new", "middle", "old"]);
}

#[tokio::test]
async fn author_filter_isolates_per_author() {
    let (db, _tmp) = fresh_db().await;
    let a = keys();
    let b = keys();
    db.save_event(&text_note(&a, "a1", 100)).await.unwrap();
    db.save_event(&text_note(&b, "b1", 100)).await.unwrap();
    db.save_event(&text_note(&a, "a2", 200)).await.unwrap();

    let filter = Filter::new().author(*a.public_key());
    let events = db.query(filter).await.expect("query");
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn kind_author_filter_targets_secondary_index() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    db.save_event(&text_note(&k, "note", 100)).await.unwrap();
    db.save_event(&event_with_tags(&k, Kind::new(6), "repost", 110, []))
        .await
        .unwrap();

    let filter = Filter::new().author(*k.public_key()).kind(Kind::TEXT_NOTE);
    let events = db.query(filter).await.expect("query");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().unwrap().content, "note");
}

#[tokio::test]
async fn ids_filter_uses_primary_table() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    let a = text_note(&k, "a", 100);
    let b = text_note(&k, "b", 200);
    db.save_event(&a).await.unwrap();
    db.save_event(&b).await.unwrap();

    let filter = Filter::new().id(a.id);
    let events = db.query(filter).await.expect("query");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().unwrap().id, a.id);
}

#[tokio::test]
async fn replaceable_keeps_one_per_kind_author() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    let v1 = event_with_tags(&k, Kind::METADATA, "{\"v\":1}", 100, []);
    let v2 = event_with_tags(&k, Kind::METADATA, "{\"v\":2}", 200, []);
    db.save_event(&v1).await.unwrap();
    db.save_event(&v2).await.unwrap();

    let events = db
        .query(Filter::new().author(*k.public_key()).kind(Kind::METADATA))
        .await
        .expect("query");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().unwrap().content, "{\"v\":2}");
}

#[tokio::test]
async fn addressable_coordinate_is_indexed() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    let d = Tag::new(["d", "draft-1"]).unwrap();
    let post = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "draft", 100, [d]);
    db.save_event(&post).await.unwrap();

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("draft-1");
    let events = db.query(filter).await.expect("query");
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn count_matches_query_length() {
    let (db, _tmp) = fresh_db().await;
    let k = keys();
    for ts in 100..105 {
        db.save_event(&text_note(&k, "x", ts)).await.unwrap();
    }
    let total = db.count(Filter::new()).await.unwrap();
    assert_eq!(total, 5);
}
