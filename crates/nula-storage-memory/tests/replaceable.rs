//! Replaceable + addressable kind routing.

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

use helpers::{event_with_tags, keys, metadata_event};
use nula_core::event::{Kind, Tag};
use nula_core::filter::Filter;
use nula_storage::{NostrDatabase, RejectedReason, SaveEventStatus};
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn newer_metadata_replaces_older() {
    let db = MemoryDatabase::new();
    let k = keys();
    let v1 = metadata_event(&k, r#"{"name":"old"}"#, 100);
    let v2 = metadata_event(&k, r#"{"name":"new"}"#, 200);

    db.save_event(&v1).await.unwrap();
    db.save_event(&v2).await.unwrap();
    assert_eq!(db.len(), 1, "replaceable kinds keep one event per author");

    let filter = Filter::new().author(*k.public_key()).kind(Kind::METADATA);
    let events = db.query(filter).await.unwrap();
    assert_eq!(events.first().unwrap().content, r#"{"name":"new"}"#);
}

#[tokio::test]
async fn older_metadata_is_rejected_as_replaced() {
    let db = MemoryDatabase::new();
    let k = keys();
    let v1 = metadata_event(&k, r#"{"name":"new"}"#, 200);
    let v0 = metadata_event(&k, r#"{"name":"old"}"#, 100);

    db.save_event(&v1).await.unwrap();
    let status = db.save_event(&v0).await.unwrap();
    assert_eq!(
        status,
        SaveEventStatus::Rejected(RejectedReason::Replaced),
        "older replaceable must lose"
    );
}

#[tokio::test]
async fn addressable_coordinate_replacement() {
    let db = MemoryDatabase::new();
    let k = keys();
    let d = Tag::new(["d", "post-1"]).unwrap();
    let v1 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "draft", 100, [d.clone()]);
    let v2 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "final", 200, [d.clone()]);

    db.save_event(&v1).await.unwrap();
    db.save_event(&v2).await.unwrap();
    assert_eq!(db.len(), 1);

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post-1");
    let events = db.query(filter).await.unwrap();
    assert_eq!(events.first().unwrap().content, "final");
}

#[tokio::test]
async fn addressable_different_d_tags_coexist() {
    let db = MemoryDatabase::new();
    let k = keys();
    let post1 = event_with_tags(
        &k,
        Kind::LONG_FORM_TEXT_NOTE,
        "first",
        100,
        [Tag::new(["d", "post-1"]).unwrap()],
    );
    let post2 = event_with_tags(
        &k,
        Kind::LONG_FORM_TEXT_NOTE,
        "second",
        100,
        [Tag::new(["d", "post-2"]).unwrap()],
    );

    db.save_event(&post1).await.unwrap();
    db.save_event(&post2).await.unwrap();
    assert_eq!(db.len(), 2, "different d-tags occupy different coordinates");
}
