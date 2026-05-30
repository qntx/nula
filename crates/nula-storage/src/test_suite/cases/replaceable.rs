//! Replaceable + addressable kind routing.

use crate::{RejectedReason, SaveEventStatus};
use nula_core::event::{Kind, Tag};
use nula_core::filter::Filter;

use crate::test_suite::DatabaseFactory;
use crate::test_suite::helpers::{event_with_tags, keys, metadata_event};

/// Newer replaceable event of the same kind/author wins.
pub async fn newer_metadata_replaces_older<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let v1 = metadata_event(&k, r#"{"name":"old"}"#, 100);
    let v2 = metadata_event(&k, r#"{"name":"new"}"#, 200);

    db.save_event(&v1).await.expect("save v1");
    db.save_event(&v2).await.expect("save v2");

    let filter = Filter::new().author(*k.public_key()).kind(Kind::METADATA);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(
        events.len(),
        1,
        "replaceable kinds keep one event per author"
    );
    assert_eq!(
        events.first().expect("one event").content,
        r#"{"name":"new"}"#
    );
}

/// Older replaceable event must lose against an existing newer one
/// (`Rejected(Replaced)`).
pub async fn older_metadata_is_rejected_as_replaced<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let v1 = metadata_event(&k, r#"{"name":"new"}"#, 200);
    let v0 = metadata_event(&k, r#"{"name":"old"}"#, 100);

    db.save_event(&v1).await.expect("save v1");
    let status = db.save_event(&v0).await.expect("re-save older");
    assert_eq!(
        status,
        SaveEventStatus::Rejected(RejectedReason::Replaced),
        "older replaceable must lose"
    );
}

/// Addressable kinds with the same `(kind, author, d)` coordinate
/// replace each other.
pub async fn addressable_coordinate_replacement<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let d = Tag::new(["d", "post-1"]).expect("d tag");
    let v1 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "draft", 100, [d.clone()]);
    let v2 = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "final", 200, [d]);

    db.save_event(&v1).await.expect("save v1");
    db.save_event(&v2).await.expect("save v2");

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post-1");
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().expect("one event").content, "final");
}

/// Different `d` tags at the same kind+author coexist independently.
pub async fn addressable_different_d_tags_coexist<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let post1 = event_with_tags(
        &k,
        Kind::LONG_FORM_TEXT_NOTE,
        "first",
        100,
        [Tag::new(["d", "post-1"]).expect("d-1")],
    );
    let post2 = event_with_tags(
        &k,
        Kind::LONG_FORM_TEXT_NOTE,
        "second",
        100,
        [Tag::new(["d", "post-2"]).expect("d-2")],
    );

    db.save_event(&post1).await.expect("save post-1");
    db.save_event(&post2).await.expect("save post-2");

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(
        events.len(),
        2,
        "different d-tags occupy different coordinates"
    );
}
