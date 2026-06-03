//! Query-path semantics: every `QueryPattern` variant, ordering,
//! inclusive time bounds, `count` agreement, and non-tombstoning
//! `delete`.

use nula_core::event::{Kind, Tag};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;

use crate::test_suite::DatabaseFactory;
use crate::test_suite::helpers::{event_with_tags, keys, text_note};

/// Empty filter must return every stored event, sorted newest-first
/// (NIP-01 wire order).
pub async fn empty_filter_returns_everything_newest_first<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    db.save_event(&text_note(&k, "old", 100))
        .await
        .expect("save old");
    db.save_event(&text_note(&k, "new", 200))
        .await
        .expect("save new");
    db.save_event(&text_note(&k, "middle", 150))
        .await
        .expect("save middle");

    let events = db.query(Filter::new()).await.expect("query ok");
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["new", "middle", "old"]);
}

/// `Filter::author` must restrict results to the right pubkey and
/// keep newest-first ordering.
pub async fn author_filter_uses_index_and_orders_correctly<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let a = keys();
    let b = keys();
    db.save_event(&text_note(&a, "a1", 100))
        .await
        .expect("save a1");
    db.save_event(&text_note(&b, "b1", 100))
        .await
        .expect("save b1");
    db.save_event(&text_note(&a, "a2", 200))
        .await
        .expect("save a2");

    let filter = Filter::new().author(*a.public_key());
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 2);
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["a2", "a1"]);
}

/// `Filter::author + kind` must drop events of other kinds.
pub async fn kind_author_filter_drops_other_kinds<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    db.save_event(&text_note(&k, "note", 100))
        .await
        .expect("save note");
    db.save_event(&event_with_tags(&k, Kind::new(6), "repost", 110, []))
        .await
        .expect("save repost");

    let filter = Filter::new().author(*k.public_key()).kind(Kind::TEXT_NOTE);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().expect("at least one").content, "note");
}

/// Coordinate filter (kind + author + `d` identifier) must target
/// addressable events.
pub async fn coordinate_filter_targets_addressable<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    let d = Tag::new(["d", "post-1"]).expect("d tag");
    let event = event_with_tags(&k, Kind::LONG_FORM_TEXT_NOTE, "v1", 100, [d]);
    db.save_event(&event).await.expect("save");

    let filter = Filter::new()
        .author(*k.public_key())
        .kind(Kind::LONG_FORM_TEXT_NOTE)
        .identifier("post-1");
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
}

/// `since` / `until` bounds are inclusive on both endpoints.
pub async fn time_bounds_are_inclusive<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    db.save_event(&text_note(&k, "earlier", 50))
        .await
        .expect("save earlier");
    db.save_event(&text_note(&k, "mid", 100))
        .await
        .expect("save mid");
    db.save_event(&text_note(&k, "later", 150))
        .await
        .expect("save later");

    let filter = Filter::new()
        .since(Timestamp::from_secs(100))
        .until(Timestamp::from_secs(100));
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 1);
    assert_eq!(events.first().expect("one event").content, "mid");
}

/// `Filter::limit` caps the returned set.
pub async fn limit_caps_returned_events<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    for ts in 100..110 {
        db.save_event(&text_note(&k, "x", ts)).await.expect("save");
    }

    let filter = Filter::new().limit(3);
    let events = db.query(filter).await.expect("query ok");
    assert_eq!(events.len(), 3);
}

/// `count` and `query.len()` must agree for the same filter.
pub async fn count_matches_query_length<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    db.save_event(&text_note(&k, "a", 100))
        .await
        .expect("save a");
    db.save_event(&text_note(&k, "b", 200))
        .await
        .expect("save b");

    let total = db.count(Filter::new()).await.expect("count ok");
    assert_eq!(
        total,
        db.query(Filter::new()).await.expect("query ok").len()
    );
}

/// `negentropy_items` must yield the matching events' `(id, created_at)` set.
///
/// It must equal the pairs `query` would produce, regardless of order
/// (`NegentropyStorageVector::seal` sorts). Pins LMDB's zero-parse
/// override against the materialising default the other backends use.
pub async fn negentropy_items_match_query<F: DatabaseFactory>(factory: &F) {
    let (db, _guard) = factory.build().await;
    let k = keys();
    // A tagged event exercises the borrowed projection's tag decode; a
    // plain one covers the common case.
    db.save_event(&event_with_tags(
        &k,
        Kind::TEXT_NOTE,
        "tagged",
        100,
        [Tag::new(["t", "rust"]).expect("t tag")],
    ))
    .await
    .expect("save tagged");
    db.save_event(&text_note(&k, "plain", 200))
        .await
        .expect("save plain");

    let mut from_neg = db
        .negentropy_items(Filter::new())
        .await
        .expect("negentropy_items ok");
    let mut from_query: Vec<_> = db
        .query(Filter::new())
        .await
        .expect("query ok")
        .into_iter()
        .map(|e| (e.id, e.created_at))
        .collect();
    from_neg.sort();
    from_query.sort();
    assert_eq!(
        from_neg, from_query,
        "negentropy items must equal the query-derived (id, created_at) set"
    );
}

/// `delete(filter)` must drop matching events **without** writing a
/// tombstone (re-inserting the same id afterwards must succeed).
pub async fn delete_matching_drops_events_without_tombstoning<F: DatabaseFactory>(factory: &F) {
    use crate::SaveEventStatus;

    let (db, _guard) = factory.build().await;
    let k = keys();
    let evt = text_note(&k, "drop", 100);
    db.save_event(&evt).await.expect("save");

    db.delete(Filter::new().id(evt.id))
        .await
        .expect("delete ok");

    assert!(
        db.event_by_id(&evt.id).await.expect("lookup ok").is_none(),
        "deleted event must not be retrievable"
    );

    // No tombstone → re-saving the same id succeeds.
    let status = db.save_event(&evt).await.expect("re-save ok");
    assert_eq!(
        status,
        SaveEventStatus::Success,
        "non-NIP-09 delete must not tombstone"
    );
}
