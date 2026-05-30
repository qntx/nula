//! Concurrency stress: many concurrent `save_event` calls into the
//! same handle must not deadlock, corrupt state, or lose events.
//!
//! This case complements the per-method semantic checks in
//! [`crate::test_suite::cases::save_event`] — those verify *what* the store does,
//! this verifies that the store *survives* hot contention.

use std::sync::Arc;

use crate::SaveEventStatus;
use nula_core::filter::Filter;

use crate::test_suite::DatabaseFactory;
use crate::test_suite::helpers::{keys, text_note};

/// Spawn `WRITERS` tasks, each saving `EVENTS_PER_WRITER` distinct
/// events through the same `Arc<dyn NostrDatabase>`. Every save must
/// succeed and every event must be observable through `query`.
pub async fn concurrent_saves_do_not_lose_events<F: DatabaseFactory>(factory: &F) {
    const WRITERS: u64 = 8;
    const EVENTS_PER_WRITER: u64 = 16;

    let (db, _guard) = factory.build().await;
    let k = Arc::new(keys());

    let mut handles = Vec::with_capacity(WRITERS as usize);
    for writer in 0..WRITERS {
        let db = Arc::clone(&db);
        let k = Arc::clone(&k);
        handles.push(tokio::spawn(async move {
            for i in 0..EVENTS_PER_WRITER {
                let ts = 1_000 + writer * 1_000 + i;
                let content = format!("w{writer}-e{i}");
                let event = text_note(&k, &content, ts);
                let status = db
                    .save_event(&event)
                    .await
                    .expect("concurrent save must succeed");
                assert_eq!(
                    status,
                    SaveEventStatus::Success,
                    "writer {writer} event {i} status {status:?}"
                );
            }
        }));
    }

    for h in handles {
        h.await.expect("writer task must join cleanly");
    }

    let expected = WRITERS * EVENTS_PER_WRITER;
    let count = db.count(Filter::new()).await.expect("count ok");
    assert_eq!(
        count as u64, expected,
        "every concurrent save must be visible: expected {expected}, got {count}"
    );

    let events = db.query(Filter::new()).await.expect("query ok");
    assert_eq!(
        events.len() as u64,
        expected,
        "query must materialise every concurrently-saved event"
    );
}
