//! Backend-specific: persistence across handle drop + reopen.
//!
//! Not part of the shared conformance suite because no other backend
//! currently models cross-process durability (`MemoryDatabase`
//! evaporates when the handle drops).

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

use std::path::Path;

use nula_core::filter::Filter;
use nula_storage::{NostrDatabase, SaveEventStatus};
use nula_storage_lmdb::{Error, LmdbDatabase};
use nula_storage_test_suite::helpers::{keys, text_note};

/// Open a fresh `LmdbDatabase` against `path`, propagating typed
/// errors. Local helper because the rest of the LMDB tests use the
/// shared `LmdbFactory` in `suite.rs`.
async fn try_open(path: impl AsRef<Path>) -> Result<LmdbDatabase, Error> {
    LmdbDatabase::builder(path.as_ref().to_owned())
        .build()
        .await
}

#[tokio::test]
async fn events_survive_handle_drop_and_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let k = keys();

    {
        let db = try_open(tmp.path()).await.expect("first open");
        for (i, ts) in (100..105_u64).enumerate() {
            let event = text_note(&k, &format!("evt-{i}"), ts);
            let status = db.save_event(&event).await.expect("save ok");
            assert_eq!(status, SaveEventStatus::Success);
        }
        // Drop the handle — the ingester thread must flush and the
        // env must close cleanly before we reopen.
        drop(db);
    }

    let reopened = try_open(tmp.path()).await.expect("reopen");
    let events = reopened.query(Filter::new()).await.expect("query ok");
    assert_eq!(events.len(), 5, "events must survive a handle cycle");

    // Ordering is newest-first by created_at.
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["evt-4", "evt-3", "evt-2", "evt-1", "evt-0"]);
}

#[tokio::test]
async fn wipe_persists_across_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let k = keys();

    {
        let db = try_open(tmp.path()).await.expect("first open");
        db.save_event(&text_note(&k, "transient", 100))
            .await
            .expect("save");
        db.wipe().await.expect("wipe ok");
    }

    let reopened = try_open(tmp.path()).await.expect("reopen");
    let events = reopened.query(Filter::new()).await.expect("query ok");
    assert!(
        events.is_empty(),
        "wiped store must stay empty after reopen"
    );
}
