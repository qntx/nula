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
use nula_storage::redb::{Error, RedbDatabase};
use nula_storage::test_suite::helpers::{keys, text_note};
use nula_storage::{NostrDatabase, SaveEventStatus};

/// Open a fresh `RedbDatabase` against `path`, propagating typed
/// errors. Local helper because the rest of the redb tests use the
/// shared `RedbFactory` in `redb_suite.rs`.
async fn try_open(path: impl AsRef<Path>) -> Result<RedbDatabase, Error> {
    RedbDatabase::builder(path.as_ref().to_owned())
        .build()
        .await
}

#[tokio::test]
async fn events_survive_handle_drop_and_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("events.redb");
    let k = keys();

    {
        let db = try_open(&path).await.expect("first open");
        for (i, ts) in (100..105_u64).enumerate() {
            let event = text_note(&k, &format!("evt-{i}"), ts);
            let status = db.save_event(&event).await.expect("save ok");
            assert_eq!(status, SaveEventStatus::Success);
        }
        // Drop the handle — redb must flush and close the file before
        // we reopen.
        drop(db);
    }

    let reopened = try_open(&path).await.expect("reopen");
    let events = reopened.query(Filter::new()).await.expect("query ok");
    assert_eq!(events.len(), 5, "events must survive a handle cycle");

    // Ordering is newest-first by created_at.
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["evt-4", "evt-3", "evt-2", "evt-1", "evt-0"]);
}

#[tokio::test]
async fn wipe_persists_across_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("events.redb");
    let k = keys();

    {
        let db = try_open(&path).await.expect("first open");
        db.save_event(&text_note(&k, "transient", 100))
            .await
            .expect("save");
        db.wipe().await.expect("wipe ok");
    }

    let reopened = try_open(&path).await.expect("reopen");
    let events = reopened.query(Filter::new()).await.expect("query ok");
    assert!(
        events.is_empty(),
        "wiped store must stay empty after reopen"
    );
}
