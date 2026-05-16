//! Capacity cap eviction.

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

use std::num::NonZeroUsize;

use helpers::{keys, text_note};
use nula_storage::{Features, NostrDatabase, SaveEventStatus};
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn bounded_capacity_evicts_oldest() {
    let db = MemoryDatabase::builder()
        .max_events(NonZeroUsize::new(3).expect("positive"))
        .build();
    let k = keys();

    // Insert 5 events; only the 3 newest should remain.
    for ts in 100..105 {
        let status = db
            .save_event(&text_note(&k, &format!("e-{ts}"), ts))
            .await
            .expect("save ok");
        assert_eq!(status, SaveEventStatus::Success);
    }
    assert_eq!(db.len(), 3);

    let events = db.query(nula_core::Filter::new()).await.unwrap();
    let contents: Vec<&str> = events.iter().map(|e| e.content.as_str()).collect();
    assert_eq!(contents, ["e-104", "e-103", "e-102"]);
}

#[tokio::test]
async fn bounded_capacity_advertised_in_features() {
    let db = MemoryDatabase::builder()
        .max_events(NonZeroUsize::new(1).expect("positive"))
        .build();
    assert!(db.features().contains(Features::BOUNDED_CAPACITY));

    let unbounded = MemoryDatabase::new();
    assert!(!unbounded.features().contains(Features::BOUNDED_CAPACITY));
}
