//! NIP-40 expiration: events with a past `expiration` tag are
//! refused at write time.

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

use helpers::{expiring_text_note, keys};
use nula_storage::{NostrDatabase, RejectedReason, SaveEventStatus};
use nula_storage_memory::MemoryDatabase;

#[tokio::test]
async fn already_expired_event_is_rejected() {
    let db = MemoryDatabase::new();
    let event = expiring_text_note(
        &keys(),
        "stale",
        /* created_at */ 100,
        /* exp_at */ 200,
    );

    // Saving "now" is the wall-clock when we call save_event(); the
    // expiration is timestamp 200 (Unix epoch), so the event is well
    // and truly expired.
    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Expired));
    assert!(db.is_empty());
}

#[tokio::test]
async fn future_expiration_event_is_accepted() {
    let db = MemoryDatabase::new();
    // Set the expiration tag a century into the future so wall-clock
    // drift cannot make this test flaky.
    let one_century_seconds = 100u64 * 365 * 24 * 60 * 60;
    let now_secs = nula_core::Timestamp::now().expect("clock").as_secs();
    let event = expiring_text_note(&keys(), "fresh", now_secs, now_secs + one_century_seconds);

    let status = db.save_event(&event).await.expect("save ok");
    assert_eq!(status, SaveEventStatus::Success);
}
