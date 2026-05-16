//! End-to-end publish path: pool fans an event out to every WRITE
//! relay and round-trips OK acknowledgements.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use std::time::Duration;

use nula_relay_pool::{Error, RelayCapabilities};

mod helpers;
use helpers::{make_pool, make_relay, make_text_note};

#[tokio::test]
async fn send_event_full_success_persists_on_every_relay() {
    let (pool, _db) = make_pool();
    let r1 = make_relay().await;
    let r2 = make_relay().await;

    pool.add_relay(r1.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add r1");
    pool.add_relay(r2.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add r2");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let event = make_text_note("hello relays", "send_event");
    let id = event.id;
    let output = pool
        .send_event(event)
        .await
        .expect("send_event yields output");

    assert_eq!(output.value, id);
    assert!(output.is_full_success(), "every relay should ack");
    assert_eq!(output.success.len(), 2);
    assert!(output.failed.is_empty());

    // Both relays' storage should now hold the event.
    let on_r1 = r1.database().event_by_id(&id).await.expect("query r1");
    let on_r2 = r2.database().event_by_id(&id).await.expect("query r2");
    assert!(on_r1.is_some());
    assert!(on_r2.is_some());
}

#[tokio::test]
async fn send_event_no_write_relays_errors() {
    let (pool, _db) = make_pool();
    let r1 = make_relay().await;

    // Add as READ-only — no WRITE relays exist.
    pool.add_relay(r1.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let event = make_text_note("nope", "no-write");
    let err = pool
        .send_event(event)
        .await
        .expect_err("no WRITE relay -> NoRelaysSpecified");
    assert!(matches!(err, Error::NoRelaysSpecified));
}
