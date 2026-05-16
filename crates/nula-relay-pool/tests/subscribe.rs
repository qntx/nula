//! Subscribe path: pool opens a per-relay subscription, relays
//! reply with events + EOSE.

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
async fn subscribe_against_all_read_relays() {
    let (pool, _db) = make_pool();
    let r1 = make_relay().await;
    let r2 = make_relay().await;

    // Pre-populate r1 with one historical event so the subscribe
    // path observably hits storage on the relay side.
    let historical = make_text_note("history", "sub-1");
    let id = historical.id;
    r1.database().save_event(&historical).await.expect("seed");

    pool.add_relay(r1.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add r1");
    pool.add_relay(r2.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add r2");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let sub_id = nula_core::SubscriptionId::generate().expect("sub id");
    let filters = vec![nula_core::Filter::new().id(id)];
    let output = pool
        .subscribe(
            sub_id.clone(),
            filters,
            nula_relay::SubscribeOptions::default(),
        )
        .await
        .expect("subscribe yields output");

    assert_eq!(output.value, sub_id);
    assert!(output.is_full_success());
    assert_eq!(output.success.len(), 2);
}

#[tokio::test]
async fn subscribe_no_read_relays_errors() {
    let (pool, _db) = make_pool();
    let r1 = make_relay().await;
    pool.add_relay(r1.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let sub_id = nula_core::SubscriptionId::generate().expect("sub id");
    let err = pool
        .subscribe(
            sub_id,
            vec![nula_core::Filter::new()],
            nula_relay::SubscribeOptions::default(),
        )
        .await
        .expect_err("no READ relay");
    assert!(matches!(err, Error::NoRelaysSpecified));
}
