//! Pool broadcast notification stream.

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

use nula_relay::pool::{PoolNotification, RelayCapabilities};

mod helpers;
use helpers::{make_pool, make_relay};

#[tokio::test]
async fn add_relay_emits_relay_added() {
    let (pool, _db) = make_pool();
    let mut rx = pool.notifications();
    let relay = make_relay().await;

    pool.add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add");

    let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("notification arrives in under a second")
        .expect("notification rx");
    matches!(evt, PoolNotification::RelayAdded { .. });
}

#[tokio::test]
async fn shutdown_emits_shutdown_terminator() {
    let (pool, _db) = make_pool();
    let mut rx = pool.notifications();

    pool.shutdown().await;
    let evt = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("notification arrives in under a second")
        .expect("notification rx");
    assert!(matches!(evt, PoolNotification::Shutdown));
}
