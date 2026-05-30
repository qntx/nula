//! Drop and shutdown semantics.

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

use nula_relay::pool::{Error, RelayCapabilities};

mod helpers;
use helpers::{make_pool, make_relay};

#[tokio::test]
async fn explicit_shutdown_is_idempotent() {
    let (pool, _db) = make_pool();
    let relay = make_relay().await;
    pool.add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add");

    pool.shutdown().await;
    pool.shutdown().await;
    pool.shutdown().await;
    assert!(pool.is_shutdown());
}

#[tokio::test]
async fn operations_after_shutdown_error() {
    let (pool, _db) = make_pool();
    let relay = make_relay().await;

    pool.shutdown().await;
    let err = pool
        .add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect_err("post-shutdown add fails");
    assert!(matches!(err, Error::Shutdown));
}
