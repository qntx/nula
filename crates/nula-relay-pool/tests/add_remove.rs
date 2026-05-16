//! Add / remove / capacity / shutdown semantics for `RelayPool`.

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

use std::num::NonZeroUsize;

use nula_relay_pool::{Error, RelayCapabilities, RelayPool, RelayPoolOptions};

mod helpers;
use helpers::{make_pool, make_relay};

#[tokio::test]
async fn add_relay_inserts_once() {
    let (pool, _db) = make_pool();
    let relay = make_relay().await;

    let inserted = pool
        .add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect("first add succeeds");
    assert!(inserted, "first add returns true");

    let inserted_again = pool
        .add_relay(relay.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("second add merges capabilities");
    assert!(!inserted_again, "duplicate add returns false");

    let snapshot = pool.relays().await;
    assert_eq!(snapshot.len(), 1, "url stays unique in the map");
}

#[tokio::test]
async fn remove_relay_evicts_and_errors_on_missing() {
    let (pool, _db) = make_pool();
    let relay = make_relay().await;

    pool.add_relay(relay.url().clone(), RelayCapabilities::default())
        .await
        .expect("add");
    pool.remove_relay(relay.url(), false).await.expect("remove");

    let err = pool
        .remove_relay(relay.url(), false)
        .await
        .expect_err("second remove should fail");
    assert!(matches!(err, Error::RelayNotFound(_)));
}

#[tokio::test]
async fn capacity_enforced() {
    let opts = RelayPoolOptions::new().max_relays(Some(NonZeroUsize::new(1).expect("1 != 0")));

    let pool = RelayPool::builder()
        .database(std::sync::Arc::new(
            nula_storage_memory::MemoryDatabase::new(),
        ))
        .options(opts)
        .build();

    let r1 = make_relay().await;
    let r2 = make_relay().await;

    pool.add_relay(r1.url().clone(), RelayCapabilities::READ)
        .await
        .expect("first add");
    let err = pool
        .add_relay(r2.url().clone(), RelayCapabilities::READ)
        .await
        .expect_err("over capacity");
    assert!(matches!(err, Error::TooManyRelays { limit: 1 }));
}

#[tokio::test]
async fn add_after_shutdown_errors() {
    let (pool, _db) = make_pool();
    let relay = make_relay().await;

    pool.shutdown().await;
    assert!(pool.is_shutdown());

    let err = pool
        .add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect_err("post-shutdown add should fail");
    assert!(matches!(err, Error::Shutdown));
}

#[tokio::test]
async fn relays_with_capability_filters() {
    let (pool, _db) = make_pool();
    let r_read = make_relay().await;
    let r_write = make_relay().await;

    pool.add_relay(r_read.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add read");
    pool.add_relay(r_write.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add write");

    let readers = pool
        .relays_with_any_capability(RelayCapabilities::READ)
        .await;
    assert_eq!(readers.len(), 1);
    assert!(readers.contains(r_read.url()));

    let writers = pool
        .relays_with_any_capability(RelayCapabilities::WRITE)
        .await;
    assert_eq!(writers.len(), 1);
    assert!(writers.contains(r_write.url()));
}
