//! Regression coverage for [`nula_signer_connect::NostrConnectBuilder`]
//! misconfiguration paths. The builder used to `panic!` on a missing
//! URI / pool; Phase 6.1 turned both into typed errors.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use nula_signer_connect::{Error, NostrConnect};

#[tokio::test]
async fn build_without_uri_returns_missing_uri() {
    let err = NostrConnect::builder()
        .build()
        .await
        .expect_err("missing URI must be reported as an error");

    assert!(
        matches!(err, Error::MissingUri),
        "expected Error::MissingUri, got {err:?}"
    );
}

#[tokio::test]
async fn build_without_pool_returns_missing_pool() {
    let uri = "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.example.com"
        .parse()
        .expect("hardcoded valid bunker URI");

    let err = NostrConnect::builder()
        .uri(uri)
        .build()
        .await
        .expect_err("missing pool must be reported as an error");

    assert!(
        matches!(err, Error::MissingPool),
        "expected Error::MissingPool, got {err:?}"
    );
}
