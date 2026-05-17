//! Regression coverage for [`nula_relay_pool::RelayPoolBuilder`]
//! misconfiguration paths. Phase 6.1 replaced the previous `panic!`
//! on missing database with a typed [`nula_relay_pool::Error`].

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use nula_relay_pool::{Error, RelayPool};

#[test]
fn build_without_database_returns_missing_database() {
    let err = RelayPool::builder()
        .build()
        .expect_err("missing database must be reported as an error");

    assert!(
        matches!(err, Error::MissingDatabase),
        "expected Error::MissingDatabase, got {err:?}"
    );
}
