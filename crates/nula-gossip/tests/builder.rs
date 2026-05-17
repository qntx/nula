//! Regression coverage for [`nula_gossip::GossipBuilder`] misconfiguration
//! paths. The builder used to `panic!` on a missing database; Phase 6.1
//! turned it into a typed error.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use nula_gossip::{Error, Gossip};

#[test]
fn build_without_database_returns_missing_database() {
    let err = Gossip::builder()
        .build()
        .expect_err("missing database must be reported as an error");

    assert!(
        matches!(err, Error::MissingDatabase),
        "expected Error::MissingDatabase, got {err:?}"
    );
}
