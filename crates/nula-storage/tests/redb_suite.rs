//! Conformance against the shared
//! [`nula_storage_test_suite`].
//!
//! Backend-specific edge cases (persistence across handle drop +
//! reopen) live alongside in `redb_persistence.rs` because they
//! exercise behaviour the in-memory backend does not model.

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

use std::sync::Arc;

use nula_storage::NostrDatabase;
use nula_storage::redb::RedbDatabase;
use nula_storage::test_suite::{DatabaseFactory, run_suite};
use tempfile::TempDir;

struct RedbFactory;

impl DatabaseFactory for RedbFactory {
    /// Hold the `TempDir` for the case's lifetime so the redb file
    /// outlives every async write.
    type Guard = TempDir;

    async fn build(&self) -> (Arc<dyn NostrDatabase>, Self::Guard) {
        let tmp = tempfile::tempdir().expect("tempdir creation");
        let db = RedbDatabase::builder(tmp.path().join("events.redb"))
            .build()
            .await
            .expect("open redb");
        (Arc::new(db), tmp)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance() {
    run_suite(&RedbFactory).await;
}
