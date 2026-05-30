//! Conformance against the shared [`nula_storage_test_suite`].

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
use nula_storage::sqlite::SqliteDatabase;
use nula_storage::test_suite::{DatabaseFactory, run_suite};
use tempfile::TempDir;

struct SqliteFactory;

impl DatabaseFactory for SqliteFactory {
    /// Hold the `TempDir` for the case's lifetime so the `SQLite`
    /// file outlives every async write.
    type Guard = TempDir;

    async fn build(&self) -> (Arc<dyn NostrDatabase>, Self::Guard) {
        let tmp = tempfile::tempdir().expect("tempdir creation");
        let path = tmp.path().join("events.sqlite");
        let db = SqliteDatabase::open(&path).await.expect("open sqlite");
        (Arc::new(db), tmp)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance() {
    run_suite(&SqliteFactory).await;
}
