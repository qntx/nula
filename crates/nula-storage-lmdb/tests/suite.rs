//! Conformance against the shared
//! [`nula_storage_test_suite`].
//!
//! Backend-specific edge cases (cross-process persistence, env
//! reopen) live alongside in `persistence.rs` because they exercise
//! behaviour no other backend currently models.

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
use nula_storage_lmdb::LmdbDatabase;
use nula_storage_test_suite::{DatabaseFactory, run_suite};
use tempfile::TempDir;

struct LmdbFactory;

impl DatabaseFactory for LmdbFactory {
    /// Hold the `TempDir` for the case's lifetime so the LMDB env
    /// outlives every async write.
    type Guard = TempDir;

    async fn build(&self) -> (Arc<dyn NostrDatabase>, Self::Guard) {
        let tmp = tempfile::tempdir().expect("tempdir creation");
        let db = LmdbDatabase::builder(tmp.path())
            .build()
            .await
            .expect("open lmdb");
        (Arc::new(db), tmp)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance() {
    run_suite(&LmdbFactory).await;
}
