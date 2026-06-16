//! Conformance against the shared
//! [`nula_storage_test_suite`].
//!
//! Backend-specific edge cases (capacity eviction, the
//! [`Features::BOUNDED_CAPACITY`] flag) live alongside in
//! `capacity.rs` because they depend on `MemoryDatabase::builder`
//! and have no equivalent on other backends.

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

use std::future::Future;
use std::sync::Arc;

use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;
use nula_storage::test_suite::{DatabaseFactory, run_suite};

struct MemoryFactory;

impl DatabaseFactory for MemoryFactory {
    type Guard = ();

    fn build(&self) -> impl Future<Output = (Arc<dyn NostrDatabase>, Self::Guard)> + Send {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
        std::future::ready((db, ()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance() {
    run_suite(&MemoryFactory).await;
}
