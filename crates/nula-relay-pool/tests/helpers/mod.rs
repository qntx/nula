//! Shared fixtures for relay-pool integration tests.
//!
//! Each test binary picks its own subset of helpers; the
//! `dead_code` / `unreachable_pub` allows below silence warnings
//! triggered by binaries that only use a subset.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "different test files exercise different helpers"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "helpers panic on misconfigured fixtures — each panic carries a clear message"
)]

use std::sync::Arc;

use nula_core::{Event, EventBuilder, Keys, Tag, Timestamp};
use nula_relay_builder::{MockRelay, MockRelayBuilder};
use nula_relay_pool::RelayPool;
use nula_storage::NostrDatabase;
use nula_storage_memory::MemoryDatabase;

/// Spin up a fresh `RelayPool` backed by an in-memory database.
#[must_use]
pub fn make_pool() -> (RelayPool, Arc<dyn NostrDatabase>) {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let pool = RelayPool::builder().database(Arc::clone(&db)).build();
    (pool, db)
}

/// Spin up a `MockRelay` with the workspace defaults (in-memory
/// storage, accept-all admit policies).
pub async fn make_relay() -> MockRelay {
    MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay should bind to 127.0.0.1:0")
}

/// A deterministic dev key used by every fixture so two tests in the
/// same process produce reproducible event ids.
#[must_use]
pub fn dev_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("hardcoded valid hex key")
}

/// Build and sign a kind-1 text note with the dev keys plus an
/// `alt` tag carrying the supplied label so multiple events in a
/// single test stay distinguishable.
#[must_use]
pub fn make_text_note(content: &str, alt: &str) -> Event {
    EventBuilder::text_note(content)
        .tag(Tag::new(["alt", alt]).expect("valid tag"))
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("test event should sign")
}
