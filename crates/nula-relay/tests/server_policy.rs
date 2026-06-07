//! B6 author-restricted relay: the built-in `AuthorAllowlist`
//! `WritePolicy` admits events from allowlisted authors and blocks
//! every other author with a `blocked:` reason.

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

use std::sync::Arc;
use std::time::Duration;

use nula_core::{EventBuilder, Keys, Timestamp};
use nula_relay::pool::RelayCapabilities;
use nula_relay::server::{AuthorAllowlist, MockRelayBuilder};

mod helpers;
use helpers::make_pool;

fn allowed_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("hardcoded valid hex key")
}

#[tokio::test]
async fn author_allowlist_admits_allowed_and_blocks_others() {
    let allowed = allowed_keys();
    let blocked = Keys::generate().expect("generate throwaway key");

    let policy = Arc::new(AuthorAllowlist::new([*allowed.public_key()]));
    let relay = MockRelayBuilder::new()
        .write_policy(policy)
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let (pool, _db) = make_pool();
    pool.add_relay(relay.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add relay");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    // An event from the allowlisted author is persisted.
    let ok_event = EventBuilder::text_note("allowed")
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&allowed)
        .expect("sign allowed event");
    let ok_id = ok_event.id;
    pool.send_event(ok_event).await.expect("send allowed event");
    assert!(
        relay
            .database()
            .event_by_id(&ok_id)
            .await
            .expect("query allowed")
            .is_some(),
        "allowlisted author event must persist"
    );

    // An event from a non-allowlisted author is rejected before storage.
    let bad_event = EventBuilder::text_note("blocked")
        .created_at(Timestamp::from_secs(1_700_000_001))
        .sign_with_keys(&blocked)
        .expect("sign blocked event");
    let bad_id = bad_event.id;
    // The relay rejects this; the pool may surface it as an error or a
    // per-relay failure. The ground truth is that it is never stored.
    let _outcome = pool.send_event(bad_event).await;
    assert!(
        relay
            .database()
            .event_by_id(&bad_id)
            .await
            .expect("query blocked")
            .is_none(),
        "non-allowlisted author event must be rejected"
    );
}
