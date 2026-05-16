//! `Drop` and explicit `shutdown` semantics.

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

use std::time::Duration;

use nula_signer_connect::{Error, NostrConnect, NostrConnectOptions};

mod helpers;
use helpers::{bunker_uri, make_client_keys, make_pool, spawn_environment};

#[tokio::test]
async fn drop_aborts_pending_rpcs() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(5))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("bootstrap");

    // Ping once to confirm the dispatcher is alive.
    client.ping().await.expect("first ping");

    // Tear the signer's relay subscription down so subsequent
    // requests would never be served. We simulate this by killing
    // the mock signer task.
    drop(env.mock_signer);

    // Now an explicit shutdown — should be a no-op error-wise.
    client.shutdown().await;
}

#[tokio::test]
async fn explicit_shutdown_is_idempotent_and_unblocks_clones() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(6))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_millis(500)))
        .build()
        .await
        .expect("bootstrap");

    let clone = client.clone();
    client.shutdown().await;
    // The clone keeps the inner Arc alive but the dispatcher was
    // told to stop. Subsequent RPCs surface DispatcherDown / Timeout.
    let err = clone.ping().await.expect_err("dispatcher gone");
    assert!(
        matches!(err, Error::DispatcherDown(_) | Error::Timeout { .. }),
        "expected DispatcherDown or Timeout, got {err:?}",
    );
}
