//! `bunker://` end-to-end: bootstrap, `get_public_key`, ping.

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

use nula_signer_connect::{NostrConnect, NostrConnectOptions};

mod helpers;
use helpers::{bunker_uri, make_client_keys, make_pool, spawn_environment};

#[tokio::test]
async fn bunker_bootstrap_then_get_public_key() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(1))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("bootstrap");

    let user_pk = client.get_public_key().await.expect("get_public_key");
    assert_eq!(user_pk, *env.user_keys.public_key());
}

#[tokio::test]
async fn bunker_ping_round_trips() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(2))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("bootstrap");

    client.ping().await.expect("ping");
}
