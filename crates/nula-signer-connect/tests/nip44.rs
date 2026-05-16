//! NIP-44 v2 round-trip through the remote signer.

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

use nula_core::Keys;
use nula_core::nips::nip44;
use nula_signer_connect::{NostrConnect, NostrConnectOptions};

mod helpers;
use helpers::{bunker_uri, make_client_keys, make_pool, spawn_environment};

#[tokio::test]
async fn nip44_encrypt_then_decrypt_through_signer() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();
    let peer = Keys::parse("0000000000000000000000000000000000000000000000000000000000000088")
        .expect("hardcoded hex");

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(4))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("bootstrap");

    // Encrypt a message to the peer via the signer.
    let cipher = client
        .nip44_encrypt(peer.public_key(), "hello over nip-44")
        .await
        .expect("nip44_encrypt");
    // Verify the peer can decrypt it locally with their own secret
    // key — proves the signer encrypted to the right peer.
    let plain =
        nip44::decrypt(peer.secret_key(), env.user_keys.public_key(), &cipher).expect("decrypt");
    assert_eq!(plain, "hello over nip-44");

    // Now flip the direction: peer encrypts to the user, signer
    // decrypts on the user's behalf.
    let outbound =
        nip44::encrypt(peer.secret_key(), env.user_keys.public_key(), "ping").expect("encrypt");
    let recovered = client
        .nip44_decrypt(peer.public_key(), &outbound)
        .await
        .expect("nip44_decrypt");
    assert_eq!(recovered, "ping");
}
