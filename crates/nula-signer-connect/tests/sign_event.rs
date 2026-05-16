//! Sign an event through the [`nula_core::NostrSigner`] trait surface.

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

use nula_core::Kind;
use nula_core::event::EventBuilder;
use nula_core::signer::NostrSigner;
use nula_signer_connect::{NostrConnect, NostrConnectOptions};

mod helpers;
use helpers::{bunker_uri, make_client_keys, make_pool, spawn_environment};

#[tokio::test]
async fn sign_event_via_trait_round_trips() {
    let env = spawn_environment().await;
    let uri = bunker_uri(*env.user_keys.public_key(), &env.server_url);
    let pool = make_pool();

    let client = NostrConnect::builder()
        .uri(uri)
        .client_keys(make_client_keys(3))
        .embedded_pool(pool)
        .options(NostrConnectOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("bootstrap");

    // Erase the concrete type through `Arc<dyn NostrSigner>` to
    // exercise the object-safe path the lower crates rely on.
    let signer: Arc<dyn NostrSigner> = Arc::new(client.clone());

    let user_pk = signer.get_public_key().await.expect("get_public_key");
    assert_eq!(user_pk, *env.user_keys.public_key());

    let unsigned = EventBuilder::new(Kind::TEXT_NOTE, "remote-signed hi")
        .build_unsigned(*env.user_keys.public_key())
        .expect("build_unsigned");
    let event = signer.sign_event(unsigned).await.expect("sign_event");
    event.verify().expect("signature verifies");
    assert_eq!(event.pubkey, *env.user_keys.public_key());
    assert_eq!(event.content, "remote-signed hi");
}
