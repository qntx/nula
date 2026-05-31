//! End-to-end: a real [`NostrConnect`] client driving a real
//! [`NostrConnectRemoteSigner`] bunker over a `MockRelay`.

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

use nula_core::nips::nip46::Request;
use nula_core::{EventBuilder, Keys, PublicKey};
use nula_relay::pool::RelayPool;
use nula_relay::server::MockRelayBuilder;
use nula_signer::bunker::{BunkerPolicy, NostrConnectKeys, NostrConnectRemoteSigner};
use nula_signer::{NostrConnect, NostrConnectOptions};
use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;

fn make_pool() -> RelayPool {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    RelayPool::builder()
        .database(db)
        .build()
        .expect("database supplied to builder")
}

fn opts() -> NostrConnectOptions {
    NostrConnectOptions::default().timeout(Duration::from_secs(3))
}

#[tokio::test]
async fn client_round_trips_against_bunker() {
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let url = server.url().clone();
    let user = Keys::generate().expect("generate user keys");

    let bunker = NostrConnectRemoteSigner::builder()
        .keys(NostrConnectKeys::new(user.clone()))
        .relay(url.clone())
        .embedded_pool(make_pool())
        .serve()
        .await
        .expect("serve bunker");
    assert_eq!(bunker.user_public_key(), *user.public_key());

    let client = NostrConnect::builder()
        .uri(bunker.bunker_uri())
        .embedded_pool(make_pool())
        .options(opts())
        .build()
        .await
        .expect("client bootstrap");

    // get_public_key resolves to the bunker's *user* key.
    let pk = client.get_public_key().await.expect("get_public_key");
    assert_eq!(pk, *user.public_key());

    // ping round-trips.
    client.ping().await.expect("ping");

    // sign_event is performed remotely and returns a valid signature.
    let unsigned = EventBuilder::text_note("hello via bunker")
        .build_unsigned(*user.public_key())
        .expect("build unsigned");
    let signed = client.sign_event(unsigned).await.expect("sign_event");
    signed.verify().expect("valid signature");
    assert_eq!(signed.pubkey, *user.public_key());
    assert_eq!(signed.content, "hello via bunker");
}

#[derive(Debug)]
struct DenySigning;

impl BunkerPolicy for DenySigning {
    fn approve(&self, _client: &PublicKey, request: &Request) -> bool {
        !matches!(request, Request::SignEvent(_))
    }
}

#[tokio::test]
async fn policy_can_reject_sign_event() {
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let url = server.url().clone();
    let user = Keys::generate().expect("generate user keys");

    let bunker = NostrConnectRemoteSigner::builder()
        .keys(NostrConnectKeys::new(user.clone()))
        .relay(url.clone())
        .embedded_pool(make_pool())
        .policy(DenySigning)
        .serve()
        .await
        .expect("serve bunker");

    let client = NostrConnect::builder()
        .uri(bunker.bunker_uri())
        .embedded_pool(make_pool())
        .options(opts())
        .build()
        .await
        .expect("client bootstrap");

    // `get_public_key` is allowed by the policy.
    let pk = client.get_public_key().await.expect("get_public_key");
    assert_eq!(pk, *user.public_key());

    // `sign_event` is rejected by the policy.
    let unsigned = EventBuilder::text_note("should be rejected")
        .build_unsigned(*user.public_key())
        .expect("build unsigned");
    let err = client
        .sign_event(unsigned)
        .await
        .expect_err("policy rejects signing");
    assert!(
        matches!(err, nula_signer::Error::Rejected { .. }),
        "got {err:?}"
    );
}
