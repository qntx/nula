//! Shared fixtures for `nula-signer-connect` integration tests.
//!
//! The centerpiece is [`MockSigner`] — a self-contained NIP-46
//! "bunker" that subscribes to the rendezvous relay, decrypts every
//! incoming wire payload with NIP-44, dispatches the parsed
//! [`Request`] against the supplied user [`Keys`], and publishes the
//! reply back. The implementation deliberately mirrors the protocol
//! encoder/decoder shipped in `nula_core::nips::nip46` so the tests
//! exercise the round-trip rather than a hand-coded mock surface.

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

use futures::StreamExt as _;
use nula_core::event::Tag;
use nula_core::nips::nip46::{
    KIND as NOSTR_CONNECT_KIND, Message, Request, Response, ResponseResult, Uri,
};
use nula_core::nips::{nip44, nip46};
use nula_core::{EventBuilder, Filter, Keys, Kind, PublicKey, RelayUrl};
use nula_relay::SubscribeOptions;
use nula_relay::pool::{RelayCapabilities, RelayPool};
use nula_relay::server::{MockRelay, MockRelayBuilder};
use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;
use tokio::task::JoinHandle;

/// One-stop fixture set returned by [`spawn_environment`].
pub struct Environment {
    pub server: MockRelay,
    pub server_url: RelayUrl,
    pub user_keys: Keys,
    pub mock_signer: MockSigner,
}

/// Stand up a `MockRelay` plus a `MockSigner` that talks to it.
pub async fn spawn_environment() -> Environment {
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let server_url = server.url().clone();
    let user_keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000077")
        .expect("hardcoded user key");

    let mock_signer = MockSigner::spawn(user_keys.clone(), vec![server_url.clone()]).await;
    Environment {
        server,
        server_url,
        user_keys,
        mock_signer,
    }
}

/// Deterministic client keys.
pub fn make_client_keys(seed: u8) -> Keys {
    let mut hex = [b'0'; 64];
    hex[63] = match seed {
        0..=9 => b'0' + seed,
        10..=15 => b'a' + (seed - 10),
        _ => panic!("seed must be 0..=15"),
    };
    let s = std::str::from_utf8(&hex).expect("ascii hex");
    Keys::parse(s).expect("valid hex")
}

/// Build a freshly-allocated [`RelayPool`] backed by an in-memory
/// store.
pub fn make_pool() -> RelayPool {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    RelayPool::builder()
        .database(db)
        .build()
        .expect("database supplied to builder")
}

/// In-process NIP-46 signer.
///
/// Spawns a tokio task that drains `kind:24133` events targeting the
/// signer's pubkey, runs them through the same protocol decoder the
/// production client uses, and publishes a NIP-44-encrypted reply.
#[derive(Debug)]
pub struct MockSigner {
    pub keys: Keys,
    pub relays: Vec<RelayUrl>,
    pool: RelayPool,
    join: JoinHandle<()>,
}

impl MockSigner {
    pub async fn spawn(keys: Keys, relays: Vec<RelayUrl>) -> Self {
        let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
        let pool = RelayPool::builder()
            .database(db)
            .build()
            .expect("database supplied to builder");
        for url in &relays {
            pool.add_relay(
                url.clone(),
                RelayCapabilities::READ | RelayCapabilities::WRITE,
            )
            .await
            .expect("add_relay");
        }
        pool.try_connect(std::time::Duration::from_secs(2)).await;

        let filter = Filter::new()
            .pubkey(*keys.public_key())
            .kind(Kind::new(NOSTR_CONNECT_KIND))
            .limit(0);
        let signer_keys = keys.clone();
        let signer_pool = pool.clone();
        let signer_relays = relays.clone();
        let join = tokio::spawn(async move {
            run_signer_loop(signer_pool, signer_keys, signer_relays, filter).await;
        });

        Self {
            keys,
            relays,
            pool,
            join,
        }
    }

    pub fn url_iter(&self) -> impl Iterator<Item = &RelayUrl> {
        self.relays.iter()
    }
}

impl Drop for MockSigner {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Top-level signer dispatch loop, extracted from the spawn body so
/// the closure stays shallow and clippy's `excessive_nesting`
/// remains satisfied.
async fn run_signer_loop(pool: RelayPool, keys: Keys, relays: Vec<RelayUrl>, filter: Filter) {
    let mut stream = pool
        .stream_events_to(
            relays.clone(),
            vec![filter],
            SubscribeOptions::default(),
            None,
        )
        .await
        .expect("subscribe");
    while let Some((_, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        if event.kind != Kind::new(NOSTR_CONNECT_KIND) {
            continue;
        }
        process_one_event(&pool, &relays, &keys, &event).await;
    }
}

async fn process_one_event(
    pool: &RelayPool,
    relays: &[RelayUrl],
    keys: &Keys,
    event: &nula_core::Event,
) {
    let Ok(plain) = nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content) else {
        return;
    };
    let Ok(envelope) = serde_json::from_str::<Message>(&plain) else {
        return;
    };
    let request_id = envelope.id().to_owned();
    let Ok(typed_request) = envelope.into_request() else {
        return;
    };
    let reply = handle_request(keys, typed_request);
    publish_reply(pool, relays, keys, &event.pubkey, &request_id, reply).await;
}

fn handle_request(keys: &Keys, request: Request) -> Response {
    match request {
        Request::Connect { secret, .. } => connect_response(secret),
        Request::GetPublicKey => {
            Response::with_result(ResponseResult::GetPublicKey(*keys.public_key()))
        }
        Request::SignEvent(unsigned) => match unsigned.sign_with_keys(keys) {
            Ok(event) => Response::with_result(ResponseResult::SignEvent(Box::new(event))),
            Err(e) => Response::with_error(format!("sign failed: {e}")),
        },
        Request::Ping => Response::with_result(ResponseResult::Pong),
        Request::SwitchRelays => Response::with_result(ResponseResult::SwitchRelays(None)),
        Request::Nip44Encrypt { peer, text } => {
            match nip44::encrypt(keys.secret_key(), &peer, &text) {
                Ok(c) => Response::with_result(ResponseResult::Nip44Encrypt(c)),
                Err(e) => Response::with_error(format!("nip44_encrypt failed: {e}")),
            }
        }
        Request::Nip44Decrypt { peer, ciphertext } => {
            match nip44::decrypt(keys.secret_key(), &peer, &ciphertext) {
                Ok(p) => Response::with_result(ResponseResult::Nip44Decrypt(p)),
                Err(e) => Response::with_error(format!("nip44_decrypt failed: {e}")),
            }
        }
        #[cfg(feature = "nip04")]
        Request::Nip04Encrypt { peer, text } => {
            match nula_core::nips::nip04::encrypt(keys.secret_key(), &peer, &text) {
                Ok(c) => Response::with_result(ResponseResult::Nip04Encrypt(c)),
                Err(e) => Response::with_error(format!("nip04_encrypt failed: {e}")),
            }
        }
        #[cfg(feature = "nip04")]
        Request::Nip04Decrypt { peer, ciphertext } => {
            match nula_core::nips::nip04::decrypt(keys.secret_key(), &peer, &ciphertext) {
                Ok(p) => Response::with_result(ResponseResult::Nip04Decrypt(p)),
                Err(e) => Response::with_error(format!("nip04_decrypt failed: {e}")),
            }
        }
        #[cfg(not(feature = "nip04"))]
        Request::Nip04Encrypt { .. } | Request::Nip04Decrypt { .. } => {
            Response::with_error("nip04 disabled".to_owned())
        }
        // `Request` is `#[non_exhaustive]`. New variants from a
        // future spec extension fall through as a structured error
        // rather than a panic.
        _ => Response::with_error("unsupported method".to_owned()),
    }
}

fn connect_response(secret: Option<String>) -> Response {
    // For the bunker:// flow without a secret we ack; for both
    // bunker and nostrconnect *with* secret we echo it verbatim,
    // which the dispatcher uses as the anti-spoofing latch on
    // `nostrconnect://`.
    secret.map_or_else(
        || Response::with_result(ResponseResult::Ack),
        |s| Response::with_result(ResponseResult::ConnectSecret(s)),
    )
}

async fn publish_reply(
    pool: &RelayPool,
    relays: &[RelayUrl],
    signer_keys: &Keys,
    target_client_pk: &PublicKey,
    request_id: &str,
    reply: Response,
) {
    let envelope = Message::response(request_id.to_owned(), reply);
    let plain = serde_json::to_string(&envelope).expect("encode response");
    let cipher =
        nip44::encrypt(signer_keys.secret_key(), target_client_pk, &plain).expect("encrypt");
    let event = EventBuilder::new(Kind::new(nip46::KIND), cipher)
        .tag(Tag::p(*target_client_pk))
        .sign_with_keys(signer_keys)
        .expect("sign");
    pool.send_event_to(relays.iter().cloned(), event)
        .await
        .expect("send_event");
}

/// Build a bunker URI advertising the supplied signer pubkey on the
/// supplied relay set, with no secret.
pub fn bunker_uri(signer_pk: PublicKey, relay: &RelayUrl) -> Uri {
    Uri::Bunker {
        remote_signer_public_key: signer_pk,
        relays: vec![relay.clone()],
        secret: None,
    }
}

/// Build a bunker URI with a one-shot secret.
pub fn bunker_uri_with_secret(signer_pk: PublicKey, relay: &RelayUrl, secret: &str) -> Uri {
    Uri::Bunker {
        remote_signer_public_key: signer_pk,
        relays: vec![relay.clone()],
        secret: Some(secret.to_owned()),
    }
}

/// Build a `nostrconnect://` URI for the supplied client pubkey.
pub fn client_uri(
    client_pk: PublicKey,
    relay: &RelayUrl,
    secret: &str,
    perms: Vec<nip46::Permission>,
) -> Uri {
    Uri::Client {
        public_key: client_pk,
        relays: vec![relay.clone()],
        metadata: nip46::Metadata::new("nula test"),
        secret: secret.to_owned(),
        perms,
    }
}
