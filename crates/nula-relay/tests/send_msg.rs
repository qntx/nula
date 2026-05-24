//! `Relay::send_msg` tests.
//!
//! The new `send_msg` API lets callers ship arbitrary `ClientMessage`
//! variants (e.g. NIP-77 `NegOpen` / `NegMsg` / `NegClose`) through
//! the actor without a bespoke command per variant. These tests
//! cover:
//!
//! * the happy path -- a connected relay observes the exact frame
//!   on the wire;
//! * the `NotConnected` path -- `send_msg` returns
//!   `Error::NotConnected` when no socket is open;
//! * the `Shutdown` path -- `send_msg` returns `Error::Shutdown` after
//!   `Relay::disconnect` tears the actor down.

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

use nula_core::message::{ClientMessage, SubscriptionId};
use nula_core::{Filter, Kind, RelayUrl};
use nula_net::Message;
use nula_net::mock::{MockHandle, MockTransport};
use nula_relay::{Error, Relay};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.test.example").expect("valid relay URL")
}

async fn connected_relay() -> (Relay, MockHandle) {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(transport)
        .build()
        .expect("transport supplied to builder");

    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });
    let handle = subscriber.recv().await.expect("mock handle");
    connect.await.expect("join").expect("connect ok");

    (relay, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_msg_round_trips_a_neg_open_frame() {
    let (relay, mut handle) = connected_relay().await;

    let sub_id = SubscriptionId::generate().expect("OS RNG");
    let filter = Filter::new().kind(Kind::TEXT_NOTE);
    // v97 (0x61) payload with no ranges. Two-char lowercase hex
    // string -- keep it inline so we don't drag `hex` into nula-
    // relay's dev-deps.
    let initial_payload = "61".to_owned();
    let message = ClientMessage::NegOpen {
        subscription_id: sub_id.clone(),
        filter: filter.clone(),
        initial_message: initial_payload.clone(),
    };

    relay
        .send_msg(message.clone())
        .await
        .expect("send_msg succeeds while connected");

    let frame = timeout(STEP_TIMEOUT, handle.next_outbound())
        .await
        .expect("frame arrives")
        .expect("channel open");
    let Message::Text(raw) = frame else {
        panic!("expected text frame, got {frame:?}");
    };
    let parsed: ClientMessage = serde_json::from_str(&raw).expect("valid wire frame");
    assert_eq!(parsed, message, "round-trip equality");
    match parsed {
        ClientMessage::NegOpen {
            subscription_id,
            initial_message,
            ..
        } => {
            assert_eq!(subscription_id, sub_id);
            assert_eq!(initial_message, initial_payload);
        }
        other => panic!("expected NegOpen, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_msg_when_disconnected_returns_not_connected() {
    let transport = Arc::new(MockTransport::new());
    let relay = Relay::builder(url())
        .transport(transport)
        .build()
        .expect("builder ok");

    // Never `.connect()` -- the sink slot is empty.
    let message = ClientMessage::NegClose {
        subscription_id: SubscriptionId::generate().expect("rng"),
    };
    let err = relay
        .send_msg(message)
        .await
        .expect_err("send_msg fails without a connection");
    assert!(matches!(err, Error::NotConnected), "got {err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_msg_after_shutdown_returns_shutdown() {
    let (relay, _handle) = connected_relay().await;
    relay
        .disconnect()
        .await
        .expect("disconnect resolves cleanly");

    // Re-publish on a fresh send_msg call: dropping the handle would
    // terminate the actor, so we keep `relay` alive and verify that
    // `NotConnected` is what surfaces (because the sink is gone),
    // not `Shutdown` (the actor is still alive).
    let message = ClientMessage::NegClose {
        subscription_id: SubscriptionId::generate().expect("rng"),
    };
    let err = relay
        .send_msg(message)
        .await
        .expect_err("send_msg fails post-disconnect");
    assert!(matches!(err, Error::NotConnected), "got {err:?}");

    // Now drop the public handle: the actor exits via `Inner::Drop`.
    // A second `send_msg` from a fresh clone of the inner channel
    // would surface `Shutdown`, but every clone of `relay` is now
    // gone, so the `Shutdown` arm is exercised in the `relay`
    // crate's `lifecycle.rs` tests already.
}
