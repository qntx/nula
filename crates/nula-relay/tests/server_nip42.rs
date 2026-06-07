//! B3 server-side NIP-42 enforcement on the in-process `MockRelay`:
//! real signature + challenge + freshness verification, and the
//! Read / Write / Both gating modes.
//!
//! The sibling `nip42.rs` covers the *client* half (challenge surfaced
//! as a notification, `Relay::authenticate` writing the frame). This
//! file drives a raw WebSocket against the real server to prove the
//! relay verifies the AUTH event and gates the configured operations.

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

use futures::{SinkExt, StreamExt};
use nula_core::message::{ClientMessage, RelayMessage};
use nula_core::nips::nip42;
use nula_core::{Event, EventBuilder, JsonUtil, Keys, RelayUrl, Tag, Timestamp};
use nula_relay::server::{MockRelayBuilder, MockRelayOptions, Nip42Mode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn dev_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("hardcoded valid hex key")
}

fn make_note(label: &str) -> Event {
    EventBuilder::text_note(label)
        .tag(Tag::new(["alt", label]).expect("valid tag"))
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("test event should sign")
}

async fn raw_connect(url: &str) -> WsStream {
    let (ws, _response) = timeout(STEP_TIMEOUT, connect_async(url))
        .await
        .expect("connect resolves within deadline")
        .expect("websocket handshake succeeds");
    ws
}

async fn send_client(ws: &mut WsStream, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).expect("client message serializes");
    ws.send(WsMessage::text(json)).await.expect("frame sends");
}

async fn send_text(ws: &mut WsStream, text: &str) {
    ws.send(WsMessage::text(text.to_owned()))
        .await
        .expect("frame sends");
}

async fn next_relay_msg(ws: &mut WsStream) -> RelayMessage {
    loop {
        let frame = timeout(STEP_TIMEOUT, ws.next())
            .await
            .expect("frame arrives within deadline")
            .expect("stream still open")
            .expect("frame reads cleanly");
        match frame {
            WsMessage::Text(text) => {
                return RelayMessage::from_json(text.as_str()).expect("valid RelayMessage JSON");
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

/// Read the connection-opening `["AUTH", challenge]` frame.
async fn recv_challenge(ws: &mut WsStream) -> String {
    match next_relay_msg(ws).await {
        RelayMessage::Auth(challenge) => challenge,
        other => panic!("expected an AUTH challenge first, got {other:?}"),
    }
}

/// Sign a valid NIP-42 AUTH event for `(relay, challenge)`.
fn auth_reply(relay: &RelayUrl, challenge: &str) -> Event {
    nip42::auth_event(relay, challenge)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("auth event signs")
}

#[tokio::test]
async fn both_mode_gates_reads_and_writes_until_authenticated() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().nip42_mode(Nip42Mode::Both))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let relay_url = relay.url().clone();

    let mut ws = raw_connect(relay_url.as_str()).await;
    let challenge = recv_challenge(&mut ws).await;

    // Reads are blocked before auth.
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Closed { message, .. } => assert!(
            message.starts_with("auth-required:"),
            "expected auth-required, got: {message}"
        ),
        other => panic!("expected CLOSED before auth, got {other:?}"),
    }

    // A valid AUTH event flips the connection to authenticated.
    let event = auth_reply(&relay_url, &challenge);
    let event_id = event.id;
    send_client(&mut ws, &ClientMessage::Auth(event)).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id: id,
            accepted,
            ..
        } => {
            assert_eq!(id, event_id);
            assert!(accepted, "valid AUTH must be accepted");
        }
        other => panic!("expected OK for AUTH, got {other:?}"),
    }

    // Reads now succeed (empty store -> immediate EOSE).
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;
    assert!(
        matches!(
            next_relay_msg(&mut ws).await,
            RelayMessage::EndOfStoredEvents(_)
        ),
        "authenticated REQ should reach EOSE"
    );
}

#[tokio::test]
async fn rejects_auth_with_wrong_challenge() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().nip42_mode(Nip42Mode::Both))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let relay_url = relay.url().clone();

    let mut ws = raw_connect(relay_url.as_str()).await;
    let _challenge = recv_challenge(&mut ws).await;

    // Sign against a challenge the relay never issued.
    let event = auth_reply(&relay_url, "not-the-real-challenge");
    send_client(&mut ws, &ClientMessage::Auth(event)).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            accepted, message, ..
        } => {
            assert!(!accepted, "mismatched challenge must be rejected");
            assert!(
                message.starts_with("restricted:"),
                "expected restricted reason, got: {message}"
            );
        }
        other => panic!("expected OK false for bad AUTH, got {other:?}"),
    }
}

#[tokio::test]
async fn read_mode_allows_writes_without_auth() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().nip42_mode(Nip42Mode::Read))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;
    let _challenge = recv_challenge(&mut ws).await;

    // EVENT is permitted without auth in Read mode.
    send_client(&mut ws, &ClientMessage::Event(make_note("read-mode"))).await;
    assert!(
        matches!(
            next_relay_msg(&mut ws).await,
            RelayMessage::Ok { accepted: true, .. }
        ),
        "writes must be accepted without auth in Read mode"
    );

    // REQ is still gated.
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Closed { message, .. } => assert!(
            message.starts_with("auth-required:"),
            "expected auth-required for read, got: {message}"
        ),
        other => panic!("expected CLOSED for unauth read, got {other:?}"),
    }
}

#[tokio::test]
async fn write_mode_allows_reads_without_auth() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().nip42_mode(Nip42Mode::Write))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;
    let _challenge = recv_challenge(&mut ws).await;

    // REQ is permitted without auth in Write mode.
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;
    assert!(
        matches!(
            next_relay_msg(&mut ws).await,
            RelayMessage::EndOfStoredEvents(_)
        ),
        "reads must be served without auth in Write mode"
    );

    // EVENT is still gated.
    send_client(&mut ws, &ClientMessage::Event(make_note("write-mode"))).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            accepted, message, ..
        } => {
            assert!(!accepted, "writes must be gated in Write mode");
            assert!(
                message.starts_with("auth-required:"),
                "expected auth-required for write, got: {message}"
            );
        }
        other => panic!("expected OK false for unauth write, got {other:?}"),
    }
}
