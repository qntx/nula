//! C2 server-side NIP-70 protected-event enforcement on the in-process
//! `MockRelay`. A `["-"]` event may only be published by its author,
//! authenticated via NIP-42 — even on a relay that does not otherwise
//! require authentication.

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
use nula_core::{Event, EventBuilder, JsonUtil, Keys, RelayUrl, Timestamp};
use nula_relay::server::{MockRelayBuilder, MockRelayOptions, Nip42Mode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn author_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("hardcoded valid hex key")
}

fn other_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
        .expect("hardcoded valid hex key")
}

fn make_note(label: &str) -> Event {
    EventBuilder::text_note(label)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&author_keys())
        .expect("note signs")
}

fn make_protected_note(label: &str, keys: &Keys) -> Event {
    EventBuilder::text_note(label)
        .protected()
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(keys)
        .expect("protected note signs")
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

async fn recv_challenge(ws: &mut WsStream) -> String {
    match next_relay_msg(ws).await {
        RelayMessage::Auth(challenge) => challenge,
        other => panic!("expected an AUTH challenge first, got {other:?}"),
    }
}

fn auth_reply_with(relay: &RelayUrl, challenge: &str, keys: &Keys) -> Event {
    nip42::auth_event(relay, challenge)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(keys)
        .expect("auth event signs")
}

#[tokio::test]
async fn open_relay_requires_author_auth_for_protected_event() {
    // Default options = NIP-42 Disabled, so no challenge is issued on
    // open: NIP-70 must still gate protected events on demand.
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let relay_url = relay.url().clone();

    let mut ws = raw_connect(relay_url.as_str()).await;

    // Unauthenticated protected publish -> AUTH challenge + auth-required.
    let protected = make_protected_note("secret", &author_keys());
    let protected_id = protected.id;
    send_client(&mut ws, &ClientMessage::Event(protected.clone())).await;

    let challenge = match next_relay_msg(&mut ws).await {
        RelayMessage::Auth(challenge) => challenge,
        other => panic!("expected on-demand AUTH challenge, got {other:?}"),
    };
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id,
            accepted,
            message,
        } => {
            assert_eq!(event_id, protected_id);
            assert!(!accepted, "protected event must be refused before auth");
            assert!(
                message.starts_with("auth-required:"),
                "expected auth-required, got: {message}"
            );
        }
        other => panic!("expected OK false, got {other:?}"),
    }

    // Authenticate as the author, then the same event is accepted.
    let auth = auth_reply_with(&relay_url, &challenge, &author_keys());
    send_client(&mut ws, &ClientMessage::Auth(auth)).await;
    assert!(
        matches!(
            next_relay_msg(&mut ws).await,
            RelayMessage::Ok { accepted: true, .. }
        ),
        "valid author AUTH must be accepted"
    );

    send_client(&mut ws, &ClientMessage::Event(protected)).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id, accepted, ..
        } => {
            assert_eq!(event_id, protected_id);
            assert!(accepted, "author-authenticated protected event is accepted");
        }
        other => panic!("expected OK true, got {other:?}"),
    }
}

#[tokio::test]
async fn protected_event_from_non_author_is_blocked() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().nip42_mode(Nip42Mode::Both))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let relay_url = relay.url().clone();

    let mut ws = raw_connect(relay_url.as_str()).await;
    let challenge = recv_challenge(&mut ws).await;

    // Authenticate as one identity...
    let auth = auth_reply_with(&relay_url, &challenge, &author_keys());
    send_client(&mut ws, &ClientMessage::Auth(auth)).await;
    assert!(matches!(
        next_relay_msg(&mut ws).await,
        RelayMessage::Ok { accepted: true, .. }
    ));

    // ...then try to publish a protected event authored by another.
    let foreign = make_protected_note("not mine", &other_keys());
    let foreign_id = foreign.id;
    send_client(&mut ws, &ClientMessage::Event(foreign)).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id,
            accepted,
            message,
        } => {
            assert_eq!(event_id, foreign_id);
            assert!(!accepted, "a non-author must not publish a protected event");
            assert!(
                message.starts_with("blocked:"),
                "expected blocked, got: {message}"
            );
        }
        other => panic!("expected OK false blocked, got {other:?}"),
    }
}

#[tokio::test]
async fn unprotected_event_is_unaffected() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;
    send_client(&mut ws, &ClientMessage::Event(make_note("public"))).await;
    assert!(
        matches!(
            next_relay_msg(&mut ws).await,
            RelayMessage::Ok { accepted: true, .. }
        ),
        "ordinary events must not be gated by NIP-70"
    );
}
