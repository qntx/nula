//! C3 server-side NIP-40 expiration enforcement on the in-process
//! `MockRelay`. An already-expired event is refused up front with the
//! spec reason `blocked: event is expired`; an event whose deadline is
//! still in the future is accepted normally.

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
use nula_core::{Event, EventBuilder, JsonUtil, Keys, Timestamp};
use nula_relay::server::MockRelayBuilder;
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

fn note_expiring_at(deadline: Timestamp) -> Event {
    EventBuilder::text_note("expiring")
        .expiration(deadline)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("event signs")
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

#[tokio::test]
async fn expired_event_is_blocked() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    // Deadline far in the past (1970-01-12) -> already expired.
    let event = note_expiring_at(Timestamp::from_secs(1_000_000));
    let event_id = event.id;
    send_client(&mut ws, &ClientMessage::Event(event)).await;

    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id: id,
            accepted,
            message,
        } => {
            assert_eq!(id, event_id);
            assert!(!accepted, "expired event must be refused");
            assert_eq!(message, "blocked: event is expired");
        }
        other => panic!("expected OK false for expired event, got {other:?}"),
    }
}

#[tokio::test]
async fn future_dated_event_is_accepted() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    let now = Timestamp::now().expect("system clock available").as_secs();
    let event = note_expiring_at(Timestamp::from_secs(now + 3_600));
    let event_id = event.id;
    send_client(&mut ws, &ClientMessage::Event(event)).await;

    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            event_id: id,
            accepted,
            ..
        } => {
            assert_eq!(id, event_id);
            assert!(accepted, "a not-yet-expired event must be accepted");
        }
        other => panic!("expected OK true for future-dated event, got {other:?}"),
    }
}
