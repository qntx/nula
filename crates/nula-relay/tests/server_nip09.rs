//! C6 end-to-end NIP-09 deletion against the in-process `MockRelay`.
//! The storage backend already enforces deletion-author authority; this
//! drives the full relay edge: publish an event, delete it with a
//! `kind:5` request from the same author, and confirm it is gone.

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
use nula_core::nips::nip09::DeletionRequest;
use nula_core::{Event, EventBuilder, EventId, JsonUtil, Keys, Timestamp};
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

fn make_note(label: &str) -> Event {
    EventBuilder::text_note(label)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("note signs")
}

async fn raw_connect(url: &str) -> WsStream {
    let (ws, _response) = timeout(STEP_TIMEOUT, connect_async(url))
        .await
        .expect("connect resolves within deadline")
        .expect("websocket handshake succeeds");
    ws
}

async fn send_text(ws: &mut WsStream, text: &str) {
    ws.send(WsMessage::text(text.to_owned()))
        .await
        .expect("frame sends");
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

async fn expect_ok_accepted(ws: &mut WsStream) {
    match next_relay_msg(ws).await {
        RelayMessage::Ok { accepted: true, .. } => {}
        other => panic!("expected OK true, got {other:?}"),
    }
}

/// Count stored events matching `id`, then close the subscription so the
/// connection can be re-used cleanly.
async fn count_by_id(ws: &mut WsStream, id: EventId) -> usize {
    send_text(ws, &format!(r#"["REQ","q",{{"ids":["{}"]}}]"#, id.to_hex())).await;
    let mut count = 0_usize;
    loop {
        match next_relay_msg(ws).await {
            RelayMessage::Event { .. } => count += 1,
            RelayMessage::EndOfStoredEvents(_) => break,
            other => panic!("unexpected frame during REQ stream: {other:?}"),
        }
    }
    send_text(ws, r#"["CLOSE","q"]"#).await;
    count
}

#[tokio::test]
async fn deletion_request_removes_event() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    // Publish an event and confirm it is queryable.
    let event = make_note("delete me");
    let event_id = event.id;
    send_client(&mut ws, &ClientMessage::Event(event)).await;
    expect_ok_accepted(&mut ws).await;
    assert_eq!(
        count_by_id(&mut ws, event_id).await,
        1,
        "event must be present before deletion"
    );

    // The author publishes a NIP-09 deletion request targeting it.
    let request = DeletionRequest::new()
        .delete_event(event_id)
        .with_reason("oops");
    let deletion = EventBuilder::deletion(&request)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(&dev_keys())
        .expect("deletion event signs");
    send_client(&mut ws, &ClientMessage::Event(deletion)).await;
    expect_ok_accepted(&mut ws).await;

    // The targeted event is gone.
    assert_eq!(
        count_by_id(&mut ws, event_id).await,
        0,
        "event must be removed after the deletion request"
    );
}
