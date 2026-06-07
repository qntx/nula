//! B7 test fault injection on the in-process `MockRelay`:
//! `unresponsive` (never replies to NIP-01 frames) and
//! `send_random_events` (answers every `REQ` with random events).
//!
//! These knobs exist to exercise client resilience paths and are
//! deliberately off by default.

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
use nula_core::message::RelayMessage;
use nula_relay::server::{MockRelayBuilder, MockRelayOptions};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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

async fn next_relay_msg(ws: &mut WsStream) -> RelayMessage {
    loop {
        let frame = timeout(STEP_TIMEOUT, ws.next())
            .await
            .expect("frame arrives within deadline")
            .expect("stream still open")
            .expect("frame reads cleanly");
        match frame {
            WsMessage::Text(text) => {
                return serde_json::from_str(text.as_str()).expect("valid RelayMessage JSON");
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn unresponsive_relay_never_replies() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().unresponsive(true))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;

    // The relay swallows the REQ; nothing should come back.
    let result = timeout(Duration::from_millis(500), ws.next()).await;
    assert!(
        result.is_err(),
        "an unresponsive relay must not reply to a REQ"
    );
}

#[tokio::test]
async fn send_random_events_streams_n_then_eose() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().send_random_events(3))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;
    send_text(&mut ws, r#"["REQ","sub",{}]"#).await;

    let mut events = 0_usize;
    loop {
        match next_relay_msg(&mut ws).await {
            RelayMessage::Event { .. } => events += 1,
            RelayMessage::EndOfStoredEvents(_) => break,
            other => panic!("unexpected frame during fault stream: {other:?}"),
        }
    }
    assert_eq!(events, 3, "fault mode must stream exactly 3 random events");
}
