//! Resource caps and rate limits on the in-process `MockRelay`:
//! `max_subid_length`, `max_filter_limit`, `max_connections` (B4), and
//! the per-connection `RateLimit` (B2).
//!
//! Mirrors upstream `nostr-relay-builder`'s limit knobs. Each cap is
//! opt-in; an un-configured relay stays unbounded (covered by the
//! sibling pool tests, which never set these).

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
use nula_core::{Event, EventBuilder, Keys, Tag, Timestamp};
use nula_relay::server::{MockRelayBuilder, MockRelayOptions, RateLimit};
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
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&dev_keys())
        .expect("test event should sign")
}

/// Open a raw WebSocket client against the relay's `ws://` url.
async fn raw_connect(url: &str) -> WsStream {
    let (ws, _response) = timeout(STEP_TIMEOUT, connect_async(url))
        .await
        .expect("connect resolves within deadline")
        .expect("websocket handshake succeeds");
    ws
}

/// Send a raw text frame.
async fn send_text(ws: &mut WsStream, text: &str) {
    ws.send(WsMessage::text(text.to_owned()))
        .await
        .expect("frame sends");
}

/// Send a typed client message as JSON.
async fn send_client(ws: &mut WsStream, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).expect("client message serializes");
    ws.send(WsMessage::text(json)).await.expect("frame sends");
}

/// Read the next `RelayMessage`, skipping control frames.
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
async fn rejects_subscription_id_above_cap() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().max_subid_length(8))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    // 16 chars: valid per NIP-01 (<= 64) but over the relay's 8-char cap.
    let long_id = "0123456789abcdef";
    send_text(&mut ws, &format!(r#"["REQ","{long_id}",{{}}]"#)).await;

    match next_relay_msg(&mut ws).await {
        RelayMessage::Closed {
            subscription_id,
            message,
        } => {
            assert_eq!(subscription_id.as_str(), long_id);
            assert!(
                message.starts_with("invalid:"),
                "expected an `invalid:` reason, got: {message}"
            );
        }
        other => panic!("expected CLOSED for the over-long sub id, got {other:?}"),
    }
}

#[tokio::test]
async fn clamps_filter_limit_on_req() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().max_filter_limit(2))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    // Seed five distinct notes straight into the shared store.
    for i in 0..5 {
        let event = make_note(&format!("note-{i}"));
        relay
            .database()
            .save_event(&event)
            .await
            .expect("seed event persists");
    }

    let mut ws = raw_connect(relay.url().as_str()).await;
    // Ask for far more than the cap; the relay clamps `limit` to 2.
    send_text(&mut ws, r#"["REQ","sub",{"limit":100}]"#).await;

    let mut events = 0_usize;
    loop {
        match next_relay_msg(&mut ws).await {
            RelayMessage::Event { .. } => events += 1,
            RelayMessage::EndOfStoredEvents(_) => break,
            other => panic!("unexpected frame during REQ stream: {other:?}"),
        }
    }
    assert_eq!(events, 2, "filter limit must clamp the result set to 2");
}

#[tokio::test]
async fn caps_concurrent_connections() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().max_connections(2))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let url = relay.url().as_str().to_owned();

    // Two live connections fill the cap. The accept loop increments the
    // active counter synchronously, so by the time each handshake
    // returns the slot is already taken.
    let c1 = raw_connect(&url).await;
    let _c2 = raw_connect(&url).await;

    // The third is refused: the relay drops the socket before the
    // WebSocket handshake, so the client's connect resolves to an error.
    let third = timeout(STEP_TIMEOUT, connect_async(&url))
        .await
        .expect("third connect attempt resolves within deadline");
    assert!(
        third.is_err(),
        "third connection must be refused while at the cap"
    );

    // Freeing a slot lets a new connection in again.
    drop(c1);
    // Give the per-connection task a moment to run its RAII guard.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _c3 = raw_connect(&url).await;
}

#[tokio::test]
async fn rate_limits_events_per_minute() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().rate_limit(RateLimit {
            notes_per_minute: Some(2),
            reqs_per_minute: None,
        }))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    // The first two distinct EVENTs are accepted.
    for i in 0..2 {
        send_client(
            &mut ws,
            &ClientMessage::Event(make_note(&format!("ok-{i}"))),
        )
        .await;
        assert!(
            matches!(
                next_relay_msg(&mut ws).await,
                RelayMessage::Ok { accepted: true, .. }
            ),
            "event {i} within budget must be accepted"
        );
    }

    // The third trips the per-minute budget before storage.
    send_client(&mut ws, &ClientMessage::Event(make_note("over"))).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Ok {
            accepted, message, ..
        } => {
            assert!(!accepted, "event over budget must be rejected");
            assert!(
                message.starts_with("rate-limited:"),
                "expected rate-limited reason, got: {message}"
            );
        }
        other => panic!("expected OK false over budget, got {other:?}"),
    }
}

#[tokio::test]
async fn rate_limits_reqs_per_minute() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().rate_limit(RateLimit {
            notes_per_minute: None,
            reqs_per_minute: Some(2),
        }))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let mut ws = raw_connect(relay.url().as_str()).await;

    // The first two REQs are served (empty store -> immediate EOSE).
    for i in 0..2 {
        send_text(&mut ws, &format!(r#"["REQ","sub-{i}",{{}}]"#)).await;
        assert!(
            matches!(
                next_relay_msg(&mut ws).await,
                RelayMessage::EndOfStoredEvents(_)
            ),
            "REQ {i} within budget must reach EOSE"
        );
    }

    // The third trips the per-minute budget.
    send_text(&mut ws, r#"["REQ","sub-over",{}]"#).await;
    match next_relay_msg(&mut ws).await {
        RelayMessage::Closed { message, .. } => assert!(
            message.starts_with("rate-limited:"),
            "expected rate-limited reason, got: {message}"
        ),
        other => panic!("expected CLOSED over budget, got {other:?}"),
    }
}
