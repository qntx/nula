//! Round-trip tests for the `mock` transport. These don't open a
//! socket: every frame travels through tokio mpsc channels owned by
//! the test body via `MockHandle`.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve other test files in this crate"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nula_core::RelayUrl;
use nula_net::mock::MockTransport;
use nula_net::{ConnectionMode, IntoWebSocketTransport, Message, WebSocketTransport};

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.example.com").expect("valid relay URL")
}

#[tokio::test]
async fn round_trip_text_frame() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let transport_in_task = Arc::clone(&transport);
    let task_url = endpoint.clone();
    let task = tokio::spawn(async move {
        let (mut sink, mut stream) = transport_in_task
            .connect(&task_url, &ConnectionMode::Direct)
            .await
            .expect("mock connect");
        sink.send(Message::text("hello")).await.expect("send");
        stream
            .next()
            .await
            .expect("inbound frame")
            .expect("frame ok")
    });

    let mut handle = subscriber.recv().await.expect("handle from subscriber");
    let outbound = handle.next_outbound().await.expect("outbound frame");
    assert_eq!(outbound, Message::text("hello"));

    handle
        .push_inbound(Message::text("world"))
        .expect("push inbound");

    let received = task.await.expect("task joined");
    assert_eq!(received, Message::text("world"));
}

#[tokio::test]
async fn missing_subscriber_yields_protocol_violation() {
    let transport = MockTransport::new();
    let result = transport.connect(&url(), &ConnectionMode::Direct).await;
    let Err(err) = result else {
        panic!("connect must fail without subscriber");
    };
    assert!(matches!(
        err,
        nula_net::Error::ProtocolViolation { reason } if reason.contains("MockTransport")
    ));
}

#[tokio::test]
async fn inbound_error_surfaces_on_stream() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let transport_in_task = Arc::clone(&transport);
    let task_url = endpoint.clone();
    let task = tokio::spawn(async move {
        let (_sink, mut stream) = transport_in_task
            .connect(&task_url, &ConnectionMode::Direct)
            .await
            .expect("mock connect");
        stream
            .next()
            .await
            .expect("frame slot present")
            .expect_err("expected error frame")
    });

    let handle = subscriber.recv().await.expect("handle");
    handle
        .push_inbound_error(nula_net::Error::ConnectionClosed)
        .expect("push error");

    let err = task.await.expect("task joined");
    assert!(matches!(err, nula_net::Error::ConnectionClosed));
}

#[tokio::test]
async fn into_transport_blanket_accepts_arc_and_value() {
    let value_transport = MockTransport::new();
    let _: Arc<dyn WebSocketTransport> = value_transport.into_transport();

    let arc_transport: Arc<MockTransport> = Arc::new(MockTransport::new());
    let _: Arc<dyn WebSocketTransport> = arc_transport.into_transport();

    let dyn_transport: Arc<dyn WebSocketTransport> = Arc::new(MockTransport::new());
    let _ = dyn_transport.into_transport();
}
