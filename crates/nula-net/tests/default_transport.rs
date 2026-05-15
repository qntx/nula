//! End-to-end test: drive `DefaultTransport` against a localhost
//! echo server speaking `tokio-tungstenite` directly.
//!
//! Each test is wrapped in a `tokio::time::timeout` deadline so a
//! protocol bug never wedges CI. The echo server's task handle is
//! `abort()`-ed on tear-down to avoid leaking a tokio task that
//! `await`s on a half-open socket.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files in this crate"
)]
#![allow(
    clippy::expect_used,
    clippy::excessive_nesting,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nula_core::RelayUrl;
use nula_net::default::DefaultTransport;
use nula_net::{ConnectionMode, Message, WebSocketTransport};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message as TgMessage;

/// 5-second deadline applied to every async step. CI typically
/// completes the round-trip in <50ms; the deadline only fires when a
/// regression introduces a hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a single-connection echo server bound to a random localhost
/// port. The server task accepts exactly one client, echoes every
/// `Text`/`Binary` frame back, replies to pings, and exits on a
/// `Close` frame or stream EOF.
async fn spawn_echo_server() -> (RelayUrl, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("local addr");
    let url = RelayUrl::parse(format!("ws://{addr}")).expect("valid relay URL");

    let task = tokio::spawn(async move {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(mut ws) = accept_async(stream).await else {
            return;
        };
        while let Some(frame) = ws.next().await {
            let Ok(msg) = frame else { return };
            match msg {
                TgMessage::Text(_) | TgMessage::Binary(_) => {
                    if ws.send(msg).await.is_err() {
                        return;
                    }
                }
                TgMessage::Ping(p) => {
                    if ws.send(TgMessage::Pong(p)).await.is_err() {
                        return;
                    }
                }
                TgMessage::Close(_) => return,
                TgMessage::Pong(_) | TgMessage::Frame(_) => {}
            }
        }
    });

    (url, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_frame_round_trip() {
    let (url, server) = spawn_echo_server().await;

    let result = timeout(STEP_TIMEOUT, async move {
        let transport = DefaultTransport::new();
        let (mut sink, mut stream) = transport
            .connect(&url, &ConnectionMode::Direct)
            .await
            .expect("connect succeeds");

        sink.send(Message::text("hello")).await.expect("send");
        let echoed = stream.next().await.expect("frame slot").expect("frame ok");
        assert_eq!(echoed, Message::text("hello"));

        sink.send(Message::close()).await.expect("close");
        sink.close().await.expect("close half-flush");
    })
    .await;

    server.abort();
    result.expect("test completed within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_frame_round_trip() {
    let (url, server) = spawn_echo_server().await;

    let result = timeout(STEP_TIMEOUT, async move {
        let transport = DefaultTransport::new();
        let (mut sink, mut stream) = transport
            .connect(&url, &ConnectionMode::Direct)
            .await
            .expect("connect succeeds");

        let payload = (0u8..=255).collect::<Vec<_>>();
        sink.send(Message::binary(payload.clone()))
            .await
            .expect("send");
        let echoed = stream.next().await.expect("frame slot").expect("frame ok");
        assert_eq!(echoed, Message::Binary(payload));

        sink.send(Message::close()).await.expect("close");
        sink.close().await.expect("close half-flush");
    })
    .await;

    server.abort();
    result.expect("test completed within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supports_ping_returns_true() {
    let transport = DefaultTransport::new();
    assert!(WebSocketTransport::supports_ping(&transport));
}
