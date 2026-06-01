//! End-to-end test: drive `DefaultTransport` with
//! `ConnectionMode::Socks5` through an in-test minimal SOCKS5 proxy that
//! forwards to a localhost WebSocket echo server.
//!
//! The proxy implements just enough of RFC 1928 (no-auth greeting +
//! `CONNECT` with IPv4 / domain `ATYP`, then a transparent byte pipe) to
//! prove the transport's SOCKS5 path negotiates the tunnel and completes
//! a WebSocket round-trip over it. Every async step is bounded by a
//! `tokio::time::timeout` so a regression cannot wedge CI.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files in this crate"
)]
#![allow(
    clippy::expect_used,
    clippy::excessive_nesting,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nula_core::RelayUrl;
use nula_relay::transport::default::DefaultTransport;
use nula_relay::transport::{ConnectionMode, Message, WebSocketTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message as TgMessage;

/// 5-second deadline applied to every async step. CI completes the
/// round-trip in well under this; the deadline only fires on a hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a single-connection WebSocket echo server on a random
/// localhost port. Mirrors `transport_default.rs`.
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

/// Spawn a minimal SOCKS5 proxy on a random localhost port. Accepts any
/// number of clients, each forwarded to the address it `CONNECT`s to.
async fn spawn_socks5_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind socks proxy");
    let addr = listener.local_addr().expect("local addr");

    let task = tokio::spawn(async move {
        loop {
            let Ok((client, _peer)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Best-effort: a malformed handshake just drops the conn.
                drop(handle_socks5(client).await);
            });
        }
    });

    (addr, task)
}

/// Handle one SOCKS5 client: no-auth greeting, a `CONNECT` request, then
/// a transparent bidirectional pipe to the requested target.
async fn handle_socks5(mut client: TcpStream) -> std::io::Result<()> {
    // Greeting: VER, NMETHODS, METHODS[NMETHODS].
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    // Select NO-AUTH (0x00).
    client.write_all(&[0x05, 0x00]).await?;

    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        return Ok(()); // only CONNECT is implemented
    }
    let target = read_target(&mut client, req[3]).await?;

    match TcpStream::connect(target.as_str()).await {
        Ok(mut upstream) => {
            // Success reply, BND.ADDR=0.0.0.0:0 (ATYP IPv4).
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        Err(_) => {
            // General SOCKS server failure.
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }
    Ok(())
}

/// Read the `DST.ADDR:DST.PORT` for the given `ATYP` and render it as a
/// `host:port` string. Supports IPv4 (`0x01`) and domain (`0x03`); the
/// transport sends a literal `127.0.0.1` as IPv4.
async fn read_target(client: &mut TcpStream, atyp: u8) -> std::io::Result<String> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6]; // 4 addr + 2 port
            client.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(format!("{ip}:{port}"))
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let host = String::from_utf8_lossy(&host).into_owned();
            Ok(format!("{host}:{}", u16::from_be_bytes(port)))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported SOCKS5 ATYP in test proxy",
        )),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_frame_round_trip_via_socks5_proxy() {
    let (url, echo) = spawn_echo_server().await;
    let (proxy_addr, proxy) = spawn_socks5_proxy().await;

    let result = timeout(STEP_TIMEOUT, async move {
        let transport = DefaultTransport::new();
        let (mut sink, mut stream) = transport
            .connect(&url, &ConnectionMode::socks5(proxy_addr))
            .await
            .expect("connect through SOCKS5 proxy succeeds");

        sink.send(Message::text("hello via tor"))
            .await
            .expect("send");
        let echoed = stream.next().await.expect("frame slot").expect("frame ok");
        assert_eq!(echoed, Message::text("hello via tor"));

        sink.send(Message::close()).await.expect("close");
        sink.close().await.expect("close half-flush");
    })
    .await;

    echo.abort();
    proxy.abort();
    result.expect("test completed within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_via_unreachable_proxy_errors() {
    // Bind then drop to obtain a localhost addr that refuses connections.
    let dead = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind to reserve a port");
        listener.local_addr().expect("local addr")
    };
    let url = RelayUrl::parse("ws://127.0.0.1:1").expect("valid relay URL");

    let result = timeout(STEP_TIMEOUT, async move {
        let transport = DefaultTransport::new();
        let outcome = transport.connect(&url, &ConnectionMode::socks5(dead)).await;
        assert!(
            outcome.is_err(),
            "connecting through an unreachable SOCKS5 proxy must error, not hang",
        );
    })
    .await;

    result.expect("connect attempt resolved within deadline");
}
