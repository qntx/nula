//! End-to-end test: a `nula::Client` configured with a SOCKS5
//! `ConnectionMode` reaches a relay **through** an in-test minimal SOCKS5
//! proxy. This proves the full chain — `ClientBuilder::relay_options` →
//! `RelayPoolOptions::relay_options` → `pool.add_relay` → relay actor →
//! `DefaultTransport` SOCKS5 dial — is wired, not just the transport.
//!
//! The proxy implements just enough of RFC 1928 (no-auth greeting +
//! `CONNECT` with IPv4 / domain `ATYP`, then a transparent byte pipe) to
//! forward the client to a localhost `MockRelay`.

#![allow(
    clippy::expect_used,
    clippy::excessive_nesting,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "integration test: panics/indexing for brevity; not every dev-dep is used here"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use nula::{Client, ConnectionMode, EventBuilder, Filter, Keys, Kind, RelayOptions, Timestamp};
use nula_relay::server::MockRelayBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Deadline on the whole round-trip so a regression cannot wedge CI.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn a minimal SOCKS5 proxy on a random localhost port, forwarding
/// every `CONNECT` to the address the client requests.
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
                drop(handle_socks5(client).await);
            });
        }
    });

    (addr, task)
}

/// Handle one SOCKS5 client: no-auth greeting, a `CONNECT` request, then
/// a transparent bidirectional pipe to the requested target.
async fn handle_socks5(mut client: TcpStream) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?; // select NO-AUTH

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        return Ok(()); // only CONNECT
    }
    let target = read_target(&mut client, req[3]).await?;

    match TcpStream::connect(target.as_str()).await {
        Ok(mut upstream) => {
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        Err(_) => {
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }
    Ok(())
}

/// Read `DST.ADDR:DST.PORT` for the given `ATYP` (IPv4 `0x01` / domain
/// `0x03`) and render it as a `host:port` string.
async fn read_target(client: &mut TcpStream, atyp: u8) -> std::io::Result<String> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            client.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            Ok(format!("{ip}:{}", u16::from_be_bytes([buf[4], buf[5]])))
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
async fn client_routes_through_socks5_proxy() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let (proxy_addr, proxy) = spawn_socks5_proxy().await;
    let relay_url = relay.url().clone();
    let keys = Keys::generate().expect("os rng");
    let author = *keys.public_key();

    let result = timeout(STEP_TIMEOUT, async move {
        // Every relay this client dials — here the one MockRelay — is
        // tunnelled through the SOCKS5 proxy via the pool-wide default.
        let client = Client::builder()
            .signer(keys)
            .relay_options(RelayOptions::new().connection_mode(ConnectionMode::socks5(proxy_addr)))
            .build()
            .expect("client builds");
        client
            .add_relay(relay_url.clone())
            .await
            .expect("add relay through proxy");
        client.connect().await;

        // Publishing + fetching proves the WebSocket reached the relay
        // end-to-end over the proxy tunnel.
        let output = client
            .send_event_builder(
                EventBuilder::text_note("hello over socks5")
                    .created_at(Timestamp::now().expect("system clock")),
            )
            .await
            .expect("publish over proxy");
        assert!(
            output.success.contains(&relay_url),
            "the relay must ack the publish that arrived over SOCKS5; failed={:?}",
            output.failed,
        );

        let events = client
            .fetch_events(
                Filter::new().author(author).kind(Kind::TEXT_NOTE).limit(1),
                Some(Duration::from_secs(5)),
            )
            .await
            .expect("fetch over proxy");
        assert_eq!(events.len(), 1, "exactly the note published over the proxy");
        assert_eq!(
            events.first().expect("non-empty").content,
            "hello over socks5",
        );

        client.shutdown().await;
    })
    .await;

    proxy.abort();
    relay.shutdown();
    result.expect("round-trip completed within deadline");
}
