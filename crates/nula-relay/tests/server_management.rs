//! D1 server-side NIP-86 relay management API (with NIP-98 admin
//! authorization) on the in-process `MockRelay`. Bans applied over the
//! HTTP API take effect immediately on the write path, relay metadata
//! changes surface in the NIP-11 document, and non-admin / unauthorized
//! requests are refused.

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

use std::net::SocketAddr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nula_core::message::{ClientMessage, RelayMessage};
use nula_core::nips::nip86::{self, Method};
use nula_core::nips::nip98;
use nula_core::types::Url;
use nula_core::{Event, EventBuilder, JsonUtil, Keys, Timestamp};
use nula_relay::server::MockRelayBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn admin_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("hardcoded valid hex key")
}

fn author_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000005")
        .expect("hardcoded valid hex key")
}

fn intruder_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
        .expect("hardcoded valid hex key")
}

fn note(label: &str, keys: &Keys) -> Event {
    EventBuilder::text_note(label)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(keys)
        .expect("note signs")
}

/// POST a NIP-86 request signed with a NIP-98 header by `signer`.
/// Returns the HTTP status code and the parsed NIP-86 response.
async fn post_management(
    addr: SocketAddr,
    signer: &Keys,
    request: &nip86::Request,
) -> (u16, nip86::Response) {
    let body = serde_json::to_vec(request).expect("serialize request");

    let url = Url::parse(format!("http://{addr}/")).expect("valid url");
    let auth = nip98::HttpAuthRequest::new(url, nip98::HttpMethod::Post).payload(&body);
    let auth_event = EventBuilder::http_auth(&auth)
        .created_at(Timestamp::now().expect("system clock available"))
        .sign_with_keys(signer)
        .expect("auth event signs");
    let header = nip98::authorization_header(&auth_event).expect("encode auth header");

    send_post(addr, Some(&header), &body).await
}

/// POST a NIP-86 request body with an optional Authorization header.
async fn send_post(addr: SocketAddr, auth: Option<&str>, body: &[u8]) -> (u16, nip86::Response) {
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let mut head = format!(
        "POST / HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n",
        ct = nip86::CONTENT_TYPE,
        len = body.len(),
    );
    if let Some(header) = auth {
        head.push_str("Authorization: ");
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");
    stream.flush().await.expect("flush");

    let mut raw = Vec::new();
    timeout(STEP_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .expect("response within deadline")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (status_line, response_body) = text
        .split_once("\r\n\r\n")
        .expect("response separates head and body");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code in response line");
    let response: nip86::Response =
        serde_json::from_str(response_body).expect("body parses as a NIP-86 response");
    (status, response)
}

async fn raw_connect(url: &str) -> WsStream {
    let (ws, _response) = timeout(STEP_TIMEOUT, connect_async(url))
        .await
        .expect("connect resolves within deadline")
        .expect("websocket handshake succeeds");
    ws
}

/// Publish `event` over a fresh WebSocket and return the `OK` verdict.
async fn publish(url: &str, event: Event) -> (bool, String) {
    let mut ws = raw_connect(url).await;
    let json = serde_json::to_string(&ClientMessage::Event(event)).expect("serialize event");
    ws.send(WsMessage::text(json)).await.expect("frame sends");
    loop {
        let frame = timeout(STEP_TIMEOUT, ws.next())
            .await
            .expect("frame within deadline")
            .expect("stream open")
            .expect("frame reads");
        if let WsMessage::Text(text) = frame {
            match RelayMessage::from_json(text.as_str()).expect("valid RelayMessage") {
                RelayMessage::Ok {
                    accepted, message, ..
                } => return (accepted, message),
                other => panic!("expected OK, got {other:?}"),
            }
        }
    }
}

/// GET the NIP-11 document over a raw HTTP request.
async fn fetch_nip11(addr: SocketAddr) -> nula_relay::server::RelayInformation {
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush");
    let mut raw = Vec::new();
    timeout(STEP_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .expect("response within deadline")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (_head, body) = text.split_once("\r\n\r\n").expect("split response");
    serde_json::from_str(body).expect("body parses as RelayInformation")
}

#[tokio::test]
async fn admin_ban_blocks_publishing_and_lists() {
    let relay = MockRelayBuilder::new()
        .management([*admin_keys().public_key()])
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");
    let url = relay.url().as_str().to_owned();
    let author = *author_keys().public_key();

    // Before any ban, the author can publish.
    let (accepted_before, _) = publish(&url, note("hello", &author_keys())).await;
    assert!(accepted_before, "author should publish before being banned");

    // Admin bans the author.
    let ban = nip86::pubkey_request(&Method::BanPubkey, &author, Some("spam"));
    let (status, response) = post_management(relay.addr(), &admin_keys(), &ban).await;
    assert_eq!(status, 200);
    assert!(!response.is_error(), "ban should succeed: {response:?}");

    // The very next publish from that author is blocked.
    let (accepted, message) = publish(&url, note("again", &author_keys())).await;
    assert!(!accepted, "banned author must be blocked");
    assert!(
        message.starts_with("blocked:"),
        "expected blocked reason, got: {message}"
    );

    // The ban list reflects it.
    let list = nip86::empty_request(&Method::ListBannedPubkeys);
    let (_, list_response) = post_management(relay.addr(), &admin_keys(), &list).await;
    let result = list_response.result.expect("list result present");
    assert!(
        result.to_string().contains(&author.to_hex()),
        "ban list should contain the author: {result}"
    );
}

#[tokio::test]
async fn unauthenticated_request_is_rejected() {
    let relay = MockRelayBuilder::new()
        .management([*admin_keys().public_key()])
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let body = serde_json::to_vec(&nip86::empty_request(&Method::ListBannedPubkeys)).unwrap();
    let (status, response) = send_post(relay.addr(), None, &body).await;
    assert_eq!(status, 401, "missing auth must be unauthorized");
    assert!(response.is_error());
}

#[tokio::test]
async fn non_admin_request_is_rejected() {
    let relay = MockRelayBuilder::new()
        .management([*admin_keys().public_key()])
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    // A valid NIP-98 signature, but the signer is not an admin.
    let request = nip86::empty_request(&Method::ListBannedPubkeys);
    let (status, response) = post_management(relay.addr(), &intruder_keys(), &request).await;
    assert_eq!(status, 401, "non-admin signer must be unauthorized");
    assert!(response.is_error());
}

#[tokio::test]
async fn supportedmethods_lists_known_methods() {
    let relay = MockRelayBuilder::new()
        .management([*admin_keys().public_key()])
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let request = nip86::empty_request(&Method::SupportedMethods);
    let (status, response) = post_management(relay.addr(), &admin_keys(), &request).await;
    assert_eq!(status, 200);
    let result = response.result.expect("result present").to_string();
    assert!(result.contains("banpubkey"), "methods: {result}");
    assert!(result.contains("changerelayname"), "methods: {result}");
}

#[tokio::test]
async fn relay_metadata_change_surfaces_in_nip11() {
    let relay = MockRelayBuilder::new()
        .management([*admin_keys().public_key()])
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    // NIP-86 is advertised once management is enabled.
    let before = fetch_nip11(relay.addr()).await;
    assert!(
        before.supports_nip(86),
        "management relay advertises NIP-86"
    );

    // Admin renames the relay; the change is visible in NIP-11.
    let rename = nip86::string_request(&Method::ChangeRelayName, "Renamed Relay");
    let (status, response) = post_management(relay.addr(), &admin_keys(), &rename).await;
    assert_eq!(status, 200);
    assert!(!response.is_error(), "rename should succeed: {response:?}");

    let after = fetch_nip11(relay.addr()).await;
    assert_eq!(after.name.as_deref(), Some("Renamed Relay"));
}
