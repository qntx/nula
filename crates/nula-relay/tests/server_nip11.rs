//! C1 NIP-11 relay information document served by the in-process
//! `MockRelay`. A plain HTTP `GET` with `Accept: application/nostr+json`
//! returns the document; the same socket still upgrades to WebSocket
//! for ordinary clients (covered by the sibling test files).

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

use nula_relay::server::{MockRelayBuilder, MockRelayOptions, Nip42Mode, RelayInformation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Issue a raw HTTP `GET` with the NIP-11 `Accept` header and return
/// `(head, body)` split on the blank line.
async fn http_get_nip11(addr: SocketAddr) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect");
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Accept: application/nostr+json\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush request");

    let mut raw = Vec::new();
    timeout(STEP_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .expect("response within deadline")
        .expect("read response");

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("response separates head and body");
    (head.to_owned(), body.to_owned())
}

#[tokio::test]
async fn serves_nip11_document_derived_from_options() {
    let relay = MockRelayBuilder::new()
        .options(
            MockRelayOptions::new()
                .nip42_mode(Nip42Mode::Both)
                .min_pow(20)
                .max_filter_limit(500)
                .max_subid_length(64),
        )
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let (head, body) = http_get_nip11(relay.addr()).await;

    assert!(head.starts_with("HTTP/1.1 200"), "status line: {head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/nostr+json"),
        "content-type header missing: {head}"
    );

    let info: RelayInformation =
        serde_json::from_str(&body).expect("body parses as RelayInformation");
    for nip in [1_u16, 9, 11, 40, 42, 45, 77] {
        assert!(info.supports_nip(nip), "should advertise NIP-{nip}");
    }
    assert!(info.supports_nip(13), "min_pow set should advertise NIP-13");

    let limitation = info.limitation.expect("limitation present");
    assert_eq!(limitation.auth_required, Some(true));
    assert_eq!(limitation.min_pow_difficulty, Some(20));
    assert_eq!(limitation.max_limit, Some(500));
    assert_eq!(limitation.max_subid_length, Some(64));
    assert_eq!(
        limitation.restricted_writes, None,
        "default writes are open"
    );
}

#[tokio::test]
async fn open_relay_does_not_advertise_auth_or_restrictions() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let (_head, body) = http_get_nip11(relay.addr()).await;
    let info: RelayInformation = serde_json::from_str(&body).expect("json");

    let limitation = info.limitation.expect("limitation present");
    assert_eq!(limitation.auth_required, None);
    assert_eq!(limitation.restricted_writes, None);
    assert_eq!(limitation.min_pow_difficulty, None);
    assert!(
        !info.supports_nip(42),
        "auth off should not advertise NIP-42"
    );
}

#[tokio::test]
async fn relay_info_override_is_served_verbatim() {
    let custom = RelayInformation {
        name: Some("Custom Nula Relay".to_owned()),
        description: Some("overridden".to_owned()),
        ..RelayInformation::default()
    };
    let relay = MockRelayBuilder::new()
        .relay_info(custom)
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let (head, body) = http_get_nip11(relay.addr()).await;
    assert!(head.starts_with("HTTP/1.1 200"));

    let info: RelayInformation = serde_json::from_str(&body).expect("json");
    assert_eq!(info.name.as_deref(), Some("Custom Nula Relay"));
    assert_eq!(info.description.as_deref(), Some("overridden"));
}
