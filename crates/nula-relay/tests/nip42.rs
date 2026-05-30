//! NIP-42 AUTH challenge tests. Compiled only when the `nip42`
//! feature is on.

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

use std::sync::Arc;
use std::time::Duration;

use nula_core::message::ClientMessage;
use nula_core::{EventBuilder, Keys, Kind, RelayUrl, Tag, Timestamp};
use nula_relay::transport::Message;
use nula_relay::transport::mock::MockTransport;
use nula_relay::{Relay, RelayNotification};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.test.example").expect("valid relay URL")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_challenge_surfaces_as_notification_and_authenticate_writes_frame() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(transport)
        .build()
        .expect("transport supplied to builder");
    let mut notifications = relay
        .notifications()
        .expect("notification stream available");

    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });
    let mut handle = subscriber.recv().await.expect("handle");
    connect.await.expect("join").expect("connect ok");

    // Drain status notifications until we reach Connected.
    while let Some(n) = notifications.recv().await {
        if matches!(
            n,
            RelayNotification::Status(nula_relay::RelayStatus::Connected)
        ) {
            break;
        }
    }

    // Server-side AUTH challenge.
    handle
        .push_inbound(Message::Text(r#"["AUTH","challenge-string"]"#.to_owned()))
        .expect("push auth");

    let challenge = loop {
        let n = timeout(STEP_TIMEOUT, notifications.recv())
            .await
            .expect("notification arrives")
            .expect("stream open");
        if let RelayNotification::AuthChallenge { challenge } = n {
            break challenge;
        }
    };
    assert_eq!(challenge, "challenge-string");

    // Reply with a signed kind-22242 event.
    let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("valid key");
    let event = EventBuilder::new(Kind::new(22242), "")
        .tag(Tag::new(["relay", endpoint.as_str()]).expect("tag"))
        .tag(Tag::new(["challenge", &challenge]).expect("tag"))
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&keys)
        .expect("sign succeeds");

    relay
        .authenticate(event.clone())
        .await
        .expect("authenticate succeeds");

    // The mock peer must have observed an AUTH wire frame.
    let outbound = timeout(STEP_TIMEOUT, handle.next_outbound())
        .await
        .expect("auth frame arrives")
        .expect("outbound channel open");
    let Message::Text(raw) = outbound else {
        panic!("expected text frame, got {outbound:?}");
    };
    let parsed: ClientMessage = serde_json::from_str(&raw).expect("client message");
    match parsed {
        ClientMessage::Auth(auth_event) => assert_eq!(auth_event.id, event.id),
        other => panic!("expected Auth, got {other:?}"),
    }
}
