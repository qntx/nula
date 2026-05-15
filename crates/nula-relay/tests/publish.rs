//! Publish tests: OK ack, rejection, timeout, `NotConnected`.

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
use nula_core::{Event, EventBuilder, Keys, RelayUrl, Tag, Timestamp};
use nula_net::Message;
use nula_net::mock::{MockHandle, MockTransport};
use nula_relay::{Error, PublishOptions, Relay};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.test.example").expect("valid relay URL")
}

fn signed_event() -> Event {
    let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("valid key");
    EventBuilder::text_note("publish")
        .tag(Tag::new(["alt", "publish-test"]).expect("valid tag"))
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&keys)
        .expect("sign succeeds")
}

async fn connected_relay() -> (Relay, MockHandle) {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(transport)
        .build();

    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });
    let handle = subscriber.recv().await.expect("handle");
    connect.await.expect("join").expect("connect ok");

    (relay, handle)
}

async fn next_event_id(handle: &mut MockHandle) -> nula_core::EventId {
    let frame = timeout(STEP_TIMEOUT, handle.next_outbound())
        .await
        .expect("EVENT arrived")
        .expect("channel open");
    let Message::Text(raw) = frame else {
        panic!("expected text frame, got {frame:?}");
    };
    let parsed: ClientMessage = serde_json::from_str(&raw).expect("valid client message");
    match parsed {
        ClientMessage::Event(event) => event.id,
        other => panic!("expected Event, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_ok_resolves_to_success() {
    let (relay, mut handle) = connected_relay().await;
    let event = signed_event();

    let publish = tokio::spawn({
        let relay = relay.clone();
        let event = event.clone();
        async move { relay.publish(event, PublishOptions::default()).await }
    });

    let id = next_event_id(&mut handle).await;
    assert_eq!(id, event.id);

    handle
        .push_inbound(Message::Text(format!(r#"["OK","{id}",true,""]"#)))
        .expect("push ok");

    publish.await.expect("join").expect("publish accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_ok_false_yields_publish_rejected() {
    let (relay, mut handle) = connected_relay().await;
    let event = signed_event();

    let publish = tokio::spawn({
        let relay = relay.clone();
        let event = event.clone();
        async move { relay.publish(event, PublishOptions::default()).await }
    });

    let id = next_event_id(&mut handle).await;
    handle
        .push_inbound(Message::Text(format!(
            r#"["OK","{id}",false,"blocked: spam"]"#,
        )))
        .expect("push ok=false");

    let err = publish
        .await
        .expect("join")
        .expect_err("publish must surface rejection");
    match err {
        Error::PublishRejected { event_id, message } => {
            assert_eq!(event_id, event.id);
            assert!(message.contains("blocked"), "message = {message}");
        }
        other => panic!("expected PublishRejected, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_when_disconnected_returns_not_connected() {
    // Build a relay but never connect it.
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let _subscriber = transport.subscribe(&endpoint);
    let relay = Relay::builder(endpoint).transport(transport).build();

    let err = relay
        .publish(signed_event(), PublishOptions::default())
        .await
        .expect_err("publish without connect must fail");
    assert!(matches!(err, Error::NotConnected));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_timeout_fires_when_no_ok_arrives() {
    let (relay, mut handle) = connected_relay().await;
    let event = signed_event();

    let publish = tokio::spawn({
        let relay = relay.clone();
        let event = event.clone();
        async move {
            relay
                .publish(
                    event,
                    PublishOptions::new().timeout(Duration::from_millis(100)),
                )
                .await
        }
    });

    // Drain the EVENT frame so the actor is genuinely waiting.
    let _id = next_event_id(&mut handle).await;

    let err = publish
        .await
        .expect("join")
        .expect_err("publish must time out");
    match err {
        Error::PublishTimeout {
            event_id,
            timeout: t,
        } => {
            assert_eq!(event_id, event.id);
            assert_eq!(t, Duration::from_millis(100));
        }
        other => panic!("expected PublishTimeout, got {other:?}"),
    }
}
