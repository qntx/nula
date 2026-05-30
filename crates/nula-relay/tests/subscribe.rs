//! Subscription tests: REQ wire frame, EVENT delivery, EOSE marker,
//! CLOSED termination, drop-induced CLOSE.

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

use futures::StreamExt;
use nula_core::message::ClientMessage;
use nula_core::{EventBuilder, Filter, Keys, Kind, RelayUrl, SubscriptionId, Tag, Timestamp};
use nula_relay::transport::Message;
use nula_relay::transport::mock::{MockHandle, MockTransport};
use nula_relay::{Relay, SubscribeOptions, SubscriptionItem};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.test.example").expect("valid relay URL")
}

fn signed_event() -> nula_core::Event {
    let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("valid key");
    EventBuilder::text_note("hello")
        .tag(Tag::new(["alt", "test"]).expect("valid tag"))
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&keys)
        .expect("sign succeeds")
}

/// Spawn a connected relay against a fresh mock transport. Returns
/// the relay plus the test-side handle for driving frames.
async fn connected_relay() -> (Relay, MockHandle) {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(transport)
        .build()
        .expect("transport supplied to builder");

    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });

    let handle = subscriber.recv().await.expect("subscriber received handle");
    connect
        .await
        .expect("task joined")
        .expect("connect succeeds");

    (relay, handle)
}

/// Read a `["REQ", id, ...]` frame off the test handle and assert
/// the subscription id matches `expected`.
async fn next_req(handle: &mut MockHandle, expected: &SubscriptionId) -> Vec<Filter> {
    let outbound = timeout(STEP_TIMEOUT, handle.next_outbound())
        .await
        .expect("REQ arrived within deadline")
        .expect("outbound channel open");
    let Message::Text(raw) = outbound else {
        panic!("expected text frame, got {outbound:?}");
    };
    let parsed: ClientMessage = serde_json::from_str(&raw).expect("valid ClientMessage JSON");
    match parsed {
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            assert_eq!(
                &subscription_id, expected,
                "REQ frame carried the wrong subscription id",
            );
            filters
        }
        other => panic!("expected Req, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_emits_req_and_streams_event_eose() {
    let (relay, mut handle) = connected_relay().await;

    let id = SubscriptionId::new("sub-1").expect("valid sub id");
    let mut sub = relay
        .subscribe(
            id.clone(),
            vec![Filter::new().kind(Kind::TEXT_NOTE)],
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe succeeds");

    let _filters = next_req(&mut handle, &id).await;

    let event = signed_event();
    let event_json = serde_json::to_string(&event).expect("event json");
    handle
        .push_inbound(Message::Text(format!(r#"["EVENT","sub-1",{event_json}]"#)))
        .expect("push event");
    handle
        .push_inbound(Message::Text(r#"["EOSE","sub-1"]"#.to_owned()))
        .expect("push eose");

    let first = timeout(STEP_TIMEOUT, sub.next())
        .await
        .expect("event arrives")
        .expect("stream still open");
    let SubscriptionItem::Event(received) = first else {
        panic!("expected Event item, got {first:?}");
    };
    assert_eq!(received.id, event.id);

    let second = timeout(STEP_TIMEOUT, sub.next())
        .await
        .expect("eose arrives")
        .expect("stream still open");
    assert!(matches!(second, SubscriptionItem::EndOfStoredEvents));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_on_eose_terminates_stream() {
    let (relay, mut handle) = connected_relay().await;

    let id = SubscriptionId::new("sub-eose").expect("valid sub id");
    let mut sub = relay
        .subscribe(
            id.clone(),
            vec![Filter::new().kind(Kind::TEXT_NOTE)],
            SubscribeOptions::new().close_on_eose(true),
        )
        .await
        .expect("subscribe succeeds");

    let _filters = next_req(&mut handle, &id).await;

    handle
        .push_inbound(Message::Text(r#"["EOSE","sub-eose"]"#.to_owned()))
        .expect("push eose");

    let item = timeout(STEP_TIMEOUT, sub.next())
        .await
        .expect("eose arrives")
        .expect("stream still open");
    assert!(matches!(item, SubscriptionItem::EndOfStoredEvents));
    // After EOSE the actor removed the entry. The subscription
    // sink was dropped along with the entry, so the stream ends.
    let next = timeout(STEP_TIMEOUT, sub.next())
        .await
        .expect("stream end observed within deadline");
    assert!(next.is_none(), "close-on-eose closes the handle");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_handle_emits_close_frame() {
    let (relay, mut handle) = connected_relay().await;

    let id = SubscriptionId::new("sub-drop").expect("valid sub id");
    let sub = relay
        .subscribe(
            id.clone(),
            vec![Filter::new().kind(Kind::TEXT_NOTE)],
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe succeeds");

    let _filters = next_req(&mut handle, &id).await;
    drop(sub);

    let outbound = timeout(STEP_TIMEOUT, handle.next_outbound())
        .await
        .expect("CLOSE arrived")
        .expect("outbound channel open");
    let Message::Text(raw) = outbound else {
        panic!("expected text frame, got {outbound:?}");
    };
    let parsed: ClientMessage = serde_json::from_str(&raw).expect("client message json");
    match parsed {
        ClientMessage::Close(close_id) => assert_eq!(close_id, id),
        other => panic!("expected Close, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_frame_terminates_handle_with_message() {
    let (relay, mut handle) = connected_relay().await;

    let id = SubscriptionId::new("sub-closed").expect("valid sub id");
    let mut sub = relay
        .subscribe(
            id.clone(),
            vec![Filter::new().kind(Kind::TEXT_NOTE)],
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe succeeds");

    let _ = next_req(&mut handle, &id).await;
    handle
        .push_inbound(Message::Text(
            r#"["CLOSED","sub-closed","auth-required: please AUTH first"]"#.to_owned(),
        ))
        .expect("push closed");

    let item = timeout(STEP_TIMEOUT, sub.next())
        .await
        .expect("closed arrives")
        .expect("stream still open");
    let SubscriptionItem::Closed { message } = item else {
        panic!("expected Closed, got {item:?}");
    };
    assert!(message.contains("auth-required"));

    // Stream ends after Closed.
    let after = sub.next().await;
    assert!(after.is_none(), "stream ended after CLOSED, got {after:?}");
}
