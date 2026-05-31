//! End-to-end NWC client test against an in-process mock wallet.
//!
//! Stands up a [`MockRelay`], spawns a wallet task that answers
//! `kind:23194` requests with `kind:23195` responses (correlated via the
//! `e` tag, exactly as the spec requires), and drives the real
//! [`NostrWalletConnect`] client through it.

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

use futures::StreamExt as _;
use nula_core::nips::nip47::{
    self, ConnectionUri, Encryption, ErrorCode, KIND_REQUEST, Request, Response, ResponseError,
};
use nula_core::{EventBuilder, Filter, Keys, RelayUrl, SecretKey};
use nula_nwc::{NostrWalletConnect, NwcOptions, PayInvoiceRequest};
use nula_relay::SubscribeOptions;
use nula_relay::pool::{RelayCapabilities, RelayPool};
use nula_relay::server::MockRelayBuilder;
use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;
use tokio::task::JoinHandle;

fn make_pool() -> RelayPool {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    RelayPool::builder()
        .database(db)
        .build()
        .expect("database supplied to builder")
}

fn handle_request(request: &Request) -> Response {
    match request.method.as_str() {
        "get_balance" => Response {
            result_type: "get_balance".to_owned(),
            error: None,
            result: Some(serde_json::json!({ "balance": 123_000_u64 })),
        },
        "pay_invoice" => Response {
            result_type: "pay_invoice".to_owned(),
            error: None,
            result: Some(serde_json::json!({ "preimage": "deadbeef", "fees_paid": 1_000_u64 })),
        },
        other => Response {
            result_type: other.to_owned(),
            error: Some(ResponseError {
                code: ErrorCode::NotImplemented,
                message: format!("method `{other}` not implemented by mock wallet"),
            }),
            result: None,
        },
    }
}

/// Spawn an in-process wallet service bound to `relay`.
async fn spawn_mock_wallet(wallet: Keys, relay: RelayUrl) -> JoinHandle<()> {
    let pool = make_pool();
    pool.add_relay(
        relay.clone(),
        RelayCapabilities::READ | RelayCapabilities::WRITE,
    )
    .await
    .expect("add_relay");
    pool.try_connect(Duration::from_secs(2)).await;

    let filter = Filter::new()
        .pubkey(*wallet.public_key())
        .kind(KIND_REQUEST)
        .limit(0);

    tokio::spawn(async move {
        let mut stream = pool
            .stream_events_to(
                vec![relay.clone()],
                vec![filter],
                SubscribeOptions::default(),
                None,
            )
            .await
            .expect("subscribe");
        while let Some((_url, item)) = stream.next().await {
            let Ok(event) = item else { continue };
            let Ok(request) = nip47::decrypt_request(&event, wallet.secret_key()) else {
                continue;
            };
            let response = handle_request(&request);
            let Ok(builder) = EventBuilder::nwc_response(
                wallet.secret_key(),
                &event.pubkey,
                event.id,
                &response,
                Encryption::Nip44V2,
            ) else {
                continue;
            };
            let Ok(resp_event) = builder.sign_with_keys(&wallet) else {
                continue;
            };
            pool.send_event_to(vec![relay.clone()], resp_event)
                .await
                .ok();
        }
    })
}

fn client_uri(wallet: &Keys, relay: &RelayUrl) -> ConnectionUri {
    let secret =
        SecretKey::parse("0000000000000000000000000000000000000000000000000000000000000005")
            .expect("hardcoded client secret");
    ConnectionUri {
        wallet_pubkey: *wallet.public_key(),
        relays: vec![relay.clone()],
        secret,
        lud16: None,
    }
}

#[tokio::test]
async fn get_balance_and_pay_invoice_round_trip() {
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let url = server.url().clone();
    let wallet = Keys::parse("0000000000000000000000000000000000000000000000000000000000000077")
        .expect("hardcoded wallet key");

    let _wallet_task = spawn_mock_wallet(wallet.clone(), url.clone()).await;

    let client = NostrWalletConnect::builder()
        .uri(client_uri(&wallet, &url))
        .embedded_pool(make_pool())
        .options(NwcOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("build client");

    assert_eq!(client.wallet_public_key(), *wallet.public_key());

    let balance = client.get_balance().await.expect("get_balance");
    assert_eq!(balance.balance, 123_000);

    let paid = client
        .pay_invoice(PayInvoiceRequest::new("lnbc1exampleinvoice"))
        .await
        .expect("pay_invoice");
    assert_eq!(paid.preimage, "deadbeef");
    assert_eq!(paid.fees_paid, Some(1_000));
}

#[tokio::test]
async fn wallet_error_maps_to_error_variant() {
    let server = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let url = server.url().clone();
    let wallet = Keys::parse("0000000000000000000000000000000000000000000000000000000000000078")
        .expect("hardcoded wallet key");

    let _wallet_task = spawn_mock_wallet(wallet.clone(), url.clone()).await;

    let client = NostrWalletConnect::builder()
        .uri(client_uri(&wallet, &url))
        .embedded_pool(make_pool())
        .options(NwcOptions::default().timeout(Duration::from_secs(3)))
        .build()
        .await
        .expect("build client");

    // `make_invoice` is not implemented by the mock wallet, so it
    // returns a structured error envelope that maps to `Error::Wallet`.
    let err = client
        .make_invoice(nula_nwc::MakeInvoiceRequest::new(1_000))
        .await
        .expect_err("mock wallet rejects make_invoice");
    assert!(matches!(err, nula_nwc::Error::Wallet { .. }), "got {err:?}");
}
