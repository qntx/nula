//! NIP-13 `min_pow` admission gate on the in-process `MockRelay`.
//!
//! Mirrors upstream `nostr-relay-builder`'s `min_pow`: a relay
//! configured with a difficulty floor rejects under-powered events
//! (with a `pow:` reason) and accepts mined ones.

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

use std::time::Duration;

use nula_core::nips::nip13;
use nula_core::{EventBuilder, Keys, Timestamp};
use nula_relay::pool::RelayCapabilities;
use nula_relay::server::{MockRelayBuilder, MockRelayOptions};

mod helpers;
use helpers::make_pool;

const MIN_POW: u8 = 8;

fn dev_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
        .expect("valid dev key")
}

#[tokio::test]
async fn min_pow_rejects_under_powered_and_accepts_mined() {
    let relay = MockRelayBuilder::new()
        .options(MockRelayOptions::new().min_pow(MIN_POW))
        .run()
        .await
        .expect("relay binds on 127.0.0.1:0");

    let (pool, _db) = make_pool();
    pool.add_relay(relay.url().clone(), RelayCapabilities::WRITE)
        .await
        .expect("add relay");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    // A plain note with a pinned `created_at` has a deterministic id; it
    // is overwhelmingly below the 8-bit floor. The guard makes the
    // assumption explicit and the test reproducible across runs.
    let low = EventBuilder::text_note("no pow")
        .created_at(Timestamp::from_secs(1_700_000_000))
        .sign_with_keys(&dev_keys())
        .expect("sign low-pow note");
    assert!(
        nip13::event_id_difficulty(&low.id) < MIN_POW,
        "fixture must be below the pow floor"
    );
    let low_id = low.id;
    // The relay rejects this before storage. The pool may surface that as
    // an error or as a per-relay failure; either way the ground truth is
    // that the event was never persisted (asserted below).
    let _outcome = pool.send_event(low).await;
    assert!(
        relay
            .database()
            .event_by_id(&low_id)
            .await
            .expect("query low")
            .is_none(),
        "under-powered event must not be persisted"
    );

    // A mined event clears the floor and is accepted + persisted.
    let mined = nip13::mine_and_sign(&EventBuilder::text_note("mined"), &dev_keys(), MIN_POW)
        .expect("mining succeeds");
    assert!(nip13::event_id_difficulty(&mined.id) >= MIN_POW);
    let mined_id = mined.id;
    pool.send_event(mined).await.expect("send mined event");
    assert!(
        relay
            .database()
            .event_by_id(&mined_id)
            .await
            .expect("query mined")
            .is_some(),
        "mined event must be persisted"
    );
}
