//! `break_down_event` outbox-model routing for outgoing events.

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

use nula_core::nips::nip65::RelayMarker;
use nula_core::{Kind, Timestamp};
use nula_gossip::EventRoute;

mod helpers;
use helpers::{
    build_dm_relays_event, build_event_with_p_tags, build_relay_list, keys, make_gossip,
    relay_list_from_iter, url,
};

#[tokio::test]
async fn normal_event_routes_author_outbox_and_recipient_inbox() {
    let (gossip, _db) = make_gossip();
    let alice = keys(1);
    let bob = keys(2);

    // Alice advertises a write (outbox) relay; Bob a read (inbox) one.
    gossip
        .process(
            &build_relay_list(
                &alice,
                &relay_list_from_iter([("wss://alice-out.example/", RelayMarker::Write)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;
    gossip
        .process(
            &build_relay_list(
                &bob,
                &relay_list_from_iter([("wss://bob-in.example/", RelayMarker::Read)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;

    // Alice authors a note mentioning Bob.
    let note = build_event_with_p_tags(
        &alice,
        Kind::TEXT_NOTE,
        &[*bob.public_key()],
        Timestamp::from_secs(200),
    );
    let EventRoute::Relays(relays) = gossip.break_down_event(&note).await else {
        panic!("expected resolved relays for a note with known author + recipient");
    };
    assert!(
        relays.contains(&url("wss://alice-out.example/")),
        "author's outbox relay must be a target; got {relays:?}",
    );
    assert!(
        relays.contains(&url("wss://bob-in.example/")),
        "recipient's inbox relay must be a target; got {relays:?}",
    );
}

#[tokio::test]
async fn gift_wrap_routes_recipient_dm_relays_only() {
    let (gossip, _db) = make_gossip();
    let alice = keys(3);
    let bob = keys(4);

    // Alice has an outbox relay that must NOT be used for a gift wrap.
    gossip
        .process(
            &build_relay_list(
                &alice,
                &relay_list_from_iter([("wss://alice-out.example/", RelayMarker::Write)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;
    // Bob advertises a NIP-17 DM relay.
    gossip
        .process(
            &build_dm_relays_event(
                &bob,
                &[url("wss://bob-dm.example/")],
                Timestamp::from_secs(101),
            ),
            None,
        )
        .await;

    // A gift wrap is signed by a throw-away key; here Alice stands in
    // for that ephemeral author, tagging Bob as the recipient.
    let wrap = build_event_with_p_tags(
        &alice,
        Kind::GIFT_WRAP,
        &[*bob.public_key()],
        Timestamp::from_secs(200),
    );
    let EventRoute::Relays(relays) = gossip.break_down_event(&wrap).await else {
        panic!("expected resolved DM relays for a gift wrap with a known recipient");
    };
    assert!(
        relays.contains(&url("wss://bob-dm.example/")),
        "recipient's DM relay must be a target; got {relays:?}",
    );
    assert!(
        !relays.contains(&url("wss://alice-out.example/")),
        "gift wraps must not leak to the author's outbox; got {relays:?}",
    );
}

#[tokio::test]
async fn gift_wrap_without_dm_relays_is_private_message_orphan() {
    let (gossip, _db) = make_gossip();
    let alice = keys(5);
    let bob = keys(6);

    // Bob has a NIP-65 list but NO NIP-17 DM relays.
    gossip
        .process(
            &build_relay_list(
                &bob,
                &relay_list_from_iter([("wss://bob-in.example/", RelayMarker::Read)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;

    let wrap = build_event_with_p_tags(
        &alice,
        Kind::GIFT_WRAP,
        &[*bob.public_key()],
        Timestamp::from_secs(200),
    );
    assert!(
        matches!(
            gossip.break_down_event(&wrap).await,
            EventRoute::Orphan {
                private_message: true
            }
        ),
        "a gift wrap whose recipient has no DM relays must be a private-message orphan",
    );
}

#[tokio::test]
async fn contact_list_routes_author_outbox_only() {
    let (gossip, _db) = make_gossip();
    let alice = keys(3);
    let bob = keys(4);

    gossip
        .process(
            &build_relay_list(
                &alice,
                &relay_list_from_iter([("wss://alice-out.example/", RelayMarker::Write)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;
    gossip
        .process(
            &build_relay_list(
                &bob,
                &relay_list_from_iter([("wss://bob-in.example/", RelayMarker::Read)]),
                Timestamp::from_secs(100),
            ),
            None,
        )
        .await;

    // A kind:3 contact list authored by Alice following Bob.
    let contacts = build_event_with_p_tags(
        &alice,
        Kind::CONTACTS,
        &[*bob.public_key()],
        Timestamp::from_secs(200),
    );
    let EventRoute::Relays(relays) = gossip.break_down_event(&contacts).await else {
        panic!("expected resolved relays for a contact list with a known author");
    };
    assert!(
        relays.contains(&url("wss://alice-out.example/")),
        "author's outbox relay must be a target; got {relays:?}",
    );
    assert!(
        !relays.contains(&url("wss://bob-in.example/")),
        "contact lists must not fan out to followees' inboxes; got {relays:?}",
    );
}

#[tokio::test]
async fn unknown_author_event_is_non_private_orphan() {
    let (gossip, _db) = make_gossip();
    let alice = keys(7);
    let bob = keys(8);

    // Neither key is known to the routing graph.
    let note = build_event_with_p_tags(
        &alice,
        Kind::TEXT_NOTE,
        &[*bob.public_key()],
        Timestamp::from_secs(200),
    );
    assert!(
        matches!(
            gossip.break_down_event(&note).await,
            EventRoute::Orphan {
                private_message: false
            }
        ),
        "an event with no resolvable route falls back to a non-private orphan",
    );
}
