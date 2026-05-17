//! Shared fixtures for `nula-gossip` integration tests.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "different test files exercise different helpers"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "helpers panic on misconfigured fixtures — each panic carries a clear message"
)]

use std::sync::Arc;

use nula_core::nips::nip65::{RelayList, RelayMarker};
use nula_core::{Event, EventBuilder, Keys, Kind, RelayUrl, Tag, Timestamp};
use nula_gossip::{Gossip, GossipOptions};
use nula_storage::NostrDatabase;
use nula_storage_memory::MemoryDatabase;

/// Build a fresh in-memory backed gossip handle.
pub fn make_gossip() -> (Gossip, Arc<dyn NostrDatabase>) {
    make_gossip_with_options(GossipOptions::default())
}

/// Build a gossip handle with caller-chosen options.
pub fn make_gossip_with_options(options: GossipOptions) -> (Gossip, Arc<dyn NostrDatabase>) {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let gossip = Gossip::builder()
        .options(options)
        .database(Arc::clone(&db))
        .build()
        .expect("database supplied to builder");
    (gossip, db)
}

/// Convenience: deterministic test keys (per-seed hex byte at byte 31).
pub fn keys(seed: u8) -> Keys {
    let mut hex = [b'0'; 64];
    hex[63] = match seed {
        0..=9 => b'0' + seed,
        10..=15 => b'a' + (seed - 10),
        _ => panic!("seed must be 0..=15 for the helper"),
    };
    let s = std::str::from_utf8(&hex).expect("ascii hex");
    Keys::parse(s).expect("valid hex")
}

/// Build a signed `kind:10002` event from a [`RelayList`].
pub fn build_relay_list(keys: &Keys, list: &RelayList, created_at: Timestamp) -> Event {
    list.to_event_builder()
        .created_at(created_at)
        .sign_with_keys(keys)
        .expect("relay list event")
}

/// Convenience constructor for a NIP-65 `RelayList` from the
/// `(url, marker)` pairs.
pub fn relay_list_from_iter<I, U>(entries: I) -> RelayList
where
    I: IntoIterator<Item = (U, RelayMarker)>,
    U: AsRef<str>,
{
    let mut list = RelayList::new();
    for (url, marker) in entries {
        list.insert(
            RelayUrl::parse(url.as_ref()).expect("valid relay url"),
            marker,
        );
    }
    list
}

/// Build a signed `kind:10050` (NIP-17 DM relays) event.
pub fn build_dm_relays_event(keys: &Keys, relays: &[RelayUrl], created_at: Timestamp) -> Event {
    nula_core::nips::nip17::build_dm_relays_event(relays)
        .created_at(created_at)
        .sign_with_keys(keys)
        .expect("dm relays event")
}

/// Build a regular kind:1 event with `r` tag relay hints.
pub fn build_text_with_relay_hints(keys: &Keys, hints: &[RelayUrl]) -> Event {
    let mut builder =
        EventBuilder::new(Kind::TEXT_NOTE, "hello").created_at(Timestamp::from_secs(1));
    for hint in hints {
        builder = builder.tag(Tag::new(["r", hint.as_str()]).expect("valid r tag"));
    }
    builder.sign_with_keys(keys).expect("text note")
}

/// Convenience: parse a relay URL or panic.
pub fn url(s: &str) -> RelayUrl {
    RelayUrl::parse(s).expect("hardcoded test url")
}
