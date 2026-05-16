//! Shared fixtures for the integration tests.
//!
//! Each test file re-declares `mod helpers;` to pull these in. The
//! module is intentionally small — every test does its own asserts so
//! the helpers stay readable.

#![allow(dead_code, reason = "different test files exercise different helpers")]

use nula_core::event::{Event, EventBuilder, Kind, Tag};
use nula_core::key::Keys;
use nula_core::types::Timestamp;

/// Construct a fresh signing keypair via the OS RNG.
pub(crate) fn keys() -> Keys {
    Keys::generate().expect("OS RNG works in tests")
}

/// Build a signed kind-1 (text-note) event with the given content and
/// `created_at` timestamp, signed with `keys`.
pub(crate) fn text_note(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::text_note(content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("text-note signs")
}

/// Build a signed kind-0 (metadata) event with arbitrary content body.
pub(crate) fn metadata_event(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::METADATA, content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("metadata signs")
}

/// Build a signed event of an arbitrary kind with the supplied tags.
///
/// Used for replaceable / addressable / ephemeral test cases that
/// need to set a specific `Kind` plus a `d` tag.
pub(crate) fn event_with_tags(
    keys: &Keys,
    kind: Kind,
    content: &str,
    created_at: u64,
    tags: impl IntoIterator<Item = Tag>,
) -> Event {
    let mut builder = EventBuilder::new(kind, content).created_at(Timestamp::from_secs(created_at));
    for tag in tags {
        builder = builder.tag(tag);
    }
    builder.sign_with_keys(keys).expect("custom event signs")
}

/// Build a NIP-40-expiring event: the expiration tag is `exp_at`,
/// expressed as a Unix timestamp.
pub(crate) fn expiring_text_note(
    keys: &Keys,
    content: &str,
    created_at: u64,
    exp_at: u64,
) -> Event {
    let expiration_tag =
        Tag::new(["expiration", &exp_at.to_string()]).expect("expiration tag is well-formed");
    event_with_tags(keys, Kind::TEXT_NOTE, content, created_at, [expiration_tag])
}
