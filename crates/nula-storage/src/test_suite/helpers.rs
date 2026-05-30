//! Event-construction helpers shared by every [`crate::test_suite::cases`]
//! module. Kept tiny on purpose — every case still asserts what it
//! cares about explicitly.

use nula_core::event::{Event, EventBuilder, Kind, Tag};
use nula_core::key::Keys;
use nula_core::types::Timestamp;

/// Fresh signing keypair from the OS RNG. Backend test suites do
/// not need deterministic keys: every case starts with an empty
/// database and only writes events it itself produced.
#[must_use]
pub fn keys() -> Keys {
    Keys::generate().expect("OS RNG works in tests")
}

/// Signed kind-1 (text note) event.
#[must_use]
pub fn text_note(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::text_note(content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("text note signs")
}

/// Signed kind-0 (metadata) event.
#[must_use]
pub fn metadata_event(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::METADATA, content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("metadata signs")
}

/// Signed event of an arbitrary kind with the supplied tags.
///
/// Used by replaceable / addressable / ephemeral cases that need to
/// pin a specific `Kind` plus a `d` tag.
#[must_use]
pub fn event_with_tags(
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

/// NIP-40 expiring text-note event.
#[must_use]
pub fn expiring_text_note(keys: &Keys, content: &str, created_at: u64, exp_at: u64) -> Event {
    let expiration_tag =
        Tag::new(["expiration", &exp_at.to_string()]).expect("expiration tag is well-formed");
    event_with_tags(keys, Kind::TEXT_NOTE, content, created_at, [expiration_tag])
}
