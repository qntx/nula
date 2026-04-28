//! [NIP-70] Protected Events.
//!
//! NIP-70 lets the author mark an event as *protected*: relays SHOULD
//! refuse to accept the event from anyone other than its (NIP-42
//! authenticated) author, and SHOULD strip the event from query results
//! served to clients that have not authenticated as the author.
//!
//! The marker is a single-element tag: `["-"]`. This module exposes the
//! tag's wire name and two trivial helpers — [`is_protected`] to check an
//! event and [`EventBuilder::protected`] to attach the marker.
//!
//! [NIP-70]: https://github.com/nostr-protocol/nips/blob/master/70.md

use crate::event::{Event, EventBuilder, Tag, TagKind};

/// Wire name of the NIP-70 protected tag (`-`).
pub const PROTECTED_TAG: &str = "-";

/// True when `event` carries a `["-"]` tag.
#[must_use]
pub fn is_protected(event: &Event) -> bool {
    let kind = TagKind::from_wire(PROTECTED_TAG);
    event.tags.find_first(&kind).is_some()
}

impl EventBuilder {
    /// Attach the NIP-70 protected marker.
    ///
    /// The marker is idempotent: the builder skips the operation if a
    /// `-` tag is already present, so chaining `.protected()` multiple
    /// times produces exactly one tag.
    #[must_use]
    pub fn protected(mut self) -> Self {
        let kind = TagKind::from_wire(PROTECTED_TAG);
        // `Tag::with` ships the head string as the tag's first element and
        // accepts zero further values, producing exactly `["-"]`.
        let tag = Tag::with(&kind, core::iter::empty::<String>());
        self.tags_mut().push_unique_kind(tag);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::types::Timestamp;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn unmarked_event_is_not_protected() {
        let event = EventBuilder::text_note("public")
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(!is_protected(&event));
    }

    #[test]
    fn protected_marker_round_trip() {
        let event = EventBuilder::text_note("private")
            .created_at(Timestamp::from_secs(2))
            .protected()
            .sign_with_keys(&keys())
            .unwrap();
        event.verify().unwrap();
        assert!(is_protected(&event));
    }

    #[test]
    fn protected_is_idempotent() {
        let event = EventBuilder::text_note("private")
            .created_at(Timestamp::from_secs(3))
            .protected()
            .protected()
            .protected()
            .sign_with_keys(&keys())
            .unwrap();
        let count = event
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::from_wire(PROTECTED_TAG))
            .count();
        assert_eq!(count, 1);
    }
}
