//! [NIP-09] Event Deletion Request.
//!
//! NIP-09 lets an author request deletion of one or more of their own
//! events by publishing a `kind: 5` event whose tags reference the
//! targets:
//!
//! ```text
//! ["e", "<event-id>"]                     // a regular event
//! ["a", "<kind>:<author>:<identifier>"]   // a parameterized replaceable event
//! ["k", "<kind>"]                          // optional hint
//! ```
//!
//! The `content` is a free-form, human-readable reason (which may be
//! empty). Relays SHOULD honour the request only when the deletion event
//! and the targeted event share the same author.
//!
//! [`DeletionRequest`] models the request, serializes to / parses from a
//! NIP-09 event, and exposes [`validate_target_authority`] for relays
//! checking that a candidate target was authored by the deletion's
//! signer.
//!
//! [NIP-09]: https://github.com/nostr-protocol/nips/blob/master/09.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind,
};
use crate::key::PublicKey;

/// Wire name of the NIP-09 kind hint tag (`k`).
pub const KIND_TAG: &str = "k";

/// A deletion request published as a `kind: 5` event.
///
/// Use [`DeletionRequest::new`] + the chainable `delete_*` / `with_*`
/// methods to build a request, [`EventBuilder::deletion`] to turn it into
/// a signable event, or [`DeletionRequest::from_event`] to parse one off
/// the wire.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeletionRequest {
    /// Regular events to delete (the `e` tag values).
    pub event_ids: Vec<EventId>,
    /// Parameterized replaceable events to delete (the `a` tag values).
    pub coordinates: Vec<Coordinate>,
    /// Kind hints (`k` tags) for relays that index by kind.
    pub kinds: Vec<Kind>,
    /// Free-form reason; an empty string means "no reason supplied".
    pub reason: String,
}

impl DeletionRequest {
    /// Construct an empty request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a regular event id to delete.
    #[must_use]
    pub fn delete_event(mut self, id: EventId) -> Self {
        self.event_ids.push(id);
        self
    }

    /// Add several event ids.
    #[must_use]
    pub fn delete_events(mut self, ids: impl IntoIterator<Item = EventId>) -> Self {
        self.event_ids.extend(ids);
        self
    }

    /// Add a coordinate (parameterized replaceable event) to delete.
    #[must_use]
    pub fn delete_coordinate(mut self, coord: Coordinate) -> Self {
        self.coordinates.push(coord);
        self
    }

    /// Add a kind hint.
    #[must_use]
    pub fn hint_kind(mut self, kind: Kind) -> Self {
        self.kinds.push(kind);
        self
    }

    /// Set the human-readable reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Render the deletion request as the [`Tag`]s that go into a `kind: 5`
    /// event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags =
            Vec::with_capacity(self.event_ids.len() + self.coordinates.len() + self.kinds.len());
        for id in &self.event_ids {
            tags.push(Tag::e(*id));
        }
        for coord in &self.coordinates {
            tags.push(Tag::a(coord));
        }
        for kind in &self.kinds {
            tags.push(Tag::k(*kind));
        }
        tags
    }

    /// Parse a [`DeletionRequest`] from a `kind: 5` [`Event`].
    ///
    /// Tags whose head is not one of `e`/`a`/`k` are silently ignored
    /// (forward-compat).
    ///
    /// # Errors
    ///
    /// Returns [`DeletionError::UnexpectedKind`] if the event's kind is not
    /// `5`, plus the matching parse error if any of the recognised tags is
    /// malformed.
    pub fn from_event(event: &Event) -> Result<Self, DeletionError> {
        if event.kind != Kind::EVENT_DELETION {
            return Err(DeletionError::UnexpectedKind(event.kind.as_u16()));
        }
        let mut request = Self::new().with_reason(event.content.clone());
        let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let a_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        let k_kind = TagKind::from_wire(KIND_TAG);
        for tag in &event.tags {
            let head = tag.kind();
            if head == e_kind {
                let value = tag
                    .values()
                    .get(1)
                    .ok_or(DeletionError::MissingTagValue { tag: "e" })?;
                request.event_ids.push(value.parse::<EventId>()?);
            } else if head == a_kind {
                let value = tag
                    .values()
                    .get(1)
                    .ok_or(DeletionError::MissingTagValue { tag: "a" })?;
                request.coordinates.push(value.parse::<Coordinate>()?);
            } else if head == k_kind {
                let value = tag
                    .values()
                    .get(1)
                    .ok_or(DeletionError::MissingTagValue { tag: "k" })?;
                let raw: u16 = value
                    .parse()
                    .map_err(|_| DeletionError::InvalidKindHint(value.clone()))?;
                request.kinds.push(Kind::from(raw));
            }
        }
        Ok(request)
    }
}

impl EventBuilder {
    /// Build a `kind: 5` deletion event from the given [`DeletionRequest`].
    #[must_use]
    pub fn deletion(request: &DeletionRequest) -> Self {
        Self::new(Kind::EVENT_DELETION, request.reason.clone()).tags(request.to_tags())
    }
}

/// Errors raised when parsing or applying a NIP-09 deletion event.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum DeletionError {
    /// The event's kind was not `5`.
    #[error("expected kind 5, got {0}")]
    UnexpectedKind(u16),
    /// A tag head was recognised but had no value.
    #[error("`{tag}` tag is missing its value")]
    MissingTagValue {
        /// Wire name of the offending tag head.
        tag: &'static str,
    },
    /// An `e` tag value did not parse as a 32-byte event id.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// An `a` tag value did not parse as a [`Coordinate`].
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// A `k` tag value did not parse as `u16`.
    #[error("invalid `k` tag hint: `{0}`")]
    InvalidKindHint(String),
}

/// Errors raised by [`validate_target_authority`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorityError {
    /// The deletion event was not authored by the target's author. The
    /// relay MUST refuse to apply the request in this case.
    #[error("deletion author does not match target author")]
    AuthorMismatch,
}

/// Verify that `deletion`'s author matches `target`'s author.
///
/// Relays MUST refuse to honour a NIP-09 request whose signer is not the
/// author of the targeted event.
///
/// # Errors
///
/// Returns [`AuthorityError::AuthorMismatch`] when the authors differ.
pub fn validate_target_authority(
    deletion: &Event,
    target_author: &PublicKey,
) -> Result<(), AuthorityError> {
    if deletion.pubkey == *target_author {
        Ok(())
    } else {
        Err(AuthorityError::AuthorMismatch)
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

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    #[test]
    fn round_trip_simple() {
        let id = EventId::from_byte_array([0xab; 32]);
        let request = DeletionRequest::new().delete_event(id).with_reason("typo");

        let deletion = EventBuilder::deletion(&request)
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        deletion.verify().unwrap();
        assert_eq!(deletion.kind, Kind::EVENT_DELETION);
        assert_eq!(deletion.content, "typo");

        let parsed = DeletionRequest::from_event(&deletion).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn round_trip_with_coordinate_and_kind_hint() {
        let id = EventId::from_byte_array([0x01; 32]);
        let coord = Coordinate::new(Kind::from(30_023_u16), *keys().public_key(), "long-form-1");
        let request = DeletionRequest::new()
            .delete_event(id)
            .delete_coordinate(coord)
            .hint_kind(Kind::from(30_023_u16))
            .with_reason("retract draft");

        let deletion = EventBuilder::deletion(&request)
            .created_at(Timestamp::from_secs(2))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = DeletionRequest::from_event(&deletion).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn empty_request_round_trips() {
        let request = DeletionRequest::new();
        let deletion = EventBuilder::deletion(&request)
            .created_at(Timestamp::from_secs(3))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = DeletionRequest::from_event(&deletion).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn rejects_wrong_kind() {
        let event = EventBuilder::text_note("not a deletion")
            .created_at(Timestamp::from_secs(4))
            .sign_with_keys(&keys())
            .unwrap();
        let err = DeletionRequest::from_event(&event).unwrap_err();
        assert!(matches!(err, DeletionError::UnexpectedKind(1)));
    }

    #[test]
    fn rejects_missing_e_value() {
        let event = EventBuilder::new(Kind::EVENT_DELETION, "")
            .created_at(Timestamp::from_secs(5))
            .tag(Tag::new(["e"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = DeletionRequest::from_event(&event).unwrap_err();
        assert!(matches!(err, DeletionError::MissingTagValue { tag: "e" }));
    }

    #[test]
    fn validate_authority_accepts_matching_author() {
        let request = DeletionRequest::new();
        let deletion = EventBuilder::deletion(&request)
            .created_at(Timestamp::from_secs(6))
            .sign_with_keys(&keys())
            .unwrap();
        validate_target_authority(&deletion, keys().public_key()).unwrap();
    }

    #[test]
    fn validate_authority_rejects_mismatching_author() {
        let request = DeletionRequest::new();
        let deletion = EventBuilder::deletion(&request)
            .created_at(Timestamp::from_secs(7))
            .sign_with_keys(&keys())
            .unwrap();
        let err = validate_target_authority(&deletion, other_keys().public_key()).unwrap_err();
        assert_eq!(err, AuthorityError::AuthorMismatch);
    }
}
