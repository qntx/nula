// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-40] Expiration Timestamp.
//!
//! NIP-40 lets the author of an event declare a deadline after which the
//! event should be deleted by relays and ignored by clients. The deadline
//! is encoded as a single tag:
//!
//! ```text
//! ["expiration", "<unix_seconds>"]
//! ```
//!
//! The crate parses, builds, and evaluates these tags through three small
//! pieces of API:
//!
//! - [`parse_expiration`] reads an event's deadline (if any).
//! - [`is_expired`] / [`is_expired_now`] tell you whether a deadline has
//!   passed.
//! - [`EventBuilder::expiration`] attaches a deadline when constructing an
//!   event.
//!
//! [NIP-40]: https://github.com/nostr-protocol/nips/blob/master/40.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Tag, TagKind};
use crate::types::{Timestamp, TimestampError};

/// Wire name of the NIP-40 expiration tag (`expiration`).
pub const EXPIRATION_TAG: &str = "expiration";

/// Errors raised when reading an [`Event`]'s NIP-40 deadline.
#[derive(Debug, Clone, Error)]
pub enum ExpirationError {
    /// The expiration tag had no value (i.e. only `["expiration"]`).
    #[error("`expiration` tag is missing the timestamp value")]
    MissingValue,
    /// The expiration tag value was not a non-negative integer.
    #[error("`expiration` tag value `{0}` is not a valid unix timestamp")]
    InvalidTimestamp(String),
}

/// Read the NIP-40 deadline from `event`, if any.
///
/// Returns `Ok(None)` when no `expiration` tag is present and `Ok(Some(ts))`
/// when the tag exists and is well formed.
///
/// # Errors
///
/// Returns [`ExpirationError`] if the tag exists but is malformed.
pub fn parse_expiration(event: &Event) -> Result<Option<Timestamp>, ExpirationError> {
    let kind = TagKind::from_wire(EXPIRATION_TAG);
    let Some(tag) = event.tags.find_first(&kind) else {
        return Ok(None);
    };
    let Some(value) = tag.values().get(1) else {
        return Err(ExpirationError::MissingValue);
    };
    let secs: u64 = value
        .parse()
        .map_err(|_| ExpirationError::InvalidTimestamp(value.clone()))?;
    Ok(Some(Timestamp::from_secs(secs)))
}

/// Whether `event`'s deadline (if any) has passed at `now`.
///
/// An event without an `expiration` tag is never considered expired
/// (returns `Ok(false)`).
///
/// # Errors
///
/// Returns [`ExpirationError`] if the tag exists but is malformed.
pub fn is_expired(event: &Event, now: Timestamp) -> Result<bool, ExpirationError> {
    Ok(parse_expiration(event)?.is_some_and(|deadline| now >= deadline))
}

/// Like [`is_expired`] but reads the wall clock for `now`.
///
/// # Errors
///
/// Returns [`ExpirationError`] for a malformed tag, or
/// [`TimestampError`] if the system clock cannot be read.
pub fn is_expired_now(event: &Event) -> Result<bool, IsExpiredError> {
    let now = Timestamp::now()?;
    Ok(is_expired(event, now)?)
}

/// Composite error returned by [`is_expired_now`].
#[derive(Debug, Error)]
pub enum IsExpiredError {
    /// The expiration tag was malformed.
    #[error(transparent)]
    Expiration(#[from] ExpirationError),
    /// The wall clock could not be read.
    #[error(transparent)]
    Clock(#[from] TimestampError),
}

impl EventBuilder {
    /// Attach a NIP-40 expiration deadline.
    ///
    /// Subsequent calls replace any earlier deadline so the resulting event
    /// always carries at most one `expiration` tag.
    #[must_use]
    pub fn expiration(mut self, ts: Timestamp) -> Self {
        let kind = TagKind::from_wire(EXPIRATION_TAG);
        let mut owned: Vec<Tag> = self
            .tags
            .iter()
            .filter(|t| t.kind() != kind)
            .cloned()
            .collect();
        owned.push(Tag::with(&kind, [ts.as_secs().to_string()]));
        self.tags = crate::event::Tags::from_vec(owned);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
    }

    #[test]
    fn missing_tag_returns_none() {
        let event = EventBuilder::text_note("no-deadline")
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(parse_expiration(&event).unwrap(), None);
        assert!(!is_expired(&event, Timestamp::from_secs(u64::MAX)).unwrap());
    }

    #[test]
    fn builder_attaches_expiration_tag() {
        let deadline = Timestamp::from_secs(1_700_000_000);
        let event = EventBuilder::text_note("deadline")
            .created_at(Timestamp::from_secs(1))
            .expiration(deadline)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(parse_expiration(&event).unwrap(), Some(deadline));
    }

    #[test]
    fn expiration_replaces_previous() {
        let earlier = Timestamp::from_secs(100);
        let later = Timestamp::from_secs(200);
        let event = EventBuilder::text_note("replace")
            .created_at(Timestamp::from_secs(1))
            .expiration(earlier)
            .expiration(later)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(parse_expiration(&event).unwrap(), Some(later));
        // Only one expiration tag should remain.
        let count = event
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::from_wire(EXPIRATION_TAG))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn before_deadline_not_expired() {
        let event = EventBuilder::text_note("future")
            .created_at(Timestamp::from_secs(1))
            .expiration(Timestamp::from_secs(2_000))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(!is_expired(&event, Timestamp::from_secs(1_999)).unwrap());
    }

    #[test]
    fn at_or_after_deadline_is_expired() {
        let event = EventBuilder::text_note("late")
            .created_at(Timestamp::from_secs(1))
            .expiration(Timestamp::from_secs(2_000))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(is_expired(&event, Timestamp::from_secs(2_000)).unwrap());
        assert!(is_expired(&event, Timestamp::from_secs(2_001)).unwrap());
    }

    #[test]
    fn malformed_value_is_reported() {
        let event = EventBuilder::text_note("oops")
            .created_at(Timestamp::from_secs(1))
            .tag(Tag::new(["expiration", "soon"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = parse_expiration(&event).unwrap_err();
        assert!(matches!(err, ExpirationError::InvalidTimestamp(_)));
    }

    #[test]
    fn missing_value_is_reported() {
        let event = EventBuilder::text_note("oops")
            .created_at(Timestamp::from_secs(1))
            .tag(Tag::new(["expiration"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = parse_expiration(&event).unwrap_err();
        assert!(matches!(err, ExpirationError::MissingValue));
    }
}
