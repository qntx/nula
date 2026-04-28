// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Fluent builder for [`Event`]s and [`UnsignedEvent`]s.
//!
//! [`EventBuilder`] decouples the *intent* (kind, content, tags, …) from the
//! *signer* (local [`Keys`], NIP-46 remote signer, hardware bunker, …). Every
//! builder method returns `Self`, so the typical call site reads top-down:
//!
//! ```
//! use nula_core::{EventBuilder, Keys, Kind, Tag};
//!
//! let keys = Keys::generate().unwrap();
//! let event = EventBuilder::new(Kind::TEXT_NOTE, "hello, nostr")
//!     .tag(Tag::new(["alt", "greeting"]).unwrap())
//!     .sign_with_keys(&keys)
//!     .unwrap();
//! event.verify().unwrap();
//! ```

use super::event::Event;
use super::kind::Kind;
use super::tag::{Tag, Tags};
use super::unsigned::{UnsignedEvent, UnsignedEventError};
use crate::key::{Keys, PublicKey};
use crate::types::{Timestamp, TimestampError};

/// Errors raised by [`EventBuilder`] terminal methods.
#[derive(Debug, thiserror::Error)]
pub enum EventBuilderError {
    /// The system clock could not be read while choosing `created_at`.
    #[error("could not read the system clock: {0}")]
    Clock(#[from] TimestampError),
    /// The signer's public key did not match the supplied `pubkey`.
    #[error(transparent)]
    Signer(#[from] UnsignedEventError),
}

/// Fluent builder.
///
/// All fields are public so adapters in higher layers (NIP-specific helpers,
/// gossip planners, fuzzers, …) can mutate them without going through the
/// builder methods. Direct construction is intentionally cheap: every field
/// is owned and the builder never copies anything implicitly.
#[derive(Debug, Clone)]
pub struct EventBuilder {
    /// Event kind. Defaults to [`Kind::TEXT_NOTE`].
    pub kind: Kind,
    /// Event content.
    pub content: String,
    /// Event tags (insertion order is preserved).
    pub tags: Tags,
    /// Optional `created_at`. `None` means "use the wall clock at sign time".
    pub created_at: Option<Timestamp>,
}

impl EventBuilder {
    /// Construct a builder with the given kind and content.
    #[must_use]
    pub fn new<S>(kind: Kind, content: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            kind,
            content: content.into(),
            tags: Tags::new(),
            created_at: None,
        }
    }

    /// Build a [`Kind::TEXT_NOTE`] event (NIP-01) with the supplied content.
    #[must_use]
    pub fn text_note<S>(content: S) -> Self
    where
        S: Into<String>,
    {
        Self::new(Kind::TEXT_NOTE, content)
    }

    /// Set the event kind (overrides any previously set value).
    #[must_use]
    pub const fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    /// Replace the event content.
    #[must_use]
    pub fn content<S>(mut self, content: S) -> Self
    where
        S: Into<String>,
    {
        self.content = content.into();
        self
    }

    /// Append a single tag.
    #[must_use]
    pub fn tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// Append several tags from any iterator.
    #[must_use]
    pub fn tags<I>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = Tag>,
    {
        self.tags.extend(tags);
        self
    }

    /// Pin a custom `created_at`.
    ///
    /// Useful when re-signing historical events or backfilling fixtures.
    #[must_use]
    pub const fn created_at(mut self, ts: Timestamp) -> Self {
        self.created_at = Some(ts);
        self
    }

    /// Build the [`UnsignedEvent`] but do not sign it.
    ///
    /// `pubkey` becomes the `pubkey` field. The `created_at` field is taken
    /// from the builder if set, otherwise from the system clock.
    ///
    /// # Errors
    ///
    /// Returns [`EventBuilderError::Clock`] if the wall clock could not be
    /// read.
    pub fn build_unsigned(
        self,
        pubkey: PublicKey,
    ) -> Result<UnsignedEvent, EventBuilderError> {
        let created_at = match self.created_at {
            Some(ts) => ts,
            None => Timestamp::now()?,
        };
        Ok(UnsignedEvent::new(
            pubkey,
            created_at,
            self.kind,
            self.tags,
            self.content,
        ))
    }

    /// Build and sign with `keys` in one shot.
    ///
    /// # Errors
    ///
    /// Returns [`EventBuilderError::Clock`] if the wall clock could not be
    /// read or [`EventBuilderError::Signer`] if signing fails (it cannot, in
    /// the local-keys case).
    pub fn sign_with_keys(self, keys: &Keys) -> Result<Event, EventBuilderError> {
        let unsigned = self.build_unsigned(*keys.public_key())?;
        let event = unsigned.sign_with_keys(keys)?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
    }

    #[test]
    fn new_text_note_signs_and_verifies() {
        let keys = fixture_keys();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.kind, Kind::TEXT_NOTE);
        assert_eq!(event.content, "hello");
        event.verify().unwrap();
    }

    #[test]
    fn pin_created_at_round_trip() {
        let keys = fixture_keys();
        let ts = Timestamp::from_secs(1_700_000_000);
        let event = EventBuilder::text_note("pinned")
            .created_at(ts)
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.created_at, ts);
        event.verify().unwrap();
    }

    #[test]
    fn tags_and_kind_are_applied() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::REACTION, "+")
            .tag(Tag::new(["e", "abc"]).unwrap())
            .tag(Tag::new(["p", "def"]).unwrap())
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.kind, Kind::REACTION);
        assert_eq!(event.tags.len(), 2);
        event.verify().unwrap();
    }

    #[test]
    fn build_unsigned_does_not_require_keys() {
        let keys = fixture_keys();
        let unsigned = EventBuilder::text_note("draft")
            .build_unsigned(*keys.public_key())
            .unwrap();
        assert_eq!(unsigned.pubkey, *keys.public_key());
        // Signing with the matching keys works.
        let event = unsigned.sign_with_keys(&keys).unwrap();
        event.verify().unwrap();
    }

    #[test]
    fn extend_tags_in_one_call() {
        let keys = fixture_keys();
        let event = EventBuilder::text_note("multi")
            .tags([
                Tag::new(["e", "id-1"]).unwrap(),
                Tag::new(["p", "pk-1"]).unwrap(),
            ])
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.tags.len(), 2);
        event.verify().unwrap();
    }
}
