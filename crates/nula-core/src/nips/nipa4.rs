//! [NIP-A4] Public Messages.
//!
//! `kind: 24` is a plaintext public message addressed to one or more
//! recipients via `p` tags. The spec deliberately forbids `e` tags so
//! these events form a flat notification surface (no chains, no
//! threads). Replies, reactions, and zaps still cross-reference the
//! event via NIP-22 / NIP-25 / NIP-57 with the `k` tag pointing at
//! `24`.
//!
//! [NIP-A4]: https://github.com/nostr-protocol/nips/blob/master/A4.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 24` — public message.
pub const KIND_PUBLIC_MESSAGE: Kind = Kind::PUBLIC_MESSAGE;

/// A `p` tag column on a public message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMessageRecipient {
    /// Recipient pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint per NIP-65 inbox routing.
    pub relay_hint: Option<RelayUrl>,
}

/// Typed bundle for a `kind: 24` public-message event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMessage {
    /// Plaintext body.
    pub content: String,
    /// At least one recipient (per spec).
    pub recipients: Vec<PublicMessageRecipient>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-A4 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PublicMessageError {
    /// Event kind is not `24`.
    #[error("unexpected kind for NIP-A4 public message: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `p` tag is missing the pubkey column.
    #[error("`p` tag missing recipient pubkey")]
    MalformedRecipient,
    /// Spec forbids `e` tags on public messages.
    #[error("NIP-A4 public message MUST NOT include `e` tags")]
    ForbiddenEventTag,
    /// Event has no `p` recipient.
    #[error("NIP-A4 public message has no recipients")]
    MissingRecipient,
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

impl PublicMessageRecipient {
    /// Construct a recipient with no relay hint.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    fn to_tag(&self) -> Tag {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        self.relay_hint.as_ref().map_or_else(
            || Tag::with(&head, [self.pubkey.to_hex()]),
            |relay| Tag::with(&head, [self.pubkey.to_hex(), relay.as_str().to_owned()]),
        )
    }

    fn from_tag(tag: &Tag) -> Result<Self, PublicMessageError> {
        let pk_hex = tag.get(1).ok_or(PublicMessageError::MalformedRecipient)?;
        let pubkey = PublicKey::parse(pk_hex)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        Ok(Self { pubkey, relay_hint })
    }
}

impl PublicMessage {
    /// Construct a public message addressed to the given recipients.
    #[must_use]
    pub fn new(content: impl Into<String>, recipients: Vec<PublicMessageRecipient>) -> Self {
        Self {
            content: content.into(),
            recipients,
            extra_tags: Vec::new(),
        }
    }

    /// Parse a `kind: 24` public-message event.
    ///
    /// # Errors
    ///
    /// See [`PublicMessageError`] for the failure modes. Notably an
    /// `e` tag triggers [`PublicMessageError::ForbiddenEventTag`] per
    /// spec §"Warnings".
    pub fn from_event(event: &Event) -> Result<Self, PublicMessageError> {
        if event.kind != KIND_PUBLIC_MESSAGE {
            return Err(PublicMessageError::WrongKind(event.kind));
        }
        let mut recipients: Vec<PublicMessageRecipient> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    recipients.push(PublicMessageRecipient::from_tag(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    return Err(PublicMessageError::ForbiddenEventTag);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        if recipients.is_empty() {
            return Err(PublicMessageError::MissingRecipient);
        }
        Ok(Self {
            content: event.content.clone(),
            recipients,
            extra_tags,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-A4 `kind: 24` public message.
    ///
    /// # Errors
    ///
    /// Returns [`PublicMessageError::MissingRecipient`] when
    /// [`PublicMessage::recipients`] is empty.
    pub fn public_message(msg: &PublicMessage) -> Result<Self, PublicMessageError> {
        if msg.recipients.is_empty() {
            return Err(PublicMessageError::MissingRecipient);
        }
        let mut builder = Self::new(KIND_PUBLIC_MESSAGE, msg.content.clone());
        for recipient in &msg.recipients {
            builder = builder.tag(recipient.to_tag());
        }
        for tag in &msg.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn public_message_round_trip() {
        let recipient = PublicMessageRecipient::new(*keys().public_key())
            .relay_hint(RelayUrl::parse("wss://relay.example/").unwrap());
        let msg = PublicMessage::new("hello", vec![recipient]);
        let event = EventBuilder::public_message(&msg)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PublicMessage::from_event(&event).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn missing_recipient_is_rejected() {
        let msg = PublicMessage::new("hello", Vec::new());
        assert!(matches!(
            EventBuilder::public_message(&msg),
            Err(PublicMessageError::MissingRecipient)
        ));
    }

    #[test]
    fn event_tag_is_rejected() {
        use crate::event::EventId;
        let event = EventBuilder::new(KIND_PUBLIC_MESSAGE, "rough")
            .tag(Tag::e(EventId::from_byte_array([0x99; 32])))
            .tag(Tag::p(*keys().public_key()))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            PublicMessage::from_event(&event),
            Err(PublicMessageError::ForbiddenEventTag)
        ));
    }
}
