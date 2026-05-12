//! [NIP-C7] Chats.
//!
//! `kind: 9` carries the body of a chat message in `.content`. Replies
//! reuse the same `kind: 9` and quote the parent through a `q` tag,
//! intentionally avoiding the threaded `e` model NIP-10 uses for
//! `kind: 1` notes.
//!
//! [NIP-C7]: https://github.com/nostr-protocol/nips/blob/master/C7.md

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventId, EventIdError, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 9` — chat message.
pub const KIND_CHAT_MESSAGE: Kind = Kind::CHAT_MESSAGE;

/// Typed bundle for a `kind: 9` chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// Free-form body of the message.
    pub content: String,
    /// Optional `q`-quoted parent (only set for replies).
    pub quote: Option<ChatQuote>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Reply target for a chat message (`q` tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatQuote {
    /// Parent event id.
    pub id: EventId,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
    /// Optional author pubkey of the parent (4th column of `q`).
    pub author: Option<PublicKey>,
}

/// Errors raised while parsing a NIP-C7 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChatError {
    /// Event kind is not `9`.
    #[error("unexpected kind for NIP-C7 chat message: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `q` tag is missing the parent id column.
    #[error("`q` tag missing parent event id")]
    MalformedQuote,
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
}

impl ChatMessage {
    /// Construct a top-level chat message.
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            quote: None,
            extra_tags: Vec::new(),
        }
    }

    /// Attach a quoted parent.
    #[must_use]
    pub fn quote(mut self, quote: ChatQuote) -> Self {
        self.quote = Some(quote);
        self
    }

    /// Parse a `kind: 9` chat-message event.
    ///
    /// # Errors
    ///
    /// See [`ChatError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, ChatError> {
        if event.kind != KIND_CHAT_MESSAGE {
            return Err(ChatError::WrongKind(event.kind));
        }
        let mut quote: Option<ChatQuote> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::Q && quote.is_none() =>
                {
                    quote = Some(parse_quote(tag)?);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            content: event.content.clone(),
            quote,
            extra_tags,
        })
    }
}

fn parse_quote(tag: &Tag) -> Result<ChatQuote, ChatError> {
    let id = tag
        .get(1)
        .ok_or(ChatError::MalformedQuote)
        .and_then(|s| EventId::parse(s).map_err(Into::into))?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    let author = match tag.get(3) {
        Some(s) if !s.is_empty() => Some(PublicKey::parse(s)?),
        _ => None,
    };
    Ok(ChatQuote {
        id,
        relay_hint,
        author,
    })
}

fn quote_tag(quote: &ChatQuote) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::Q));
    let relay = quote
        .relay_hint
        .as_ref()
        .map_or_else(String::new, |r| r.as_str().to_owned());
    match (quote.author, quote.relay_hint.is_some()) {
        (Some(pk), _) => Tag::with(&head, [quote.id.to_hex(), relay, pk.to_hex()]),
        (None, true) => Tag::with(&head, [quote.id.to_hex(), relay]),
        (None, false) => Tag::with(&head, [quote.id.to_hex()]),
    }
}

impl EventBuilder {
    /// Author a NIP-C7 `kind: 9` chat message.
    #[must_use]
    pub fn chat_message(msg: &ChatMessage) -> Self {
        let mut builder = Self::new(KIND_CHAT_MESSAGE, msg.content.clone());
        if let Some(quote) = &msg.quote {
            builder = builder.tag(quote_tag(quote));
        }
        for tag in &msg.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
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
    fn chat_message_round_trip() {
        let quote = ChatQuote {
            id: EventId::from_byte_array([0x55; 32]),
            relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
            author: Some(*keys().public_key()),
        };
        let msg = ChatMessage::new("yes").quote(quote.clone());
        let event = EventBuilder::chat_message(&msg)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ChatMessage::from_event(&event).unwrap();
        assert_eq!(parsed, msg);
        assert_eq!(parsed.quote, Some(quote));
    }

    #[test]
    fn top_level_chat_round_trip() {
        let msg = ChatMessage::new("GM");
        let event = EventBuilder::chat_message(&msg)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ChatMessage::from_event(&event).unwrap();
        assert_eq!(parsed, msg);
        assert!(parsed.quote.is_none());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ChatMessage::from_event(&event),
            Err(ChatError::WrongKind(_))
        ));
    }
}
