//! [NIP-88] Polls.
//!
//! Two regular kinds:
//!
//! - `kind: 1068` — poll author event. `.content` carries the poll
//!   label; `option`, `relay`, `polltype`, and `endsAt` tags carry
//!   structured metadata.
//! - `kind: 1018` — poll response. References the poll via `e` and
//!   carries one or more `response` tags pointing at option ids.
//!
//! [NIP-88]: https://github.com/nostr-protocol/nips/blob/master/88.md

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventId, EventIdError, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError};

/// `kind: 1068` — poll event.
pub const KIND_POLL: Kind = Kind::POLL;

/// `kind: 1018` — poll response event.
pub const KIND_POLL_RESPONSE: Kind = Kind::POLL_RESPONSE;

const OPTION_TAG: &str = "option";
const RELAY_TAG: &str = "relay";
const POLLTYPE_TAG: &str = "polltype";
const ENDS_AT_TAG: &str = "endsAt";
const RESPONSE_TAG: &str = "response";

/// Poll behaviour: spec defines `singlechoice` (default) and
/// `multiplechoice`; unknown values pass through as `Custom`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum PollType {
    /// `singlechoice` — only the first response counts.
    #[default]
    SingleChoice,
    /// `multiplechoice` — first response per option id counts.
    MultipleChoice,
    /// Forward-compatible passthrough for unknown tokens.
    Custom(String),
}

impl PollType {
    /// Wire token.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleChoice => "singlechoice",
            Self::MultipleChoice => "multiplechoice",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds; missing tags MUST be
    /// treated as [`Self::SingleChoice`] per spec.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "singlechoice" => Self::SingleChoice,
            "multiplechoice" => Self::MultipleChoice,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// A single `option` row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PollOption {
    /// Alphanumeric option identifier (referenced by responses).
    pub id: String,
    /// Display label.
    pub label: String,
}

/// Typed bundle for a `kind: 1068` poll event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Poll {
    /// Free-form poll label (mirrors `.content`).
    pub label: String,
    /// `option` rows in display order.
    pub options: Vec<PollOption>,
    /// Recommended response relays.
    pub relays: Vec<RelayUrl>,
    /// Optional poll type.
    pub poll_type: Option<PollType>,
    /// Optional `endsAt` Unix timestamp.
    pub ends_at: Option<Timestamp>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 1018` poll-response event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResponse {
    /// Target poll event id.
    pub poll_id: EventId,
    /// Response option ids (one per `response` tag).
    pub response_ids: Vec<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing NIP-88 events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PollError {
    /// Event kind is not `1068` / `1018`.
    #[error("unexpected kind for NIP-88 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `option` tag is missing the id or label column.
    #[error("`option` tag missing id or label")]
    MalformedOption,
    /// `e` tag missing on a poll response.
    #[error("poll response missing `e` reference to poll event id")]
    MissingPollReference,
    /// `response` tag missing the option-id column.
    #[error("`response` tag missing option id")]
    MalformedResponse,
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
}

impl Poll {
    /// Construct a poll with the label seeded.
    #[must_use]
    pub fn new(label: impl Into<String>, options: Vec<PollOption>) -> Self {
        Self {
            label: label.into(),
            options,
            ..Self::default()
        }
    }

    /// Parse a `kind: 1068` poll event.
    ///
    /// # Errors
    ///
    /// See [`PollError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, PollError> {
        if event.kind != KIND_POLL {
            return Err(PollError::WrongKind(event.kind));
        }
        let mut out = Self::new(event.content.clone(), Vec::new());
        for tag in &event.tags {
            absorb_poll_tag(tag, &mut out)?;
        }
        Ok(out)
    }

    /// Effective poll type (defaults to [`PollType::SingleChoice`]
    /// when unset per spec).
    #[must_use]
    pub fn effective_type(&self) -> PollType {
        self.poll_type.clone().unwrap_or_default()
    }
}

fn absorb_poll_tag(tag: &Tag, out: &mut Poll) -> Result<(), PollError> {
    match tag.name() {
        OPTION_TAG => {
            let id = tag.get(1).ok_or(PollError::MalformedOption)?.to_owned();
            let label = tag.get(2).ok_or(PollError::MalformedOption)?.to_owned();
            out.options.push(PollOption { id, label });
        }
        RELAY_TAG => {
            if let Some(raw) = tag.get(1) {
                out.relays.push(RelayUrl::parse(raw)?);
            }
        }
        POLLTYPE_TAG => {
            out.poll_type = tag.get(1).map(PollType::parse);
        }
        ENDS_AT_TAG => {
            if let Some(raw) = tag.get(1) {
                out.ends_at = Some(raw.parse::<Timestamp>()?);
            }
        }
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

impl PollResponse {
    /// Construct a single-choice response.
    #[must_use]
    pub fn single(poll_id: EventId, option_id: impl Into<String>) -> Self {
        Self {
            poll_id,
            response_ids: vec![option_id.into()],
            extra_tags: Vec::new(),
        }
    }

    /// Parse a `kind: 1018` poll-response event.
    ///
    /// # Errors
    ///
    /// See [`PollError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, PollError> {
        if event.kind != KIND_POLL_RESPONSE {
            return Err(PollError::WrongKind(event.kind));
        }
        let mut poll_id: Option<EventId> = None;
        let mut response_ids: Vec<String> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::E && poll_id.is_none() =>
                {
                    let raw = tag.get(1).ok_or(PollError::MissingPollReference)?;
                    poll_id = Some(EventId::parse(raw)?);
                }
                _ if tag.name() == RESPONSE_TAG => {
                    let raw = tag.get(1).ok_or(PollError::MalformedResponse)?;
                    response_ids.push(raw.to_owned());
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            poll_id: poll_id.ok_or(PollError::MissingPollReference)?,
            response_ids,
            extra_tags,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-88 `kind: 1068` poll event.
    #[must_use]
    pub fn poll(poll: &Poll) -> Self {
        let mut builder = Self::new(KIND_POLL, poll.label.clone());
        for option in &poll.options {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(OPTION_TAG),
                [option.id.clone(), option.label.clone()],
            ));
        }
        for relay in &poll.relays {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(RELAY_TAG),
                [relay.as_str().to_owned()],
            ));
        }
        if let Some(pt) = &poll.poll_type {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(POLLTYPE_TAG),
                [pt.as_str().to_owned()],
            ));
        }
        if let Some(ts) = poll.ends_at {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(ENDS_AT_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        for tag in &poll.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-88 `kind: 1018` poll-response event.
    #[must_use]
    pub fn poll_response(response: &PollResponse) -> Self {
        let head_e = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let mut builder = Self::new(KIND_POLL_RESPONSE, "");
        builder = builder.tag(Tag::with(&head_e, [response.poll_id.to_hex()]));
        for option_id in &response.response_ids {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(RESPONSE_TAG),
                [option_id.clone()],
            ));
        }
        for tag in &response.extra_tags {
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
    fn poll_round_trip() {
        let poll = Poll {
            label: "Pineapple on pizza".into(),
            options: vec![
                PollOption {
                    id: "yay".into(),
                    label: "Yay".into(),
                },
                PollOption {
                    id: "nay".into(),
                    label: "Nay".into(),
                },
            ],
            relays: vec![RelayUrl::parse("wss://relay.example/").unwrap()],
            poll_type: Some(PollType::SingleChoice),
            ends_at: Some(Timestamp::from_secs(1_700_000_000)),
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::poll(&poll).sign_with_keys(&keys()).unwrap();
        let parsed = Poll::from_event(&event).unwrap();
        assert_eq!(parsed, poll);
    }

    #[test]
    fn poll_response_round_trip() {
        let response = PollResponse {
            poll_id: EventId::from_byte_array([0x77; 32]),
            response_ids: vec!["yay".into(), "nay".into()],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::poll_response(&response)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PollResponse::from_event(&event).unwrap();
        assert_eq!(parsed, response);
    }

    #[test]
    fn missing_poll_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Poll::from_event(&event),
            Err(PollError::WrongKind(_))
        ));
    }

    #[test]
    fn poll_default_type() {
        let poll = Poll::new("q", Vec::new());
        assert_eq!(poll.effective_type(), PollType::SingleChoice);
    }
}
