//! [NIP-84] Highlights.
//!
//! `kind: 9802` events signal content the publisher found valuable.
//! The data model is a small bundle:
//!
//! - `.content` carries the highlighted text. It MAY be empty when
//!   the highlight refers to non-text media (audio/video).
//! - One or more *sources* identify the original material. Sources
//!   are encoded as `e`/`a` tags for native nostr events and `r`
//!   tags for URLs.
//! - Zero or more *attributions* (`p` tags) name the original authors
//!   or editors. The optional 4th column ([`Attribution::role`])
//!   carries the role keyword.
//! - Optional surrounding `context` for short snippets.
//! - Optional `comment` to turn the highlight into a quote-style
//!   "quote highlight" rendering.
//!
//! Forward compatibility:
//!
//! - Unknown roles surface through [`Attribution::role`] as
//!   [`Option<String>`] — no enum to bump.
//! - Unknown `r` markers (`mention`, `source`, …) are surfaced
//!   through [`HighlightSource::Url`]'s `marker` field.
//! - Anything else round-trips through [`Highlight::extra_tags`].
//!
//! [NIP-84]: https://github.com/nostr-protocol/nips/blob/master/84.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError, Url, UrlError};

/// `kind: 9802` — highlight.
pub const KIND_HIGHLIGHT: Kind = Kind::HIGHLIGHT;

/// Spec-defined role markers for [`Attribution::role`].
pub mod roles {
    /// Original author.
    pub const AUTHOR: &str = "author";
    /// Editor.
    pub const EDITOR: &str = "editor";
    /// Quote-highlight mention (added by NIP-84 "Quote Highlights").
    pub const MENTION: &str = "mention";
}

/// Spec-defined markers for `r` (URL) source tags.
pub mod url_markers {
    /// The source URL of the highlight (used inside quote highlights
    /// to disambiguate from `mention`).
    pub const SOURCE: &str = "source";
    /// A URL mentioned inside the highlight's comment.
    pub const MENTION: &str = "mention";
}

/// A source the highlight was extracted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HighlightSource {
    /// `e` tag — points at a specific nostr event.
    Event {
        /// Source event id.
        id: EventId,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `a` tag — points at an addressable event.
    Address {
        /// Source coordinate.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `r` tag — external URL. The optional `marker` distinguishes
    /// the highlight's `source` from a `mention` inside the
    /// comment (see [`url_markers`]).
    Url {
        /// Source URL.
        url: Url,
        /// Optional marker (`source` / `mention` / custom).
        marker: Option<String>,
    },
}

impl HighlightSource {
    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        match self {
            Self::Event { id, relay_hint } => relay_hint
                .as_ref()
                .map_or_else(|| Tag::e(*id), |url| Tag::e_with_relay(*id, url)),
            Self::Address {
                coordinate,
                relay_hint,
            } => relay_hint.as_ref().map_or_else(
                || Tag::a(coordinate),
                |url| Tag::a_with_relay(coordinate, url),
            ),
            Self::Url { url, marker } => {
                let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
                marker.as_ref().map_or_else(
                    || Tag::with(&head, [url.as_str().to_owned()]),
                    |m| Tag::with(&head, [url.as_str().to_owned(), m.clone()]),
                )
            }
        }
    }
}

/// Attribution for the highlighted material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// Original author / editor / mentioned pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
    /// Optional role (`author`, `editor`, `mention`, custom).
    pub role: Option<String>,
}

impl Attribution {
    /// Construct an attribution with no role marker.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
            role: None,
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Attach a role marker. Use the constants in [`roles`] for the
    /// spec-defined values.
    #[must_use]
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let mut values: Vec<String> = Vec::with_capacity(4);
        values.push(self.pubkey.to_hex());
        match (&self.relay_hint, &self.role) {
            (Some(relay), Some(role)) => {
                values.push(relay.as_str().to_owned());
                values.push(role.clone());
            }
            (Some(relay), None) => values.push(relay.as_str().to_owned()),
            (None, Some(role)) => {
                values.push(String::new());
                values.push(role.clone());
            }
            (None, None) => {}
        }
        Tag::with(&head, values)
    }
}

/// Typed bundle for a `kind: 9802` highlight event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Highlight {
    /// `.content` — highlighted text. MAY be empty for non-text
    /// highlights.
    pub content: String,
    /// Source material being highlighted.
    pub sources: Vec<HighlightSource>,
    /// Attributions (original authors, editors, mentioned pubkeys).
    pub attributions: Vec<Attribution>,
    /// Optional surrounding text (`context` tag).
    pub context: Option<String>,
    /// Optional quote-highlight comment (`comment` tag).
    pub comment: Option<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl Highlight {
    /// Construct an empty highlight.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace [`Self::content`].
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append a source.
    #[must_use]
    pub fn source(mut self, source: HighlightSource) -> Self {
        self.sources.push(source);
        self
    }

    /// Append an attribution.
    #[must_use]
    pub fn attribution(mut self, attribution: Attribution) -> Self {
        self.attributions.push(attribution);
        self
    }

    /// Set [`Self::context`].
    #[must_use]
    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Set [`Self::comment`] — turns the event into a quote highlight.
    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Parse a `kind: 9802` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`HighlightError::WrongKind`] for non-9802 events.
    /// - Field-specific errors for malformed tag columns.
    pub fn from_event(event: &Event) -> Result<Self, HighlightError> {
        if event.kind != KIND_HIGHLIGHT {
            return Err(HighlightError::WrongKind(event.kind));
        }
        let mut sources: Vec<HighlightSource> = Vec::new();
        let mut attributions: Vec<Attribution> = Vec::new();
        let mut context: Option<String> = None;
        let mut comment: Option<String> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    sources.push(parse_event_source(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    sources.push(parse_address_source(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::R => {
                    sources.push(parse_url_source(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    attributions.push(parse_attribution(tag)?);
                }
                _ if tag.name() == "context" => {
                    context = tag.get(1).map(str::to_owned);
                }
                _ if tag.name() == "comment" => {
                    comment = tag.get(1).map(str::to_owned);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            content: event.content.clone(),
            sources,
            attributions,
            context,
            comment,
            extra_tags,
        })
    }
}

fn parse_event_source(tag: &Tag) -> Result<HighlightSource, HighlightError> {
    let id_hex = tag.get(1).ok_or(HighlightError::MalformedEventSource)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    Ok(HighlightSource::Event { id, relay_hint })
}

fn parse_address_source(tag: &Tag) -> Result<HighlightSource, HighlightError> {
    let coord_str = tag.get(1).ok_or(HighlightError::MalformedAddressSource)?;
    let coordinate = Coordinate::parse(coord_str)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    Ok(HighlightSource::Address {
        coordinate,
        relay_hint,
    })
}

fn parse_url_source(tag: &Tag) -> Result<HighlightSource, HighlightError> {
    let url_str = tag.get(1).ok_or(HighlightError::MalformedUrlSource)?;
    let url = Url::parse(url_str)?;
    let marker = tag.get(2).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok(HighlightSource::Url { url, marker })
}

fn parse_attribution(tag: &Tag) -> Result<Attribution, HighlightError> {
    let pk_hex = tag.get(1).ok_or(HighlightError::MalformedAttribution)?;
    let pubkey = PublicKey::parse(pk_hex)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    let role = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok(Attribution {
        pubkey,
        relay_hint,
        role,
    })
}

fn parse_optional_relay(value: Option<&str>) -> Result<Option<RelayUrl>, HighlightError> {
    match value {
        Some(s) if !s.is_empty() => Ok(Some(RelayUrl::parse(s)?)),
        _ => Ok(None),
    }
}

/// Errors raised by [`Highlight::from_event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HighlightError {
    /// The event was not `kind: 9802`.
    #[error("expected kind 9802 (highlight), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `e` source tag is missing its event id column.
    #[error("`e` source tag missing event id")]
    MalformedEventSource,
    /// `a` source tag is missing its coordinate column.
    #[error("`a` source tag missing coordinate")]
    MalformedAddressSource,
    /// `r` source tag is missing its URL column.
    #[error("`r` source tag missing URL")]
    MalformedUrlSource,
    /// `p` attribution tag is missing its pubkey column.
    #[error("`p` attribution tag missing pubkey")]
    MalformedAttribution,
    /// Event id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Relay URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

impl EventBuilder {
    /// Author a NIP-84 `kind: 9802` highlight event.
    #[must_use]
    pub fn highlight(highlight: &Highlight) -> Self {
        let mut builder = Self::new(KIND_HIGHLIGHT, highlight.content.clone());
        for source in &highlight.sources {
            builder = builder.tag(source.to_tag());
        }
        for attribution in &highlight.attributions {
            builder = builder.tag(attribution.to_tag());
        }
        if let Some(context) = &highlight.context {
            builder = builder.tag(Tag::with(&TagKind::from_wire("context"), [context.clone()]));
        }
        if let Some(comment) = &highlight.comment {
            builder = builder.tag(Tag::with(&TagKind::from_wire("comment"), [comment.clone()]));
        }
        for tag in &highlight.extra_tags {
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

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    fn url(input: &str) -> Url {
        Url::parse(input).unwrap()
    }

    #[test]
    fn round_trip_text_highlight() {
        let id = EventId::from_byte_array([0x07; 32]);
        let highlight = Highlight::new()
            .content("Important sentence")
            .source(HighlightSource::Event {
                id,
                relay_hint: Some(relay()),
            })
            .attribution(
                Attribution::new(*keys().public_key())
                    .relay_hint(relay())
                    .role(roles::AUTHOR),
            );
        let event = EventBuilder::highlight(&highlight)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_HIGHLIGHT);
        let parsed = Highlight::from_event(&event).unwrap();
        assert_eq!(parsed, highlight);
    }

    #[test]
    fn round_trip_url_highlight_with_context() {
        let highlight = Highlight::new()
            .content("Excerpt")
            .source(HighlightSource::Url {
                url: url("https://example.com/article"),
                marker: Some(url_markers::SOURCE.to_owned()),
            })
            .context("Surrounding paragraph for context.");
        let event = EventBuilder::highlight(&highlight)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Highlight::from_event(&event).unwrap();
        assert_eq!(parsed, highlight);
    }

    #[test]
    fn round_trip_quote_highlight() {
        let highlight = Highlight::new()
            .content("the quoted text")
            .source(HighlightSource::Url {
                url: url("https://example.com/article"),
                marker: Some(url_markers::SOURCE.to_owned()),
            })
            .attribution(Attribution::new(*keys().public_key()).role(roles::AUTHOR))
            .attribution(Attribution::new(*keys().public_key()).role(roles::MENTION))
            .comment("My take on this");
        let event = EventBuilder::highlight(&highlight)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Highlight::from_event(&event).unwrap();
        assert_eq!(parsed, highlight);
    }

    #[test]
    fn round_trip_address_source() {
        let coord = Coordinate::new(Kind::new(30_023), *keys().public_key(), "post-1".to_owned());
        let highlight = Highlight::new()
            .content("Highlight from long-form post")
            .source(HighlightSource::Address {
                coordinate: coord,
                relay_hint: Some(relay()),
            });
        let event = EventBuilder::highlight(&highlight)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Highlight::from_event(&event).unwrap();
        assert_eq!(parsed, highlight);
    }

    #[test]
    fn empty_content_is_allowed_for_audio_video() {
        let highlight = Highlight::new().source(HighlightSource::Url {
            url: url("https://example.com/podcast.mp3"),
            marker: Some(url_markers::SOURCE.to_owned()),
        });
        let event = EventBuilder::highlight(&highlight)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Highlight::from_event(&event).unwrap();
        assert_eq!(parsed, highlight);
        assert!(parsed.content.is_empty());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Highlight::from_event(&event),
            Err(HighlightError::WrongKind(_))
        ));
    }

    #[test]
    fn malformed_event_source_propagates() {
        let event = EventBuilder::new(KIND_HIGHLIGHT, "")
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
                ["not-a-hex"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Highlight::from_event(&event),
            Err(HighlightError::InvalidEventId(_))
        ));
    }
}
