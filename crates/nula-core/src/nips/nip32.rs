//! [NIP-32] Labeling.
//!
//! Labels attach short, vocabulary-scoped strings to nostr targets.
//! The spec defines two indexable tags and one new event kind:
//!
//! - `L` — label *namespace* (e.g. `ISO-639-1`, `com.example.ontology`,
//!   the reserved `ugc` for user-generated content, or the
//!   `#`-prefixed form that re-uses a standard NIP tag value).
//! - `l` — label *value*, optionally carrying a mark that points back
//!   to the namespace. If no mark is provided the `ugc` namespace is
//!   implied per spec.
//! - `kind: 1985` — dedicated label event that targets one or more
//!   `e` / `p` / `a` / `r` / `t` columns. The body's `.content` is the
//!   human-readable rationale.
//!
//! Self-reporting: any non-1985 event MAY also carry `L`/`l` tags to
//! tag *itself*. We surface that via [`labels_from_tags`] so callers
//! can read the namespace/value pairs without duplicating the parser.
//!
//! # Forward compatibility
//!
//! - Unknown target columns are preserved through [`Label::extra_tags`]
//!   so producers cannot strip metadata accidentally.
//! - Labels without a mark are accepted on the wire and surfaced with
//!   namespace = [`UGC_NAMESPACE`] per spec §"Label Tag".
//! - The label namespace is treated as opaque — no validation beyond
//!   non-emptiness — so new ontologies work without a crate bump.
//!
//! [NIP-32]: https://github.com/nostr-protocol/nips/blob/master/32.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError, Url, UrlError};

/// `kind: 1985` — labeling event.
pub const KIND_LABEL: Kind = Kind::LABEL;

/// Reserved namespace for user-generated content (spec §"Label
/// Namespace Tag").
pub const UGC_NAMESPACE: &str = "ugc";

/// One namespace/value pair, the elemental unit of NIP-32.
///
/// `namespace` is the `L` tag value (or [`UGC_NAMESPACE`] when the
/// label tag had no mark). `value` is the `l` tag's first column.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabelTerm {
    /// `L` namespace. Always non-empty when surfaced from
    /// [`Label::from_event`] / [`labels_from_tags`].
    pub namespace: String,
    /// `l` value.
    pub value: String,
}

impl LabelTerm {
    /// Construct a term in `namespace` with `value`.
    #[must_use]
    pub fn new(namespace: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            value: value.into(),
        }
    }

    /// Convenience constructor for the spec's reserved
    /// [`UGC_NAMESPACE`].
    #[must_use]
    pub fn ugc(value: impl Into<String>) -> Self {
        Self::new(UGC_NAMESPACE, value)
    }

    /// True if this term lives in the reserved [`UGC_NAMESPACE`].
    #[must_use]
    pub fn is_ugc(&self) -> bool {
        self.namespace == UGC_NAMESPACE
    }
}

/// The object a label points at. The spec lists five wire columns;
/// we map them to typed variants and preserve relay hints when the
/// spec allows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelTarget {
    /// `e` tag — labels a specific event by id.
    Event {
        /// Target event id.
        id: EventId,
        /// Optional relay hint (spec §"Label Target": SHOULD be
        /// included for `e`/`p`).
        relay_hint: Option<RelayUrl>,
    },
    /// `p` tag — labels a profile by pubkey.
    Pubkey {
        /// Target pubkey.
        pubkey: PublicKey,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `a` tag — labels an addressable event by coordinate.
    Address {
        /// Target coordinate.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `r` tag — labels an external URL.
    Url(Url),
    /// `t` tag — labels a hashtag/topic. Lower-cased by [`Tag::t`].
    Topic(String),
}

impl LabelTarget {
    /// Render the target as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        match self {
            Self::Event { id, relay_hint } => relay_hint
                .as_ref()
                .map_or_else(|| Tag::e(*id), |url| Tag::e_with_relay(*id, url)),
            Self::Pubkey { pubkey, relay_hint } => relay_hint
                .as_ref()
                .map_or_else(|| Tag::p(*pubkey), |url| Tag::p_with_relay(*pubkey, url)),
            Self::Address {
                coordinate,
                relay_hint,
            } => relay_hint.as_ref().map_or_else(
                || Tag::a(coordinate),
                |url| Tag::a_with_relay(coordinate, url),
            ),
            Self::Url(url) => Tag::r(url),
            Self::Topic(topic) => Tag::t(topic),
        }
    }
}

/// Typed bundle for a NIP-32 `kind: 1985` label event.
///
/// At least one term and one target are RECOMMENDED but not strictly
/// required by the spec — parsers accept what is on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Label {
    /// Namespace/value pairs. Order is preserved across round-trips
    /// so producers that pin a stable order keep it.
    pub terms: Vec<LabelTerm>,
    /// Targets being labeled.
    pub targets: Vec<LabelTarget>,
    /// `.content` — long-form rationale (often empty).
    pub content: String,
    /// Tags the producer attached that we did not recognise.
    /// Round-tripped verbatim for forward compatibility.
    pub extra_tags: Vec<Tag>,
}

impl Label {
    /// Construct an empty label bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a namespace/value pair.
    #[must_use]
    pub fn term(mut self, term: LabelTerm) -> Self {
        self.terms.push(term);
        self
    }

    /// Append a target.
    #[must_use]
    pub fn target(mut self, target: LabelTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// Replace the `.content` rationale.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Parse a `kind: 1985` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`LabelError::WrongKind`] when the event is not `kind: 1985`.
    /// - [`LabelError::MalformedNamespace`] /
    ///   [`LabelError::MalformedValue`] when a tag is missing its
    ///   value column.
    /// - [`LabelError::InvalidEventId`] /
    ///   [`LabelError::InvalidPublicKey`] /
    ///   [`LabelError::InvalidCoordinate`] /
    ///   [`LabelError::InvalidUrl`] /
    ///   [`LabelError::InvalidRelayUrl`] for malformed targets.
    pub fn from_event(event: &Event) -> Result<Self, LabelError> {
        if event.kind != KIND_LABEL {
            return Err(LabelError::WrongKind(event.kind));
        }
        let terms = labels_from_tags(&event.tags)?;
        let mut targets: Vec<LabelTarget> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if s.uppercase && s.character == Alphabet::L => {
                    // Namespace tag handled by `labels_from_tags`.
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::L => {
                    // Value tag handled by `labels_from_tags`.
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    targets.push(parse_event_target(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    targets.push(parse_pubkey_target(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    targets.push(parse_address_target(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::R => {
                    targets.push(parse_url_target(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
                    targets.push(parse_topic_target(tag)?);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            terms,
            targets,
            content: event.content.clone(),
            extra_tags,
        })
    }
}

/// Read self-reported `L`/`l` tags off any event's tag list. Per
/// spec §"Self-Reporting" this is the same parser used by the
/// `kind: 1985` reader but applicable to any kind.
///
/// `l` tags without a mark surface in [`UGC_NAMESPACE`]; tags with a
/// mark that does not match any `L` tag in the same event are still
/// surfaced verbatim because some publishers omit the `L` column on
/// purpose.
///
/// # Errors
///
/// Returns [`LabelError::MalformedValue`] when an `l` tag has no
/// value column.
pub fn labels_from_tags(tags: &Tags) -> Result<Vec<LabelTerm>, LabelError> {
    let mut terms: Vec<LabelTerm> = Vec::new();
    for tag in tags {
        let TagKind::SingleLetter(letter) = tag.kind() else {
            continue;
        };
        if letter.character != Alphabet::L || letter.uppercase {
            continue;
        }
        let value = tag.get(1).ok_or(LabelError::MalformedValue)?.to_owned();
        let namespace = tag
            .get(2)
            .filter(|ns| !ns.is_empty())
            .map_or_else(|| UGC_NAMESPACE.to_owned(), str::to_owned);
        terms.push(LabelTerm { namespace, value });
    }
    Ok(terms)
}

/// Render a [`LabelTerm`] into the `L`/`l` tag pair the spec
/// requires. The namespace tag comes first to match the example
/// ordering in NIP-32.
#[must_use]
pub fn term_to_tags(term: &LabelTerm) -> [Tag; 2] {
    [
        Tag::with(
            &TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::L)),
            [term.namespace.clone()],
        ),
        Tag::with(
            &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::L)),
            [term.value.clone(), term.namespace.clone()],
        ),
    ]
}

/// Errors raised by [`Label::from_event`] and [`labels_from_tags`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LabelError {
    /// The event was not `kind: 1985`.
    #[error("expected kind 1985 (label), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// An `L` tag had no namespace value.
    #[error("`L` namespace tag missing namespace value")]
    MalformedNamespace,
    /// An `l` tag had no value column.
    #[error("`l` label tag missing value")]
    MalformedValue,
    /// An `e` target tag had no event id column.
    #[error("`e` target tag missing event id")]
    MalformedEventTarget,
    /// A `p` target tag had no pubkey column.
    #[error("`p` target tag missing pubkey")]
    MalformedPubkeyTarget,
    /// An `a` target tag had no coordinate column.
    #[error("`a` target tag missing coordinate")]
    MalformedAddressTarget,
    /// An `r` target tag had no URL column.
    #[error("`r` target tag missing URL")]
    MalformedUrlTarget,
    /// A `t` target tag had no topic column.
    #[error("`t` target tag missing topic")]
    MalformedTopicTarget,
    /// The `e` event id could not be parsed.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// The `p` pubkey could not be parsed.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// The `a` coordinate could not be parsed.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// The `r` URL could not be parsed.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// A relay hint URL could not be parsed.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

fn parse_event_target(tag: &Tag) -> Result<LabelTarget, LabelError> {
    let id_hex = tag.get(1).ok_or(LabelError::MalformedEventTarget)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    Ok(LabelTarget::Event { id, relay_hint })
}

fn parse_pubkey_target(tag: &Tag) -> Result<LabelTarget, LabelError> {
    let pk_hex = tag.get(1).ok_or(LabelError::MalformedPubkeyTarget)?;
    let pubkey = PublicKey::parse(pk_hex)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    Ok(LabelTarget::Pubkey { pubkey, relay_hint })
}

fn parse_address_target(tag: &Tag) -> Result<LabelTarget, LabelError> {
    let coord_str = tag.get(1).ok_or(LabelError::MalformedAddressTarget)?;
    let coordinate = Coordinate::parse(coord_str)?;
    let relay_hint = parse_optional_relay(tag.get(2))?;
    Ok(LabelTarget::Address {
        coordinate,
        relay_hint,
    })
}

fn parse_url_target(tag: &Tag) -> Result<LabelTarget, LabelError> {
    let url_str = tag.get(1).ok_or(LabelError::MalformedUrlTarget)?;
    let url = Url::parse(url_str)?;
    Ok(LabelTarget::Url(url))
}

fn parse_topic_target(tag: &Tag) -> Result<LabelTarget, LabelError> {
    let topic = tag
        .get(1)
        .ok_or(LabelError::MalformedTopicTarget)?
        .to_owned();
    Ok(LabelTarget::Topic(topic))
}

fn parse_optional_relay(value: Option<&str>) -> Result<Option<RelayUrl>, LabelError> {
    match value {
        Some(s) if !s.is_empty() => Ok(Some(RelayUrl::parse(s)?)),
        _ => Ok(None),
    }
}

impl EventBuilder {
    /// Author a NIP-32 `kind: 1985` label event.
    ///
    /// Tag layout follows the spec's example order: namespaces first
    /// (paired with their `l` value tag), then targets, then any
    /// caller-provided extras.
    #[must_use]
    pub fn label(label: &Label) -> Self {
        let mut builder = Self::new(KIND_LABEL, label.content.clone());
        for term in &label.terms {
            for tag in term_to_tags(term) {
                builder = builder.tag(tag);
            }
        }
        for target in &label.targets {
            builder = builder.tag(target.to_tag());
        }
        for tag in &label.extra_tags {
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

    #[test]
    fn round_trip_topic_label() {
        let label = Label::new()
            .term(LabelTerm::new("ISO-639-1", "en"))
            .target(LabelTarget::Topic("nostr".to_owned()));
        let event = EventBuilder::label(&label).sign_with_keys(&keys()).unwrap();
        assert_eq!(event.kind, KIND_LABEL);
        let parsed = Label::from_event(&event).unwrap();
        assert_eq!(parsed, label);
    }

    #[test]
    fn round_trip_pubkey_label_with_relay() {
        let target = LabelTarget::Pubkey {
            pubkey: *keys().public_key(),
            relay_hint: Some(relay()),
        };
        let label = Label::new()
            .term(LabelTerm::new("com.example.ontology", "VI-hum"))
            .target(target);
        let event = EventBuilder::label(&label).sign_with_keys(&keys()).unwrap();
        let parsed = Label::from_event(&event).unwrap();
        assert_eq!(parsed, label);
    }

    #[test]
    fn round_trip_multiple_terms_and_targets() {
        let id = EventId::from_byte_array([0x11; 32]);
        let coord = Coordinate::new(Kind::new(30_023), *keys().public_key(), "post-1".to_owned());
        let label = Label::new()
            .term(LabelTerm::new("license", "MIT"))
            .term(LabelTerm::new("nip28.moderation", "approve"))
            .target(LabelTarget::Event {
                id,
                relay_hint: Some(relay()),
            })
            .target(LabelTarget::Address {
                coordinate: coord,
                relay_hint: None,
            })
            .target(LabelTarget::Url(Url::parse("https://example.com").unwrap()))
            .content("ok");
        let event = EventBuilder::label(&label).sign_with_keys(&keys()).unwrap();
        let parsed = Label::from_event(&event).unwrap();
        assert_eq!(parsed, label);
    }

    #[test]
    fn self_reporting_labels_are_readable_from_kind_one_event() {
        let event = EventBuilder::text_note("It's beautiful here in Milan!")
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::L)),
                ["ISO-3166-2"],
            ))
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::L)),
                ["IT-MI", "ISO-3166-2"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let terms = labels_from_tags(&event.tags).unwrap();
        assert_eq!(terms, vec![LabelTerm::new("ISO-3166-2", "IT-MI")]);
    }

    #[test]
    fn unmarked_label_falls_back_to_ugc() {
        let event = EventBuilder::text_note("note")
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::L)),
                ["spam"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let terms = labels_from_tags(&event.tags).unwrap();
        assert_eq!(terms, vec![LabelTerm::ugc("spam")]);
        assert!(terms[0].is_ugc());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Label::from_event(&event),
            Err(LabelError::WrongKind(_))
        ));
    }

    #[test]
    fn invalid_event_target_propagates() {
        let event = EventBuilder::new(KIND_LABEL, "")
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
                ["not-a-hex"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Label::from_event(&event),
            Err(LabelError::InvalidEventId(_))
        ));
    }

    #[test]
    fn extra_unknown_tags_are_preserved() {
        let custom = Tag::with(&TagKind::Custom("foo".to_owned()), ["bar"]);
        let label = Label::new()
            .term(LabelTerm::new("license", "MIT"))
            .target(LabelTarget::Topic("rust".to_owned()));
        let mut event_builder = EventBuilder::label(&label);
        event_builder = event_builder.tag(custom.clone());
        let event = event_builder.sign_with_keys(&keys()).unwrap();
        let parsed = Label::from_event(&event).unwrap();
        assert_eq!(parsed.extra_tags, vec![custom]);
    }
}
