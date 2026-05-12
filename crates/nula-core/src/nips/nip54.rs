//! [NIP-54] Wiki.
//!
//! Three kinds make up the wiki primitives:
//!
//! - **`kind: 30818` Wiki article** — addressable encyclopedia entry
//!   identified by a normalised `d` tag (lowercase, hyphenated). The
//!   `.content` is Djot per spec, with optional NIP-21 `nostr:`
//!   references; we keep it as opaque `String` and let downstream
//!   renderers handle the format.
//! - **`kind: 30819` Wiki redirect** — addressable redirect from one
//!   `d` slug to another article coordinate.
//! - **`kind: 818` Wiki merge request** — non-addressable request to
//!   merge a forked article version back into the source author's
//!   entry. Carries the destination's `a`/`p` tags plus two `e` tags
//!   (base version + source revision with a `source` marker).
//!
//! # `d`-tag normalisation
//!
//! The spec pins a strict normalisation: lowercase, whitespace →
//! `-`, drop ASCII punctuation, collapse runs of `-`, trim
//! leading/trailing `-`, preserve non-ASCII letters. We expose
//! [`normalize_d_tag`] (and its `Cow`-returning sibling
//! [`normalize_d_tag_cow`]) so producers and consumers agree on the
//! canonical form.
//!
//! `fork` and `defer` markers from spec §"Forks" / §"Deference" are
//! modelled as typed [`Relation`] tags carried on
//! [`WikiArticle::relations`].
//!
//! [NIP-54]: https://github.com/nostr-protocol/nips/blob/master/54.md

use core::fmt;

use std::borrow::Cow;

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 30818` — wiki article.
pub const KIND_WIKI_ARTICLE: Kind = Kind::WIKI_ARTICLE;

/// `kind: 30819` — wiki redirect.
pub const KIND_WIKI_REDIRECT: Kind = Kind::WIKI_REDIRECT;

/// `kind: 818` — wiki merge request.
pub const KIND_WIKI_MERGE_REQUEST: Kind = Kind::WIKI_MERGE_REQUEST;

const TITLE_TAG: &str = "title";
const SUMMARY_TAG: &str = "summary";
const SOURCE_MARKER: &str = "source";
const FORK_MARKER: &str = "fork";
const DEFER_MARKER: &str = "defer";

/// Marker for a tagged reference (`fork`, `defer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    /// `fork` marker (spec §"Forks").
    Fork,
    /// `defer` marker (spec §"Deference").
    Defer,
}

impl Relation {
    /// Wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fork => FORK_MARKER,
            Self::Defer => DEFER_MARKER,
        }
    }

    /// Parse a wire token. Returns `None` for unrecognised tokens.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            FORK_MARKER => Some(Self::Fork),
            DEFER_MARKER => Some(Self::Defer),
            _ => None,
        }
    }
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `fork`/`defer` reference on a wiki article.
///
/// Both `a` (addressable coordinate) and `e` (specific revision)
/// are spec-recommended; either may be `None` for tolerant
/// round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationRef {
    /// Marker (`fork` or `defer`).
    pub relation: Relation,
    /// Optional source article coordinate.
    pub coordinate: Option<Coordinate>,
    /// Optional source article relay hint.
    pub coordinate_relay_hint: Option<RelayUrl>,
    /// Optional specific source revision id.
    pub event_id: Option<EventId>,
    /// Optional source revision relay hint.
    pub event_relay_hint: Option<RelayUrl>,
}

/// Normalise an article title into its canonical `d` tag value.
///
/// Drops ASCII punctuation, collapses runs of `-`, trims leading
/// and trailing `-`, lowercases every letter that has a case, and
/// preserves non-ASCII codepoints intact (see spec §"`d` tag
/// normalization rules" for the rationale).
///
/// Returns a borrowed slice if the input is already canonical.
#[must_use]
pub fn normalize_d_tag(input: &str) -> String {
    normalize_d_tag_cow(input).into_owned()
}

/// Borrowing variant of [`normalize_d_tag`].
///
/// Returns [`Cow::Borrowed`] when the input is already canonical
/// (`is_canonical_d_tag(input) == true`); otherwise allocates a
/// fresh `String` with the normalised form.
#[must_use]
pub fn normalize_d_tag_cow(input: &str) -> Cow<'_, str> {
    if is_canonical_d_tag(input) {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let mut prev_dash = true;
    for ch in input.chars() {
        if ch.is_alphabetic() || ch.is_numeric() {
            for low in ch.to_lowercase() {
                out.push(low);
            }
            prev_dash = false;
        } else if (ch.is_whitespace() || ch == '-' || ch == '_') && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
        // Anything else (ASCII punctuation, control, symbols) is
        // dropped per spec.
    }
    while out.ends_with('-') {
        out.pop();
    }
    Cow::Owned(out)
}

/// Heuristic check: returns true when `input` already obeys the
/// `d`-tag rules and [`normalize_d_tag`] would be the identity.
#[must_use]
pub fn is_canonical_d_tag(input: &str) -> bool {
    if input.starts_with('-') || input.ends_with('-') {
        return false;
    }
    let mut prev_dash = false;
    for ch in input.chars() {
        if ch.is_uppercase() {
            return false;
        }
        if ch == '-' {
            if prev_dash {
                return false;
            }
            prev_dash = true;
        } else if ch.is_alphabetic() || ch.is_numeric() {
            prev_dash = false;
        } else {
            // Anything outside `-` / alphanumeric is non-canonical.
            return false;
        }
    }
    true
}

/// Typed bundle for a `kind: 30818` wiki article event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WikiArticle {
    /// Normalised `d` slug.
    pub identifier: String,
    /// Djot body (`.content`).
    pub content: String,
    /// Optional display title (`title` tag).
    pub title: Option<String>,
    /// Optional summary (`summary` tag).
    pub summary: Option<String>,
    /// `fork`/`defer` relations carried on the article.
    pub relations: Vec<RelationRef>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl WikiArticle {
    /// Construct an article seeded with `identifier`.
    ///
    /// `identifier` is normalised through [`normalize_d_tag`] so
    /// callers don't have to.
    #[must_use]
    pub fn new(identifier: impl AsRef<str>) -> Self {
        Self {
            identifier: normalize_d_tag(identifier.as_ref()),
            ..Self::default()
        }
    }

    /// Set the Djot body.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Set [`Self::title`].
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set [`Self::summary`].
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Append a `fork`/`defer` relation.
    #[must_use]
    pub fn relation(mut self, relation: RelationRef) -> Self {
        self.relations.push(relation);
        self
    }

    /// Build the article's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_WIKI_ARTICLE, author, self.identifier.clone())
    }

    /// Parse a `kind: 30818` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`WikiError::WrongKind`] for any other kind.
    /// - [`WikiError::MissingIdentifier`] when the `d` tag is
    ///   absent.
    pub fn from_event(event: &Event) -> Result<Self, WikiError> {
        if event.kind != KIND_WIKI_ARTICLE {
            return Err(WikiError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(WikiError::MissingIdentifier)?
            .to_owned();
        let mut article = Self {
            identifier,
            content: event.content.clone(),
            ..Self::default()
        };
        let mut pending_a: Vec<(Coordinate, Option<RelayUrl>, Option<Relation>)> = Vec::new();
        let mut pending_e: Vec<(EventId, Option<RelayUrl>, Option<Relation>)> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    absorb_marker_tag_a(tag, &mut pending_a, &mut article)?;
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    absorb_marker_tag_e(tag, &mut pending_e, &mut article)?;
                }
                _ if tag.name() == TITLE_TAG => article.title = tag.get(1).map(str::to_owned),
                _ if tag.name() == SUMMARY_TAG => article.summary = tag.get(1).map(str::to_owned),
                _ => article.extra_tags.push(tag.clone()),
            }
        }
        article.relations = pair_relations(pending_a, pending_e);
        Ok(article)
    }
}

fn absorb_marker_tag_a(
    tag: &Tag,
    pending: &mut Vec<(Coordinate, Option<RelayUrl>, Option<Relation>)>,
    article: &mut WikiArticle,
) -> Result<(), WikiError> {
    let (coord, relay, marker) = parse_a_tag_with_marker(tag)?;
    if let Some(rel) = marker.as_ref().and_then(|m| Relation::parse(m)) {
        pending.push((coord, relay, Some(rel)));
    } else {
        article.extra_tags.push(tag.clone());
    }
    Ok(())
}

fn absorb_marker_tag_e(
    tag: &Tag,
    pending: &mut Vec<(EventId, Option<RelayUrl>, Option<Relation>)>,
    article: &mut WikiArticle,
) -> Result<(), WikiError> {
    let (id, relay, marker) = parse_e_tag_with_marker(tag)?;
    if let Some(rel) = marker.as_ref().and_then(|m| Relation::parse(m)) {
        pending.push((id, relay, Some(rel)));
    } else {
        article.extra_tags.push(tag.clone());
    }
    Ok(())
}

fn absorb_merge_e_tag(
    tag: &Tag,
    source: &mut Option<(EventId, Option<RelayUrl>)>,
    base: &mut Option<(EventId, Option<RelayUrl>)>,
    extra_tags: &mut Vec<Tag>,
) -> Result<(), WikiError> {
    let (id, relay, marker) = parse_e_tag_with_marker(tag)?;
    if marker.as_deref() == Some(SOURCE_MARKER) {
        *source = Some((id, relay));
    } else if base.is_none() {
        *base = Some((id, relay));
    } else {
        extra_tags.push(tag.clone());
    }
    Ok(())
}

fn pair_relations(
    a_tags: Vec<(Coordinate, Option<RelayUrl>, Option<Relation>)>,
    e_tags: Vec<(EventId, Option<RelayUrl>, Option<Relation>)>,
) -> Vec<RelationRef> {
    let mut out: Vec<RelationRef> = Vec::new();
    let mut e_iter = e_tags.into_iter();
    for (coord, coord_relay, rel) in a_tags {
        let relation = rel.unwrap_or(Relation::Fork);
        let companion = e_iter.next();
        out.push(RelationRef {
            relation,
            coordinate: Some(coord),
            coordinate_relay_hint: coord_relay,
            event_id: companion.as_ref().map(|(id, _, _)| *id),
            event_relay_hint: companion.and_then(|(_, relay, _)| relay),
        });
    }
    // Any remaining `e` tags with markers but no `a` partner.
    for (id, relay, rel) in e_iter {
        let relation = rel.unwrap_or(Relation::Fork);
        out.push(RelationRef {
            relation,
            coordinate: None,
            coordinate_relay_hint: None,
            event_id: Some(id),
            event_relay_hint: relay,
        });
    }
    out
}

/// Typed bundle for a `kind: 30819` wiki redirect event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WikiRedirect {
    /// Normalised source `d` slug.
    pub identifier: String,
    /// Target article coordinate (`a` tag).
    pub target: Coordinate,
    /// Optional relay hint for the target.
    pub target_relay_hint: Option<RelayUrl>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl WikiRedirect {
    /// Construct a redirect from `identifier` to `target`. The
    /// identifier is normalised automatically.
    #[must_use]
    pub fn new(identifier: impl AsRef<str>, target: Coordinate) -> Self {
        Self {
            identifier: normalize_d_tag(identifier.as_ref()),
            target,
            target_relay_hint: None,
            extra_tags: Vec::new(),
        }
    }

    /// Attach a relay hint for the target.
    #[must_use]
    pub fn target_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.target_relay_hint = Some(relay);
        self
    }

    /// Build the redirect's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_WIKI_REDIRECT, author, self.identifier.clone())
    }

    /// Parse a `kind: 30819` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`WikiError::WrongKind`] for any other kind.
    /// - [`WikiError::MissingIdentifier`] when the `d` tag is
    ///   absent.
    /// - [`WikiError::MissingTarget`] when no `a` tag is present.
    pub fn from_event(event: &Event) -> Result<Self, WikiError> {
        if event.kind != KIND_WIKI_REDIRECT {
            return Err(WikiError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(WikiError::MissingIdentifier)?
            .to_owned();
        let mut target: Option<(Coordinate, Option<RelayUrl>)> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::A && target.is_none() =>
                {
                    let (coord, relay, _) = parse_a_tag_with_marker(tag)?;
                    target = Some((coord, relay));
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        let (target, target_relay_hint) = target.ok_or(WikiError::MissingTarget)?;
        Ok(Self {
            identifier,
            target,
            target_relay_hint,
            extra_tags,
        })
    }
}

/// Typed bundle for a `kind: 818` merge-request event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRequest {
    /// Destination article coordinate (target of the merge).
    pub destination: Coordinate,
    /// Optional relay hint for the destination.
    pub destination_relay_hint: Option<RelayUrl>,
    /// Destination author pubkey (`p` tag).
    pub destination_pubkey: PublicKey,
    /// Optional base revision the modification was made against.
    pub base_revision: Option<EventId>,
    /// Optional relay hint for the base revision.
    pub base_revision_relay_hint: Option<RelayUrl>,
    /// Source revision (`e` tag with `source` marker — required by
    /// spec, but tolerated as `Option` to round-trip malformed
    /// events).
    pub source_revision: EventId,
    /// Optional relay hint for the source revision.
    pub source_revision_relay_hint: Option<RelayUrl>,
    /// `.content` — explanation of the merge.
    pub content: String,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl MergeRequest {
    /// Construct a merge request with the required spec columns.
    #[must_use]
    pub const fn new(
        destination: Coordinate,
        destination_pubkey: PublicKey,
        source_revision: EventId,
    ) -> Self {
        Self {
            destination,
            destination_relay_hint: None,
            destination_pubkey,
            base_revision: None,
            base_revision_relay_hint: None,
            source_revision,
            source_revision_relay_hint: None,
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Attach a relay hint for the destination coordinate.
    #[must_use]
    pub fn destination_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.destination_relay_hint = Some(relay);
        self
    }

    /// Set the base revision.
    #[must_use]
    pub const fn base_revision(mut self, id: EventId) -> Self {
        self.base_revision = Some(id);
        self
    }

    /// Attach a relay hint for the base revision.
    #[must_use]
    pub fn base_revision_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.base_revision_relay_hint = Some(relay);
        self
    }

    /// Attach a relay hint for the source revision.
    #[must_use]
    pub fn source_revision_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.source_revision_relay_hint = Some(relay);
        self
    }

    /// Set the explanation body.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Parse a `kind: 818` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`WikiError::WrongKind`] for any other kind.
    /// - [`WikiError::MissingTarget`] when no `a` tag is present.
    /// - [`WikiError::MissingMergePubkey`] when no `p` tag is
    ///   present.
    /// - [`WikiError::MissingMergeSource`] when no `e` tag with the
    ///   `source` marker is present.
    pub fn from_event(event: &Event) -> Result<Self, WikiError> {
        if event.kind != KIND_WIKI_MERGE_REQUEST {
            return Err(WikiError::WrongKind(event.kind));
        }
        let mut destination: Option<(Coordinate, Option<RelayUrl>)> = None;
        let mut destination_pubkey: Option<PublicKey> = None;
        let mut base_revision: Option<(EventId, Option<RelayUrl>)> = None;
        let mut source_revision: Option<(EventId, Option<RelayUrl>)> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::A && destination.is_none() =>
                {
                    let (coord, relay, _) = parse_a_tag_with_marker(tag)?;
                    destination = Some((coord, relay));
                }
                TagKind::SingleLetter(s)
                    if !s.uppercase
                        && s.character == Alphabet::P
                        && destination_pubkey.is_none() =>
                {
                    let pk_hex = tag.get(1).ok_or(WikiError::MissingMergePubkey)?;
                    destination_pubkey = Some(PublicKey::parse(pk_hex)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    absorb_merge_e_tag(
                        tag,
                        &mut source_revision,
                        &mut base_revision,
                        &mut extra_tags,
                    )?;
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        let (destination, destination_relay_hint) = destination.ok_or(WikiError::MissingTarget)?;
        let destination_pubkey = destination_pubkey.ok_or(WikiError::MissingMergePubkey)?;
        let (source_revision, source_revision_relay_hint) =
            source_revision.ok_or(WikiError::MissingMergeSource)?;
        let (base_revision, base_revision_relay_hint) =
            base_revision.map_or((None, None), |(id, relay)| (Some(id), relay));
        Ok(Self {
            destination,
            destination_relay_hint,
            destination_pubkey,
            base_revision,
            base_revision_relay_hint,
            source_revision,
            source_revision_relay_hint,
            content: event.content.clone(),
            extra_tags,
        })
    }
}

fn parse_a_tag_with_marker(
    tag: &Tag,
) -> Result<(Coordinate, Option<RelayUrl>, Option<String>), WikiError> {
    let coord_str = tag.get(1).ok_or(WikiError::MalformedAddressTag)?;
    let coord = Coordinate::parse(coord_str)?;
    let relay = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    let marker = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok((coord, relay, marker))
}

fn parse_e_tag_with_marker(
    tag: &Tag,
) -> Result<(EventId, Option<RelayUrl>, Option<String>), WikiError> {
    let id_hex = tag.get(1).ok_or(WikiError::MalformedEventTag)?;
    let id = EventId::parse(id_hex)?;
    let relay = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    let marker = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok((id, relay, marker))
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

/// Errors raised by NIP-54 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WikiError {
    /// The event was not a NIP-54 kind.
    #[error("unexpected kind for NIP-54 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag is absent.
    #[error("NIP-54 event missing `d` tag")]
    MissingIdentifier,
    /// `a` target tag is absent.
    #[error("NIP-54 event missing target `a` tag")]
    MissingTarget,
    /// Merge request `p` tag is absent.
    #[error("NIP-54 merge request missing `p` tag")]
    MissingMergePubkey,
    /// Merge request `e` tag with the `source` marker is absent.
    #[error("NIP-54 merge request missing source revision `e` tag")]
    MissingMergeSource,
    /// `a` tag column 1 is absent.
    #[error("`a` tag missing coordinate")]
    MalformedAddressTag,
    /// `e` tag column 1 is absent.
    #[error("`e` tag missing event id")]
    MalformedEventTag,
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped relay-url parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
}

impl EventBuilder {
    /// Author a NIP-54 `kind: 30818` wiki article event.
    #[must_use]
    pub fn wiki_article(article: &WikiArticle) -> Self {
        let mut builder = Self::new(KIND_WIKI_ARTICLE, article.content.clone());
        builder = builder.tag(Tag::d(&article.identifier));
        if let Some(title) = &article.title {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TITLE_TAG), [title.clone()]));
        }
        if let Some(summary) = &article.summary {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(SUMMARY_TAG),
                [summary.clone()],
            ));
        }
        for rel in &article.relations {
            builder = push_relation_tags(rel, builder);
        }
        for tag in &article.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-54 `kind: 30819` wiki redirect event.
    #[must_use]
    pub fn wiki_redirect(redirect: &WikiRedirect) -> Self {
        let mut builder = Self::new(KIND_WIKI_REDIRECT, "");
        builder = builder.tag(Tag::d(&redirect.identifier));
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        builder = builder.tag(redirect.target_relay_hint.as_ref().map_or_else(
            || Tag::with(&head, [redirect.target.to_wire()]),
            |relay| {
                Tag::with(
                    &head,
                    [redirect.target.to_wire(), relay.as_str().to_owned()],
                )
            },
        ));
        for tag in &redirect.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-54 `kind: 818` merge request event.
    ///
    /// Tag order matches spec example: destination `a`, base `e`,
    /// destination `p`, then source `e` with the `source` marker.
    #[must_use]
    pub fn wiki_merge_request(merge: &MergeRequest) -> Self {
        let mut builder = Self::new(KIND_WIKI_MERGE_REQUEST, merge.content.clone());
        let head_a = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        builder = builder.tag(merge.destination_relay_hint.as_ref().map_or_else(
            || Tag::with(&head_a, [merge.destination.to_wire()]),
            |relay| {
                Tag::with(
                    &head_a,
                    [merge.destination.to_wire(), relay.as_str().to_owned()],
                )
            },
        ));
        if let Some(base) = merge.base_revision {
            let head_e = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
            builder = builder.tag(merge.base_revision_relay_hint.as_ref().map_or_else(
                || Tag::with(&head_e, [base.to_hex()]),
                |relay| Tag::with(&head_e, [base.to_hex(), relay.as_str().to_owned()]),
            ));
        }
        let head_p = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        builder = builder.tag(Tag::with(&head_p, [merge.destination_pubkey.to_hex()]));
        let head_e = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let source_relay_str = merge
            .source_revision_relay_hint
            .as_ref()
            .map_or_else(String::new, |r| r.as_str().to_owned());
        builder = builder.tag(Tag::with(
            &head_e,
            [
                merge.source_revision.to_hex(),
                source_relay_str,
                SOURCE_MARKER.to_owned(),
            ],
        ));
        for tag in &merge.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }
}

fn push_relation_tags(rel: &RelationRef, mut builder: EventBuilder) -> EventBuilder {
    if let Some(coord) = &rel.coordinate {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        let relay_str = rel
            .coordinate_relay_hint
            .as_ref()
            .map_or_else(String::new, |r| r.as_str().to_owned());
        builder = builder.tag(Tag::with(
            &head,
            [coord.to_wire(), relay_str, rel.relation.as_str().to_owned()],
        ));
    }
    if let Some(id) = rel.event_id {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let relay_str = rel
            .event_relay_hint
            .as_ref()
            .map_or_else(String::new, |r| r.as_str().to_owned());
        builder = builder.tag(Tag::with(
            &head,
            [id.to_hex(), relay_str, rel.relation.as_str().to_owned()],
        ));
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn d_tag_normalisation_examples() {
        assert_eq!(normalize_d_tag("Wiki Article"), "wiki-article");
        assert_eq!(normalize_d_tag("What's Up?"), "whats-up");
        assert_eq!(normalize_d_tag("  Hello  World  "), "hello-world");
        assert_eq!(normalize_d_tag("Article 1"), "article-1");
        assert_eq!(normalize_d_tag("ウィキペディア"), "ウィキペディア");
        assert_eq!(normalize_d_tag("日本語 Article"), "日本語-article");
    }

    #[test]
    fn is_canonical_d_tag_basic_cases() {
        assert!(is_canonical_d_tag("wiki-article"));
        assert!(is_canonical_d_tag("article-1"));
        assert!(!is_canonical_d_tag("Wiki Article"));
        assert!(!is_canonical_d_tag("-leading"));
        assert!(!is_canonical_d_tag("trailing-"));
        assert!(!is_canonical_d_tag("double--dash"));
        assert!(!is_canonical_d_tag("with.punct"));
    }

    #[test]
    fn wiki_article_round_trip() {
        let article = WikiArticle::new("Wiki Article")
            .content("Wiki body")
            .title("Wiki Article")
            .summary("Short");
        let event = EventBuilder::wiki_article(&article)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = WikiArticle::from_event(&event).unwrap();
        assert_eq!(parsed, article);
        assert_eq!(parsed.identifier, "wiki-article");
    }

    #[test]
    fn wiki_redirect_round_trip() {
        let target = Coordinate::new(
            KIND_WIKI_ARTICLE,
            *keys().public_key(),
            "bitcoin".to_owned(),
        );
        let redirect = WikiRedirect::new("BTC", target)
            .target_relay_hint(RelayUrl::parse("wss://relay.example/").unwrap());
        let event = EventBuilder::wiki_redirect(&redirect)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = WikiRedirect::from_event(&event).unwrap();
        assert_eq!(parsed, redirect);
        assert_eq!(parsed.identifier, "btc");
    }

    #[test]
    fn merge_request_round_trip() {
        let destination = Coordinate::new(
            KIND_WIKI_ARTICLE,
            *keys().public_key(),
            "bitcoin".to_owned(),
        );
        let base = EventId::from_byte_array([0xaa; 32]);
        let src = EventId::from_byte_array([0xbb; 32]);
        let merge = MergeRequest::new(destination, *keys().public_key(), src)
            .base_revision(base)
            .content("Added section about block size");
        let event = EventBuilder::wiki_merge_request(&merge)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = MergeRequest::from_event(&event).unwrap();
        assert_eq!(parsed, merge);
    }

    #[test]
    fn wiki_article_wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            WikiArticle::from_event(&event),
            Err(WikiError::WrongKind(_))
        ));
    }

    #[test]
    fn wiki_redirect_missing_target_is_rejected() {
        let event = EventBuilder::new(KIND_WIKI_REDIRECT, "")
            .tag(Tag::d("btc"))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            WikiRedirect::from_event(&event),
            Err(WikiError::MissingTarget)
        ));
    }

    #[test]
    fn merge_request_missing_source_is_rejected() {
        let destination = Coordinate::new(
            KIND_WIKI_ARTICLE,
            *keys().public_key(),
            "bitcoin".to_owned(),
        );
        let event = EventBuilder::new(KIND_WIKI_MERGE_REQUEST, "")
            .tag(Tag::a(&destination))
            .tag(Tag::p(*keys().public_key()))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            MergeRequest::from_event(&event),
            Err(WikiError::MissingMergeSource)
        ));
    }
}
