//! [NIP-72] Moderated Communities (Reddit-style).
//!
//! Two new kinds drive the spec:
//!
//! | Kind   | Meaning                              | Type        |
//! |--------|--------------------------------------|-------------|
//! | 34550  | Community definition                 | Addressable |
//! | 4550   | Post approval                        | Regular     |
//!
//! Posts inside a community are normal **NIP-22** `kind: 1111`
//! comments tagged with the community `A`/`a` coordinate. The crate
//! already ships [`crate::nips::nip22::Comment`]; we add NIP-72
//! convenience constructors (`community_top_level_post`,
//! `community_reply_post`) so call-sites don't have to wire the
//! `K=34550` + `P=community-author` ceremony by hand.
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` does not ship a NIP-72 module — community
//! definitions and approvals must be hand-rolled. We model:
//!
//! - [`CommunityDefinition`] — the kind 34550 bundle: `d`,
//!   `name`, `description`, `image` (with optional dimensions),
//!   moderators, and relay hints with the four spec markers
//!   (`author`, `requests`, `approvals`, default).
//! - [`PostApproval`] — the kind 4550 bundle covering all three
//!   approval flavours (`e`-tag, `a`-tag, both) the spec allows
//!   for replaceable events.
//! - [`CommunityRelay`] / [`CommunityRelayMarker`] —
//!   forward-compatible enum for relay markers; unknown markers
//!   round-trip via `Other(String)`.
//!
//! [NIP-72]: https://github.com/nostr-protocol/nips/blob/master/72.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::nips::nip22::{Comment, CommentScope};
use crate::types::{ImageDimensions, ImageError, RelayUrl, RelayUrlError};

/// `kind: 34550` — community definition (addressable).
pub const KIND_COMMUNITY_DEFINITION: Kind = Kind::new(34_550);
/// `kind: 4550` — post approval.
pub const KIND_POST_APPROVAL: Kind = Kind::new(4_550);

/// Marker on a `relay` tag inside a community definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommunityRelayMarker {
    /// `author` — relay hosting the community owner's `kind: 0`.
    Author,
    /// `requests` — relay where post requests are sent.
    Requests,
    /// `approvals` — relay where approval events are sent.
    Approvals,
    /// No marker — generic recommended relay (spec allows this form).
    Default,
    /// Forward-compatible passthrough.
    Other(String),
}

impl CommunityRelayMarker {
    /// Render to wire form.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Author => Some("author"),
            Self::Requests => Some("requests"),
            Self::Approvals => Some("approvals"),
            Self::Default => None,
            Self::Other(s) => Some(s.as_str()),
        }
    }

    /// Parse a marker. `None` collapses to [`Self::Default`].
    #[must_use]
    pub fn parse(marker: Option<&str>) -> Self {
        match marker {
            None => Self::Default,
            Some("author") => Self::Author,
            Some("requests") => Self::Requests,
            Some("approvals") => Self::Approvals,
            Some(other) => Self::Other(other.to_owned()),
        }
    }
}

/// One community-defined `relay` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityRelay {
    /// Relay URL.
    pub url: RelayUrl,
    /// Marker (or [`CommunityRelayMarker::Default`] for unmarked).
    pub marker: CommunityRelayMarker,
}

impl CommunityRelay {
    /// Build a relay with a specific marker.
    #[must_use]
    pub const fn new(url: RelayUrl, marker: CommunityRelayMarker) -> Self {
        Self { url, marker }
    }

    /// Build an unmarked relay.
    #[must_use]
    pub const fn unmarked(url: RelayUrl) -> Self {
        Self {
            url,
            marker: CommunityRelayMarker::Default,
        }
    }
}

/// `image` tag inside a community definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityImage {
    /// Image URL. Spec leaves the format open so we keep a string.
    pub url: String,
    /// Optional `<width>x<height>` (NIP-94-style).
    pub dim: Option<ImageDimensions>,
}

impl CommunityImage {
    /// Build an image without explicit dimensions.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            dim: None,
        }
    }

    /// Set the dimensions.
    #[must_use]
    pub const fn dim(mut self, dim: ImageDimensions) -> Self {
        self.dim = Some(dim);
        self
    }
}

/// One moderator entry inside a community definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityModerator {
    /// Moderator pubkey.
    pub pubkey: PublicKey,
    /// Optional recommended relay for fetching their key / activity.
    pub relay_hint: Option<RelayUrl>,
}

impl CommunityModerator {
    /// Build a moderator without a relay hint.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
        }
    }

    /// Set the relay hint.
    #[must_use]
    pub fn relay_hint(mut self, hint: RelayUrl) -> Self {
        self.relay_hint = Some(hint);
        self
    }
}

/// Typed bundle for a `kind: 34550` community definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityDefinition {
    /// `d` tag identifier (the `(pubkey, 34550, d)` coordinate's `d`).
    pub identifier: String,
    /// `name` tag (defaults to the identifier when absent).
    pub name: Option<String>,
    /// `description` tag.
    pub description: Option<String>,
    /// `image` tag.
    pub image: Option<CommunityImage>,
    /// Moderators (`p` tags with the `"moderator"` marker).
    pub moderators: Vec<CommunityModerator>,
    /// Relay tags (with optional markers).
    pub relays: Vec<CommunityRelay>,
    /// Forward-compatible passthrough of any other `tags` rows.
    pub extra_tags: Vec<Tag>,
}

impl CommunityDefinition {
    /// Construct a community definition with only the `d` identifier
    /// set.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            name: None,
            description: None,
            image: None,
            moderators: Vec::new(),
            relays: Vec::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Set [`Self::name`].
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set [`Self::description`].
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set [`Self::image`].
    #[must_use]
    pub fn image(mut self, image: CommunityImage) -> Self {
        self.image = Some(image);
        self
    }

    /// Append one moderator.
    #[must_use]
    pub fn moderator(mut self, m: CommunityModerator) -> Self {
        self.moderators.push(m);
        self
    }

    /// Append one relay.
    #[must_use]
    pub fn relay(mut self, r: CommunityRelay) -> Self {
        self.relays.push(r);
        self
    }

    /// Append a passthrough tag (forward-compat).
    #[must_use]
    pub fn extra_tag(mut self, tag: Tag) -> Self {
        self.extra_tags.push(tag);
        self
    }

    /// Render to the tag list of a `kind: 34550` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(
            4 + self.moderators.len() + self.relays.len() + self.extra_tags.len(),
        );
        tags.push(Tag::d(&self.identifier));
        if let Some(name) = &self.name {
            tags.push(custom("name", [name.clone()]));
        }
        if let Some(desc) = &self.description {
            tags.push(custom("description", [desc.clone()]));
        }
        if let Some(image) = &self.image {
            let mut values: Vec<String> = Vec::with_capacity(2);
            values.push(image.url.clone());
            if let Some(dim) = image.dim {
                values.push(dim.to_string());
            }
            tags.push(custom("image", values));
        }
        for m in &self.moderators {
            let mut values: Vec<String> = Vec::with_capacity(4);
            values.push(m.pubkey.to_hex());
            values.push(
                m.relay_hint
                    .as_ref()
                    .map(|r| r.as_str().to_owned())
                    .unwrap_or_default(),
            );
            values.push("moderator".to_owned());
            tags.push(letter(Alphabet::P, values));
        }
        for r in &self.relays {
            let mut values: Vec<String> = Vec::with_capacity(2);
            values.push(r.url.as_str().to_owned());
            if let Some(marker) = r.marker.as_str() {
                values.push(marker.to_owned());
            }
            tags.push(custom("relay", values));
        }
        for tag in &self.extra_tags {
            tags.push(tag.clone());
        }
        tags
    }

    /// Parse a `kind: 34550` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`CommunityError::WrongKind`] for any other kind.
    /// - [`CommunityError::MissingIdentifier`] when no `d` tag.
    /// - [`CommunityError::InvalidPublicKey`] /
    ///   [`CommunityError::InvalidRelayUrl`] /
    ///   [`CommunityError::InvalidImageDim`] for malformed values.
    pub fn from_event(event: &Event) -> Result<Self, CommunityError> {
        if event.kind != KIND_COMMUNITY_DEFINITION {
            return Err(CommunityError::WrongKind(event.kind));
        }
        let identifier = identifier_value(&event.tags)
            .ok_or(CommunityError::MissingIdentifier)?
            .to_owned();
        let mut def = Self::new(identifier);

        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {
                    // Identifier already captured.
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    handle_p_tag(tag, &mut def)?;
                }
                TagKind::Custom(name) if name == "name" => {
                    def.name = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "description" => {
                    def.description = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "image" => {
                    def.image = parse_image(tag)?;
                }
                TagKind::Custom(name) if name == "relay" => {
                    def.relays.push(parse_relay(tag)?);
                }
                _ => def.extra_tags.push(tag.clone()),
            }
        }
        Ok(def)
    }

    /// Build the community's addressable coordinate.
    ///
    /// `author` is the community owner's pubkey (the event creator).
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_COMMUNITY_DEFINITION, author, self.identifier.clone())
    }
}

fn handle_p_tag(tag: &Tag, def: &mut CommunityDefinition) -> Result<(), CommunityError> {
    if tag.get(3) == Some("moderator") {
        def.moderators.push(parse_moderator(tag)?);
    } else {
        def.extra_tags.push(tag.clone());
    }
    Ok(())
}

fn parse_a_tag(tag: &Tag) -> Result<(Coordinate, Option<RelayUrl>), ApprovalError> {
    let coord_str = tag.get(1).ok_or(ApprovalError::MalformedAddressTag)?;
    let coord = Coordinate::parse(coord_str).map_err(ApprovalError::InvalidCoordinate)?;
    let relay = tag_optional_relay(tag, 2)?;
    Ok((coord, relay))
}

fn dispatch_a_tag(
    parsed: (Coordinate, Option<RelayUrl>),
    community: &mut Option<(Coordinate, Option<RelayUrl>)>,
    address_target: &mut Option<(Coordinate, Option<RelayUrl>)>,
) {
    if parsed.0.kind == KIND_COMMUNITY_DEFINITION && community.is_none() {
        *community = Some(parsed);
    } else {
        *address_target = Some(parsed);
    }
}

fn parse_moderator(tag: &Tag) -> Result<CommunityModerator, CommunityError> {
    let pk_hex = tag.get(1).ok_or(CommunityError::MalformedModerator)?;
    let pubkey = PublicKey::parse(pk_hex).map_err(CommunityError::InvalidPublicKey)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => {
            Some(RelayUrl::parse(s).map_err(CommunityError::InvalidRelayUrl)?)
        }
        _ => None,
    };
    Ok(CommunityModerator { pubkey, relay_hint })
}

fn parse_image(tag: &Tag) -> Result<Option<CommunityImage>, CommunityError> {
    let Some(url) = tag.get(1) else {
        return Ok(None);
    };
    let mut image = CommunityImage::new(url.to_owned());
    if let Some(dim_str) = tag.get(2)
        && !dim_str.is_empty()
    {
        image.dim = Some(
            dim_str
                .parse::<ImageDimensions>()
                .map_err(CommunityError::InvalidImageDim)?,
        );
    }
    Ok(Some(image))
}

fn parse_relay(tag: &Tag) -> Result<CommunityRelay, CommunityError> {
    let url_str = tag.get(1).ok_or(CommunityError::MalformedRelay)?;
    let url = RelayUrl::parse(url_str).map_err(CommunityError::InvalidRelayUrl)?;
    let marker = CommunityRelayMarker::parse(tag.get(2));
    Ok(CommunityRelay { url, marker })
}

fn identifier_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

fn custom<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::Custom(name.to_owned()), args)
}

fn letter<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(alphabet));
    Tag::with(&head, args)
}

/// Pointer to the post being approved.
///
/// Spec §"Moderation" allows three forms:
/// - `e`-tag only (regular events, or one specific replaceable
///   version);
/// - `a`-tag only (replaceable events at any version);
/// - both, so clients can show "the version at the time of approval".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalTarget {
    /// Approval points at a specific event id.
    Event {
        /// Event id of the post.
        id: EventId,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// Approval points at a replaceable event coordinate.
    Address {
        /// Coordinate of the post.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// Approval pins a specific version (`e`) of an addressable
    /// post (`a`).
    Both {
        /// Event id of the snapshot version.
        id: EventId,
        /// Coordinate of the addressable post.
        coordinate: Coordinate,
        /// Optional relay hint reused on both tags.
        relay_hint: Option<RelayUrl>,
    },
}

/// Typed bundle for a `kind: 4550` post approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostApproval {
    /// Coordinate of the community whose moderators are approving.
    pub community: Coordinate,
    /// Optional relay hint for the community `a` tag.
    pub community_relay: Option<RelayUrl>,
    /// Pointer to the approved post.
    pub target: ApprovalTarget,
    /// Original post's kind (`k` tag).
    pub post_kind: Kind,
    /// Original post's author (`p` tag).
    pub post_author: PublicKey,
    /// Optional relay hint for the post-author `p` tag.
    pub post_author_relay: Option<RelayUrl>,
    /// JSON-encoded original post per spec §"Moderation"
    /// recommendation.
    pub original_event_json: String,
}

impl PostApproval {
    /// Construct a typed approval.
    #[must_use]
    pub fn new(
        community: Coordinate,
        target: ApprovalTarget,
        post_kind: Kind,
        post_author: PublicKey,
        original_event_json: impl Into<String>,
    ) -> Self {
        Self {
            community,
            community_relay: None,
            target,
            post_kind,
            post_author,
            post_author_relay: None,
            original_event_json: original_event_json.into(),
        }
    }

    /// Add a relay hint to the community `a` tag.
    #[must_use]
    pub fn community_relay(mut self, relay: RelayUrl) -> Self {
        self.community_relay = Some(relay);
        self
    }

    /// Add a relay hint to the post-author `p` tag.
    #[must_use]
    pub fn post_author_relay(mut self, relay: RelayUrl) -> Self {
        self.post_author_relay = Some(relay);
        self
    }

    /// Render to the tag list of a `kind: 4550` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(5);
        // Community a-tag (lowercase per spec example).
        let mut a_values: Vec<String> = Vec::with_capacity(2);
        a_values.push(self.community.to_wire());
        if let Some(relay) = &self.community_relay {
            a_values.push(relay.as_str().to_owned());
        }
        tags.push(letter(Alphabet::A, a_values));

        // Approval target tags.
        match &self.target {
            ApprovalTarget::Event { id, relay_hint } => {
                tags.push(event_tag(*id, relay_hint.as_ref()));
            }
            ApprovalTarget::Address {
                coordinate,
                relay_hint,
            } => {
                tags.push(address_tag(coordinate, relay_hint.as_ref()));
            }
            ApprovalTarget::Both {
                id,
                coordinate,
                relay_hint,
            } => {
                tags.push(event_tag(*id, relay_hint.as_ref()));
                tags.push(address_tag(coordinate, relay_hint.as_ref()));
            }
        }

        // Post author p-tag.
        let mut p_values: Vec<String> = Vec::with_capacity(2);
        p_values.push(self.post_author.to_hex());
        if let Some(relay) = &self.post_author_relay {
            p_values.push(relay.as_str().to_owned());
        }
        tags.push(letter(Alphabet::P, p_values));

        // Post kind k-tag.
        tags.push(letter(Alphabet::K, [self.post_kind.as_u16().to_string()]));
        tags
    }

    /// Parse a `kind: 4550` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// Forwarded from [`Coordinate::parse`] / [`PublicKey::parse`] /
    /// [`RelayUrl::parse`] when the corresponding tag column is
    /// malformed, plus the dedicated `Missing*` errors when a
    /// required tag is absent.
    pub fn from_event(event: &Event) -> Result<Self, ApprovalError> {
        if event.kind != KIND_POST_APPROVAL {
            return Err(ApprovalError::WrongKind(event.kind));
        }

        let mut community: Option<(Coordinate, Option<RelayUrl>)> = None;
        let mut event_target: Option<(EventId, Option<RelayUrl>)> = None;
        let mut address_target: Option<(Coordinate, Option<RelayUrl>)> = None;
        let mut post_author: Option<(PublicKey, Option<RelayUrl>)> = None;
        let mut post_kind: Option<Kind> = None;

        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    dispatch_a_tag(parse_a_tag(tag)?, &mut community, &mut address_target);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    let id_hex = tag.get(1).ok_or(ApprovalError::MalformedEventTag)?;
                    let id = EventId::parse(id_hex).map_err(ApprovalError::InvalidEventId)?;
                    let relay = tag_optional_relay(tag, 2)?;
                    event_target = Some((id, relay));
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(ApprovalError::MalformedAuthorTag)?;
                    let pk = PublicKey::parse(pk_hex).map_err(ApprovalError::InvalidPublicKey)?;
                    let relay = tag_optional_relay(tag, 2)?;
                    post_author = Some((pk, relay));
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::K => {
                    let k_str = tag.get(1).ok_or(ApprovalError::MalformedKindTag)?;
                    let raw: u16 = k_str.parse().map_err(|_| ApprovalError::MalformedKindTag)?;
                    post_kind = Some(Kind::new(raw));
                }
                _ => {}
            }
        }

        let (community, community_relay) = community.ok_or(ApprovalError::MissingCommunity)?;
        let target = match (event_target, address_target) {
            (Some((id, r1)), Some((coordinate, r2))) => ApprovalTarget::Both {
                id,
                coordinate,
                relay_hint: r1.or(r2),
            },
            (Some((id, relay_hint)), None) => ApprovalTarget::Event { id, relay_hint },
            (None, Some((coordinate, relay_hint))) => ApprovalTarget::Address {
                coordinate,
                relay_hint,
            },
            (None, None) => return Err(ApprovalError::MissingTarget),
        };
        let (post_author, post_author_relay) =
            post_author.ok_or(ApprovalError::MissingPostAuthor)?;
        let post_kind = post_kind.ok_or(ApprovalError::MissingPostKind)?;

        Ok(Self {
            community,
            community_relay,
            target,
            post_kind,
            post_author,
            post_author_relay,
            original_event_json: event.content.clone(),
        })
    }
}

fn event_tag(id: EventId, relay: Option<&RelayUrl>) -> Tag {
    let mut values: Vec<String> = Vec::with_capacity(2);
    values.push(id.to_hex());
    if let Some(r) = relay {
        values.push(r.as_str().to_owned());
    }
    letter(Alphabet::E, values)
}

fn address_tag(coordinate: &Coordinate, relay: Option<&RelayUrl>) -> Tag {
    let mut values: Vec<String> = Vec::with_capacity(2);
    values.push(coordinate.to_wire());
    if let Some(r) = relay {
        values.push(r.as_str().to_owned());
    }
    letter(Alphabet::A, values)
}

fn tag_optional_relay(tag: &Tag, idx: usize) -> Result<Option<RelayUrl>, ApprovalError> {
    match tag.get(idx) {
        Some(s) if !s.is_empty() => Ok(Some(
            RelayUrl::parse(s).map_err(ApprovalError::InvalidRelayUrl)?,
        )),
        _ => Ok(None),
    }
}

/// Errors raised while parsing a [`CommunityDefinition`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CommunityError {
    /// Event kind was not 34550.
    #[error("expected kind 34550 (community definition), got {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag was absent.
    #[error("NIP-72 community must carry a `d` tag")]
    MissingIdentifier,
    /// A `p` moderator tag was missing the pubkey column.
    #[error("malformed `p` moderator tag (missing pubkey)")]
    MalformedModerator,
    /// A `relay` tag was missing its URL column.
    #[error("malformed `relay` tag (missing URL)")]
    MalformedRelay,
    /// A pubkey value did not parse.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// A relay URL did not parse.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
    /// `image[2]` failed [`ImageDimensions::from_str`].
    #[error("invalid image dimensions: {0}")]
    InvalidImageDim(#[source] ImageError),
}

/// Errors raised while parsing a [`PostApproval`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// Event kind was not 4550.
    #[error("expected kind 4550 (post approval), got {}", .0.as_u16())]
    WrongKind(Kind),
    /// No community `a` tag was present.
    #[error("NIP-72 approval must carry a community `a` tag")]
    MissingCommunity,
    /// No `e`/`a` target tag was present.
    #[error("NIP-72 approval must carry an `e` and/or `a` post tag")]
    MissingTarget,
    /// No `p` author tag was present.
    #[error("NIP-72 approval must carry a `p` author tag")]
    MissingPostAuthor,
    /// No `k` kind tag was present.
    #[error("NIP-72 approval must carry a `k` kind tag")]
    MissingPostKind,
    /// `e` tag value was missing.
    #[error("malformed `e` post tag (missing event id)")]
    MalformedEventTag,
    /// `a` tag value was missing.
    #[error("malformed `a` tag (missing coordinate)")]
    MalformedAddressTag,
    /// `p` tag value was missing.
    #[error("malformed `p` tag (missing author)")]
    MalformedAuthorTag,
    /// `k` tag was malformed.
    #[error("malformed `k` tag (must be unsigned 16-bit kind number)")]
    MalformedKindTag,
    /// Coordinate string was not parseable.
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(#[source] CoordinateError),
    /// Event id hex was not parseable.
    #[error("invalid event id: {0}")]
    InvalidEventId(#[source] EventIdError),
    /// Pubkey hex was not parseable.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// Relay URL was not parseable.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
}

impl EventBuilder {
    /// Author a NIP-72 community definition (`kind: 34550`).
    #[must_use]
    pub fn community_definition(definition: &CommunityDefinition) -> Self {
        let mut builder = Self::new(KIND_COMMUNITY_DEFINITION, "");
        for tag in definition.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-72 post approval (`kind: 4550`).
    #[must_use]
    pub fn community_post_approval(approval: &PostApproval) -> Self {
        let mut builder = Self::new(KIND_POST_APPROVAL, approval.original_event_json.clone());
        for tag in approval.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a top-level community post (`kind: 1111` per NIP-22
    /// + NIP-72 §"Top-level posts").
    ///
    /// Internally builds a [`Comment`] whose root *and* parent are
    /// the community coordinate.
    #[must_use]
    pub fn community_top_level_post(
        community: Coordinate,
        community_relay: Option<RelayUrl>,
        community_author: PublicKey,
        content: impl Into<String>,
    ) -> Self {
        let scope = CommentScope::Address {
            coordinate: community,
            relay_hint: community_relay,
        };
        let comment = Comment::top_level(scope, content)
            .with_root_kind(KIND_COMMUNITY_DEFINITION)
            .with_root_author(community_author);
        Self::comment(&comment)
    }

    /// Author a nested community reply (`kind: 1111` per NIP-22
    /// + NIP-72 §"Nested replies").
    ///
    /// `parent_post` is the parent kind 1111 reply (or another
    /// post). The community coordinate stays at the *root* scope
    /// while `parent_post` lives at the *parent* scope.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "every argument maps directly to a NIP-72 §\"Nested replies\" tag column"
    )]
    pub fn community_nested_reply(
        community: Coordinate,
        community_relay: Option<RelayUrl>,
        community_author: PublicKey,
        parent_post: EventId,
        parent_relay: Option<RelayUrl>,
        parent_kind: Kind,
        parent_author: PublicKey,
        content: impl Into<String>,
    ) -> Self {
        let root = CommentScope::Address {
            coordinate: community,
            relay_hint: community_relay,
        };
        let parent = CommentScope::Event {
            id: parent_post,
            relay_hint: parent_relay,
        };
        let comment = Comment::top_level(root, content)
            .with_root_kind(KIND_COMMUNITY_DEFINITION)
            .with_root_author(community_author)
            .with_parent(parent)
            .with_parent_kind(parent_kind)
            .with_parent_author(parent_author);
        Self::comment(&comment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    fn fixture_definition() -> CommunityDefinition {
        let owner = *keys().public_key();
        let _ = owner;
        let mod1 = CommunityModerator::new(*keys().public_key())
            .relay_hint(RelayUrl::parse("wss://moderator-relay.example/").unwrap());
        let mod2 = CommunityModerator::new(*other_keys().public_key());
        let auth_relay = CommunityRelay::new(
            RelayUrl::parse("wss://author.example/").unwrap(),
            CommunityRelayMarker::Author,
        );
        let req_relay = CommunityRelay::new(
            RelayUrl::parse("wss://requests.example/").unwrap(),
            CommunityRelayMarker::Requests,
        );
        let plain_relay =
            CommunityRelay::unmarked(RelayUrl::parse("wss://plain.example/").unwrap());
        CommunityDefinition::new("rust-nostr")
            .name("Rust Nostr")
            .description("Implementations and discussion")
            .image(
                CommunityImage::new("https://example.com/logo.png")
                    .dim(ImageDimensions::new(800, 600).unwrap()),
            )
            .moderator(mod1)
            .moderator(mod2)
            .relay(auth_relay)
            .relay(req_relay)
            .relay(plain_relay)
    }

    #[test]
    fn community_definition_round_trips_through_event() {
        let def = fixture_definition();
        let event = EventBuilder::community_definition(&def)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_COMMUNITY_DEFINITION);
        let parsed = CommunityDefinition::from_event(&event).unwrap();
        assert_eq!(parsed, def);
    }

    #[test]
    fn community_definition_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            CommunityDefinition::from_event(&event),
            Err(CommunityError::WrongKind(_))
        ));
    }

    #[test]
    fn community_definition_requires_d_tag() {
        let event = EventBuilder::new(KIND_COMMUNITY_DEFINITION, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            CommunityDefinition::from_event(&event),
            Err(CommunityError::MissingIdentifier)
        ));
    }

    #[test]
    fn community_relay_marker_round_trips_unknown() {
        let m = CommunityRelayMarker::parse(Some("custom-marker"));
        assert_eq!(m, CommunityRelayMarker::Other("custom-marker".to_owned()));
        assert_eq!(m.as_str(), Some("custom-marker"));
    }

    #[test]
    fn coordinate_helper_uses_owner_pubkey() {
        let def = CommunityDefinition::new("slug");
        let coord = def.coordinate(*keys().public_key());
        assert_eq!(coord.kind, KIND_COMMUNITY_DEFINITION);
        assert_eq!(coord.identifier, "slug");
        assert_eq!(coord.author, *keys().public_key());
    }

    #[test]
    fn approval_with_event_target_round_trips() {
        let community = Coordinate::new(KIND_COMMUNITY_DEFINITION, *keys().public_key(), "slug");
        let id = EventId::from_byte_array([0x77; 32]);
        let approval = PostApproval::new(
            community,
            ApprovalTarget::Event {
                id,
                relay_hint: None,
            },
            Kind::TEXT_NOTE,
            *other_keys().public_key(),
            r#"{"id":"77...","kind":1}"#,
        );
        let event = EventBuilder::community_post_approval(&approval)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_POST_APPROVAL);
        let parsed = PostApproval::from_event(&event).unwrap();
        assert_eq!(parsed, approval);
    }

    #[test]
    fn approval_with_address_target_round_trips() {
        let community = Coordinate::new(KIND_COMMUNITY_DEFINITION, *keys().public_key(), "slug");
        let target_coord = Coordinate::new(
            Kind::LONG_FORM_TEXT_NOTE,
            *other_keys().public_key(),
            "post-1",
        );
        let approval = PostApproval::new(
            community,
            ApprovalTarget::Address {
                coordinate: target_coord,
                relay_hint: None,
            },
            Kind::LONG_FORM_TEXT_NOTE,
            *other_keys().public_key(),
            "{}",
        );
        let event = EventBuilder::community_post_approval(&approval)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PostApproval::from_event(&event).unwrap();
        assert_eq!(parsed, approval);
    }

    #[test]
    fn approval_with_both_targets_round_trips() {
        let community = Coordinate::new(KIND_COMMUNITY_DEFINITION, *keys().public_key(), "slug");
        let target_coord = Coordinate::new(
            Kind::LONG_FORM_TEXT_NOTE,
            *other_keys().public_key(),
            "post-1",
        );
        let target_id = EventId::from_byte_array([0xab; 32]);
        let approval = PostApproval::new(
            community,
            ApprovalTarget::Both {
                id: target_id,
                coordinate: target_coord,
                relay_hint: None,
            },
            Kind::LONG_FORM_TEXT_NOTE,
            *other_keys().public_key(),
            "{}",
        );
        let event = EventBuilder::community_post_approval(&approval)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PostApproval::from_event(&event).unwrap();
        assert_eq!(parsed, approval);
    }

    #[test]
    fn approval_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            PostApproval::from_event(&event),
            Err(ApprovalError::WrongKind(_))
        ));
    }

    #[test]
    fn community_top_level_post_uses_kind_1111() {
        let community = Coordinate::new(KIND_COMMUNITY_DEFINITION, *keys().public_key(), "slug");
        let event =
            EventBuilder::community_top_level_post(community, None, *keys().public_key(), "hi")
                .sign_with_keys(&other_keys())
                .unwrap();
        assert_eq!(event.kind, Kind::new(1111));
    }

    #[test]
    fn community_nested_reply_uses_kind_1111() {
        let community = Coordinate::new(KIND_COMMUNITY_DEFINITION, *keys().public_key(), "slug");
        let parent = EventId::from_byte_array([0xab; 32]);
        let event = EventBuilder::community_nested_reply(
            community,
            None,
            *keys().public_key(),
            parent,
            None,
            Kind::new(1111),
            *other_keys().public_key(),
            "agreed",
        )
        .sign_with_keys(&other_keys())
        .unwrap();
        assert_eq!(event.kind, Kind::new(1111));
    }
}
