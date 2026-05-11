//! [NIP-58] Badges.
//!
//! Four kinds wire up the badge ecosystem:
//!
//! | Kind   | Type        | Purpose                                  |
//! |--------|-------------|------------------------------------------|
//! | 30009  | Addressable | Badge definition (immutable design)      |
//! | 8      | Regular     | Badge award (issuer → awardee bundle)    |
//! | 10008  | Replaceable | Profile badges list (chosen-by-recipient)|
//! | 30008  | Addressable | Badge sets (organising chosen badges)    |
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` has only a thin `Tag::badge_*` helper for
//! profile-badge tag building; everything else is hand-rolled. We
//! ship the full set:
//!
//! - [`BadgeDefinition`] — the kind 30009 bundle with `name`,
//!   `description`, full-resolution `image`, and any number of
//!   `thumb` variants. The image carries optional NIP-94-style
//!   dimensions.
//! - [`BadgeAward`] — the kind 8 bundle with the addressable
//!   coordinate of the definition plus one or more awardee `p`
//!   tags (with optional relay hints).
//! - [`ProfileBadges`] — the kind 10008 list. The spec says
//!   "ordered consecutive pairs of `a` and `e` tags"; we surface
//!   that as `Vec<ProfileBadgeEntry>` with a strong invariant
//!   (every entry has both halves) and the reader silently drops
//!   orphaned single-tag rows the spec also tells us to ignore.
//!
//! Spec §"Deprecated Profile Badges event" recognises the old
//! `kind: 30008` + `d=profile_badges` form: [`ProfileBadges::from_event`]
//! accepts both kinds for forward compatibility, and surfaces the
//! detected form via [`ProfileBadgesSource`].
//!
//! [NIP-58]: https://github.com/nostr-protocol/nips/blob/master/58.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{ImageDimensions, ImageError, RelayUrl, RelayUrlError};

/// `kind: 30009` — badge definition.
pub const KIND_BADGE_DEFINITION: Kind = Kind::BADGE_DEFINITION;
/// `kind: 8` — badge award.
pub const KIND_BADGE_AWARD: Kind = Kind::BADGE_AWARD;
/// `kind: 10008` — profile badges list (modern form).
pub const KIND_PROFILE_BADGES: Kind = Kind::PROFILE_BADGES;
/// `kind: 30008` — deprecated profile badges (`d = "profile_badges"`).
pub const KIND_BADGE_SET: Kind = Kind::BADGE_SET;
/// `d`-tag value used by the deprecated `kind: 30008` profile-badges
/// form (NIP-58 §"Deprecated Profile Badges event").
pub const DEPRECATED_PROFILE_BADGES_IDENTIFIER: &str = "profile_badges";

/// One image variant inside a badge — the high-res `image` or any
/// `thumb` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeImage {
    /// Image URL.
    pub url: String,
    /// Optional `<width>x<height>`.
    pub dim: Option<ImageDimensions>,
}

impl BadgeImage {
    /// Construct without dimensions.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            dim: None,
        }
    }

    /// Set dimensions.
    #[must_use]
    pub const fn dim(mut self, dim: ImageDimensions) -> Self {
        self.dim = Some(dim);
        self
    }

    fn to_tag(&self, name: &str) -> Tag {
        let mut values: Vec<String> = Vec::with_capacity(2);
        values.push(self.url.clone());
        if let Some(dim) = self.dim {
            values.push(dim.to_string());
        }
        custom_tag(name, values)
    }

    fn from_tag(tag: &Tag) -> Result<Option<Self>, BadgeError> {
        let Some(url) = tag.get(1) else {
            return Ok(None);
        };
        let mut img = Self::new(url);
        if let Some(d) = tag.get(2)
            && !d.is_empty()
        {
            img.dim = Some(
                d.parse::<ImageDimensions>()
                    .map_err(BadgeError::InvalidImageDim)?,
            );
        }
        Ok(Some(img))
    }
}

/// Typed bundle for a `kind: 30009` badge definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeDefinition {
    /// `d` tag — unique slug (`bravery`, …).
    pub identifier: String,
    /// `name` tag — short display name.
    pub name: Option<String>,
    /// `description` tag.
    pub description: Option<String>,
    /// `image` tag (high-res).
    pub image: Option<BadgeImage>,
    /// `thumb` tags (zero or more variants).
    pub thumbnails: Vec<BadgeImage>,
}

impl BadgeDefinition {
    /// Construct an empty definition.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            name: None,
            description: None,
            image: None,
            thumbnails: Vec::new(),
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
    pub fn image(mut self, image: BadgeImage) -> Self {
        self.image = Some(image);
        self
    }

    /// Append one [`thumbnails`](Self::thumbnails) variant.
    #[must_use]
    pub fn thumbnail(mut self, thumb: BadgeImage) -> Self {
        self.thumbnails.push(thumb);
        self
    }

    /// Render to the tag list of a `kind: 30009` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(4 + self.thumbnails.len());
        tags.push(Tag::d(&self.identifier));
        if let Some(name) = &self.name {
            tags.push(custom_tag("name", [name.clone()]));
        }
        if let Some(desc) = &self.description {
            tags.push(custom_tag("description", [desc.clone()]));
        }
        if let Some(img) = &self.image {
            tags.push(img.to_tag("image"));
        }
        for thumb in &self.thumbnails {
            tags.push(thumb.to_tag("thumb"));
        }
        tags
    }

    /// Parse a `kind: 30009` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`BadgeError::WrongKind`] for any other kind.
    /// - [`BadgeError::MissingIdentifier`] when no `d` tag.
    /// - [`BadgeError::InvalidImageDim`] when an image dimension
    ///   token is malformed.
    pub fn from_event(event: &Event) -> Result<Self, BadgeError> {
        if event.kind != KIND_BADGE_DEFINITION {
            return Err(BadgeError::WrongKind(event.kind));
        }
        let identifier = identifier_value(&event.tags)
            .ok_or(BadgeError::MissingIdentifier)?
            .to_owned();
        let mut def = Self::new(identifier);
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::Custom(name) if name == "name" => {
                    def.name = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "description" => {
                    def.description = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "image" => {
                    def.image = BadgeImage::from_tag(tag)?;
                }
                TagKind::Custom(name) if name == "thumb" => {
                    push_thumbnail(tag, &mut def.thumbnails)?;
                }
                _ => {}
            }
        }
        Ok(def)
    }

    /// Build the badge's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, issuer: PublicKey) -> Coordinate {
        Coordinate::new(KIND_BADGE_DEFINITION, issuer, self.identifier.clone())
    }
}

/// One awardee entry inside a badge award.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeAwardee {
    /// Awardee pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint where the awardee can be found.
    pub relay_hint: Option<RelayUrl>,
}

impl BadgeAwardee {
    /// Construct without a relay hint.
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

/// Typed bundle for a `kind: 8` badge award.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeAward {
    /// Coordinate of the badge definition (`a` tag value).
    pub definition: Coordinate,
    /// Awardees (one or more `p` tags). Spec mandates `>= 1`.
    pub awardees: Vec<BadgeAwardee>,
}

impl BadgeAward {
    /// Construct an award with one awardee. Use
    /// [`Self::awardee`] to chain more.
    #[must_use]
    pub fn new(definition: Coordinate, awardee: BadgeAwardee) -> Self {
        Self {
            definition,
            awardees: vec![awardee],
        }
    }

    /// Add another awardee.
    #[must_use]
    pub fn awardee(mut self, awardee: BadgeAwardee) -> Self {
        self.awardees.push(awardee);
        self
    }

    /// Render to the tag list of a `kind: 8` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(1 + self.awardees.len());
        tags.push(letter_tag(Alphabet::A, [self.definition.to_wire()]));
        for awardee in &self.awardees {
            let mut values: Vec<String> = Vec::with_capacity(2);
            values.push(awardee.pubkey.to_hex());
            if let Some(relay) = &awardee.relay_hint {
                values.push(relay.as_str().to_owned());
            }
            tags.push(letter_tag(Alphabet::P, values));
        }
        tags
    }

    /// Parse a `kind: 8` event.
    ///
    /// # Errors
    ///
    /// - [`BadgeError::WrongKind`] for any other kind.
    /// - [`BadgeError::MissingDefinition`] when no `a` tag.
    /// - [`BadgeError::MissingAwardee`] when no `p` tag.
    /// - Forwarded parse errors for malformed coordinates / pubkeys.
    pub fn from_event(event: &Event) -> Result<Self, BadgeError> {
        if event.kind != KIND_BADGE_AWARD {
            return Err(BadgeError::WrongKind(event.kind));
        }
        let mut definition: Option<Coordinate> = None;
        let mut awardees: Vec<BadgeAwardee> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    let coord_str = tag.get(1).ok_or(BadgeError::MalformedDefinition)?;
                    definition =
                        Some(Coordinate::parse(coord_str).map_err(BadgeError::InvalidCoordinate)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(BadgeError::MalformedAwardee)?;
                    let pubkey = PublicKey::parse(pk_hex).map_err(BadgeError::InvalidPublicKey)?;
                    let relay_hint = parse_optional_relay(tag.get(2))?;
                    awardees.push(BadgeAwardee { pubkey, relay_hint });
                }
                _ => {}
            }
        }
        let definition = definition.ok_or(BadgeError::MissingDefinition)?;
        if awardees.is_empty() {
            return Err(BadgeError::MissingAwardee);
        }
        Ok(Self {
            definition,
            awardees,
        })
    }
}

/// One row inside a profile-badges list — paired (`a`, `e`) tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileBadgeEntry {
    /// Coordinate of the badge definition (`a` tag).
    pub definition: Coordinate,
    /// Optional relay hint accompanying the `a` tag.
    pub definition_relay: Option<RelayUrl>,
    /// Event id of the matching badge award (`e` tag).
    pub award: EventId,
    /// Optional relay hint accompanying the `e` tag.
    pub award_relay: Option<RelayUrl>,
}

impl ProfileBadgeEntry {
    /// Construct an entry without relay hints.
    #[must_use]
    pub const fn new(definition: Coordinate, award: EventId) -> Self {
        Self {
            definition,
            definition_relay: None,
            award,
            award_relay: None,
        }
    }

    /// Set the relay hint on the `a` tag.
    #[must_use]
    pub fn definition_relay(mut self, hint: RelayUrl) -> Self {
        self.definition_relay = Some(hint);
        self
    }

    /// Set the relay hint on the `e` tag.
    #[must_use]
    pub fn award_relay(mut self, hint: RelayUrl) -> Self {
        self.award_relay = Some(hint);
        self
    }
}

/// Did the profile-badges event arrive in the modern form
/// (`kind: 10008`) or in the deprecated `kind: 30008` /
/// `d=profile_badges` form?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileBadgesSource {
    /// Modern `kind: 10008`.
    Replaceable,
    /// Deprecated `kind: 30008` + `d = profile_badges`.
    DeprecatedAddressable,
}

/// Typed bundle for a profile-badges list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileBadges {
    /// Ordered (`a`, `e`) pairs.
    pub entries: Vec<ProfileBadgeEntry>,
}

impl ProfileBadges {
    /// Empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append one entry.
    #[must_use]
    pub fn entry(mut self, entry: ProfileBadgeEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Render to the tag list of a `kind: 10008` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(self.entries.len() * 2);
        for entry in &self.entries {
            let mut a_values: Vec<String> = Vec::with_capacity(2);
            a_values.push(entry.definition.to_wire());
            if let Some(r) = &entry.definition_relay {
                a_values.push(r.as_str().to_owned());
            }
            tags.push(letter_tag(Alphabet::A, a_values));
            let mut e_values: Vec<String> = Vec::with_capacity(2);
            e_values.push(entry.award.to_hex());
            if let Some(r) = &entry.award_relay {
                e_values.push(r.as_str().to_owned());
            }
            tags.push(letter_tag(Alphabet::E, e_values));
        }
        tags
    }

    /// Parse a `kind: 10008` (modern) or `kind: 30008` (deprecated)
    /// profile-badges event into a typed bundle.
    ///
    /// Orphaned `a` / `e` tags (without their pair) are silently
    /// skipped per spec §"Profile Badges Event": *"Clients SHOULD
    /// ignore `a` without corresponding `e` tag and viceversa"*.
    ///
    /// # Errors
    ///
    /// - [`BadgeError::WrongKind`] for unrelated kinds.
    /// - Forwarded parse errors when an `a` / `e` value is
    ///   malformed.
    pub fn from_event(event: &Event) -> Result<(Self, ProfileBadgesSource), BadgeError> {
        let source = match event.kind {
            KIND_PROFILE_BADGES => ProfileBadgesSource::Replaceable,
            KIND_BADGE_SET
                if event
                    .tags
                    .identifier()
                    .is_some_and(|d| d == DEPRECATED_PROFILE_BADGES_IDENTIFIER) =>
            {
                ProfileBadgesSource::DeprecatedAddressable
            }
            other => return Err(BadgeError::WrongKind(other)),
        };
        let mut entries: Vec<ProfileBadgeEntry> = Vec::new();
        let mut pending_a: Option<(Coordinate, Option<RelayUrl>)> = None;
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    let coord_str = tag.get(1).ok_or(BadgeError::MalformedDefinition)?;
                    let coord =
                        Coordinate::parse(coord_str).map_err(BadgeError::InvalidCoordinate)?;
                    let relay = parse_optional_relay(tag.get(2))?;
                    pending_a = Some((coord, relay));
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    pair_award_with_pending(tag, &mut pending_a, &mut entries)?;
                }
                _ => {}
            }
        }
        Ok((Self { entries }, source))
    }
}

impl Default for ProfileBadges {
    fn default() -> Self {
        Self::new()
    }
}

fn identifier_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

fn push_thumbnail(tag: &Tag, thumbnails: &mut Vec<BadgeImage>) -> Result<(), BadgeError> {
    if let Some(img) = BadgeImage::from_tag(tag)? {
        thumbnails.push(img);
    }
    Ok(())
}

fn pair_award_with_pending(
    tag: &Tag,
    pending_a: &mut Option<(Coordinate, Option<RelayUrl>)>,
    entries: &mut Vec<ProfileBadgeEntry>,
) -> Result<(), BadgeError> {
    let id_hex = tag.get(1).ok_or(BadgeError::MalformedAward)?;
    let award = EventId::parse(id_hex).map_err(BadgeError::InvalidEventId)?;
    let award_relay = parse_optional_relay(tag.get(2))?;
    // Orphaned `e` (no preceding `a`) is silently dropped per spec.
    if let Some((definition, definition_relay)) = pending_a.take() {
        entries.push(ProfileBadgeEntry {
            definition,
            definition_relay,
            award,
            award_relay,
        });
    }
    Ok(())
}

fn parse_optional_relay(value: Option<&str>) -> Result<Option<RelayUrl>, BadgeError> {
    match value {
        Some(s) if !s.is_empty() => Ok(Some(
            RelayUrl::parse(s).map_err(BadgeError::InvalidRelayUrl)?,
        )),
        _ => Ok(None),
    }
}

fn letter_tag<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(alphabet));
    Tag::with(&head, args)
}

fn custom_tag<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::Custom(name.to_owned()), args)
}

/// Errors raised while building or parsing badge events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BadgeError {
    /// The event was not the kind expected by the parser.
    #[error("unexpected kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `kind: 30009` event was missing its `d` identifier.
    #[error("badge definition is missing the `d` identifier tag")]
    MissingIdentifier,
    /// `kind: 8` event was missing the `a` definition tag.
    #[error("badge award must carry an `a` definition tag")]
    MissingDefinition,
    /// `kind: 8` event had no `p` awardee tags.
    #[error("badge award must carry at least one `p` awardee tag")]
    MissingAwardee,
    /// `a` definition tag was missing its coordinate column.
    #[error("malformed `a` definition tag")]
    MalformedDefinition,
    /// `p` awardee tag was missing its pubkey column.
    #[error("malformed `p` awardee tag")]
    MalformedAwardee,
    /// `e` award tag was missing its event-id column.
    #[error("malformed `e` award tag")]
    MalformedAward,
    /// Coordinate parse failure.
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(#[source] CoordinateError),
    /// Pubkey parse failure.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// Event id parse failure.
    #[error("invalid event id: {0}")]
    InvalidEventId(#[source] EventIdError),
    /// Relay URL parse failure.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
    /// `image` / `thumb` dimensions parse failure.
    #[error("invalid image dimensions: {0}")]
    InvalidImageDim(#[source] ImageError),
}

impl EventBuilder {
    /// Author a NIP-58 badge definition (`kind: 30009`).
    #[must_use]
    pub fn badge_definition(definition: &BadgeDefinition) -> Self {
        let mut builder = Self::new(KIND_BADGE_DEFINITION, "");
        for tag in definition.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-58 badge award (`kind: 8`).
    #[must_use]
    pub fn badge_award(award: &BadgeAward) -> Self {
        let mut builder = Self::new(KIND_BADGE_AWARD, "");
        for tag in award.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-58 profile-badges list (`kind: 10008`).
    #[must_use]
    pub fn profile_badges(badges: &ProfileBadges) -> Self {
        let mut builder = Self::new(KIND_PROFILE_BADGES, "");
        for tag in badges.to_tags() {
            builder = builder.tag(tag);
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

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    #[test]
    fn badge_definition_round_trips() {
        let def = BadgeDefinition::new("bravery")
            .name("Medal of Bravery")
            .description("Awarded to users demonstrating bravery")
            .image(
                BadgeImage::new("https://example.com/bravery.png")
                    .dim(ImageDimensions::new(1024, 1024).unwrap()),
            )
            .thumbnail(
                BadgeImage::new("https://example.com/bravery_256.png")
                    .dim(ImageDimensions::new(256, 256).unwrap()),
            )
            .thumbnail(BadgeImage::new("https://example.com/bravery_64.png"));
        let event = EventBuilder::badge_definition(&def)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_BADGE_DEFINITION);
        let parsed = BadgeDefinition::from_event(&event).unwrap();
        assert_eq!(parsed, def);
    }

    #[test]
    fn badge_definition_requires_d_tag() {
        let event = EventBuilder::new(KIND_BADGE_DEFINITION, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            BadgeDefinition::from_event(&event),
            Err(BadgeError::MissingIdentifier)
        ));
    }

    #[test]
    fn badge_award_round_trips_multiple_awardees() {
        let issuer = *keys().public_key();
        let definition = Coordinate::new(KIND_BADGE_DEFINITION, issuer, "bravery");
        let award = BadgeAward::new(definition, BadgeAwardee::new(*other_keys().public_key()))
            .awardee(
                BadgeAwardee::new(issuer)
                    .relay_hint(RelayUrl::parse("wss://relay.example/").unwrap()),
            );
        let event = EventBuilder::badge_award(&award)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = BadgeAward::from_event(&event).unwrap();
        assert_eq!(parsed, award);
    }

    #[test]
    fn badge_award_requires_definition_and_awardee() {
        let event_no_a = EventBuilder::new(KIND_BADGE_AWARD, "")
            .tag(letter_tag(Alphabet::P, [keys().public_key().to_hex()]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            BadgeAward::from_event(&event_no_a),
            Err(BadgeError::MissingDefinition)
        ));

        let coord = Coordinate::new(KIND_BADGE_DEFINITION, *keys().public_key(), "x");
        let event_no_p = EventBuilder::new(KIND_BADGE_AWARD, "")
            .tag(letter_tag(Alphabet::A, [coord.to_wire()]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            BadgeAward::from_event(&event_no_p),
            Err(BadgeError::MissingAwardee)
        ));
    }

    #[test]
    fn profile_badges_round_trip_pairs() {
        let issuer = *keys().public_key();
        let coord1 = Coordinate::new(KIND_BADGE_DEFINITION, issuer, "bravery");
        let coord2 = Coordinate::new(KIND_BADGE_DEFINITION, issuer, "honor");
        let id1 = EventId::from_byte_array([0x10; 32]);
        let id2 = EventId::from_byte_array([0x20; 32]);
        let badges = ProfileBadges::new()
            .entry(
                ProfileBadgeEntry::new(coord1, id1)
                    .award_relay(RelayUrl::parse("wss://nostr.academy/").unwrap()),
            )
            .entry(ProfileBadgeEntry::new(coord2, id2));
        let event = EventBuilder::profile_badges(&badges)
            .sign_with_keys(&other_keys())
            .unwrap();
        let (parsed, source) = ProfileBadges::from_event(&event).unwrap();
        assert_eq!(source, ProfileBadgesSource::Replaceable);
        assert_eq!(parsed, badges);
    }

    #[test]
    fn profile_badges_drops_orphaned_e_tag() {
        let issuer = *keys().public_key();
        let coord = Coordinate::new(KIND_BADGE_DEFINITION, issuer, "bravery");
        let id1 = EventId::from_byte_array([0x10; 32]);
        let orphan_id = EventId::from_byte_array([0x99; 32]);
        // `e` before any `a` — must be dropped.
        let event = EventBuilder::new(KIND_PROFILE_BADGES, "")
            .tag(letter_tag(Alphabet::E, [orphan_id.to_hex()]))
            .tag(letter_tag(Alphabet::A, [coord.to_wire()]))
            .tag(letter_tag(Alphabet::E, [id1.to_hex()]))
            .sign_with_keys(&other_keys())
            .unwrap();
        let (parsed, _) = ProfileBadges::from_event(&event).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].award, id1);
    }

    #[test]
    fn profile_badges_recognises_deprecated_kind() {
        let issuer = *keys().public_key();
        let coord = Coordinate::new(KIND_BADGE_DEFINITION, issuer, "bravery");
        let id = EventId::from_byte_array([0xab; 32]);
        let event = EventBuilder::new(KIND_BADGE_SET, "")
            .tag(Tag::d(DEPRECATED_PROFILE_BADGES_IDENTIFIER))
            .tag(letter_tag(Alphabet::A, [coord.to_wire()]))
            .tag(letter_tag(Alphabet::E, [id.to_hex()]))
            .sign_with_keys(&other_keys())
            .unwrap();
        let (parsed, source) = ProfileBadges::from_event(&event).unwrap();
        assert_eq!(source, ProfileBadgesSource::DeprecatedAddressable);
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn profile_badges_rejects_addressable_30008_without_marker() {
        // kind 30008 with a different `d` is a regular badge set,
        // NOT a deprecated profile-badges list.
        let event = EventBuilder::new(KIND_BADGE_SET, "")
            .tag(Tag::d("some-other-set"))
            .sign_with_keys(&other_keys())
            .unwrap();
        assert!(matches!(
            ProfileBadges::from_event(&event),
            Err(BadgeError::WrongKind(_))
        ));
    }

    #[test]
    fn coordinate_helper_uses_issuer_pubkey() {
        let def = BadgeDefinition::new("bravery");
        let coord = def.coordinate(*keys().public_key());
        assert_eq!(coord.kind, KIND_BADGE_DEFINITION);
        assert_eq!(coord.identifier, "bravery");
    }
}
