//! [NIP-99] Classified Listings.
//!
//! `kind: 30402` is the addressable event for arbitrary classified
//! listings (goods, services, jobs, rentals, giveaways, …). The
//! shape intentionally mirrors NIP-23 long-form content with extra
//! structured metadata. `kind: 30403` is the inactive / draft sibling
//! and uses the same schema so the same builder can author both.
//!
//! # Modelled fields
//!
//! - **Required**: `d` identifier + `.content` markdown body. The
//!   spec marks `title`, `summary`, and `published_at` as
//!   "SHOULD include"; we keep them optional so partially-populated
//!   listings still round-trip.
//! - **Pricing**: [`Price`] models the three-column `price` tag
//!   (`amount`, `currency`, optional `frequency`). The amount stays a
//!   `String` to preserve non-decimal representations apps may use
//!   (e.g. very large integers without rounding).
//! - **Location & geohash**: optional `location` + `g` tags.
//! - **Status**: typed [`ListingStatus`] (`active` / `sold`) with a
//!   forward-compatible `Custom(String)`.
//! - **Hashtags**: `t` tags lower-cased automatically.
//! - **Images**: NIP-58-shaped `image` tags via [`Image`] (URL +
//!   optional `WxH` dimensions).
//! - **References**: optional `e` and `a` tags.
//!
//! Unknown extras round-trip through [`Listing::extra_tags`].
//!
//! [NIP-99]: https://github.com/nostr-protocol/nips/blob/master/99.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::types::{
    ImageDimensions, ImageError, RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError,
};

/// `kind: 30402` — classified listing.
pub const KIND_CLASSIFIED_LISTING: Kind = Kind::CLASSIFIED_LISTING;

/// `kind: 30403` — draft / inactive classified listing.
pub const KIND_CLASSIFIED_LISTING_DRAFT: Kind = Kind::CLASSIFIED_LISTING_DRAFT;

const TITLE_TAG: &str = "title";
const SUMMARY_TAG: &str = "summary";
const PUBLISHED_AT_TAG: &str = "published_at";
const IMAGE_TAG: &str = "image";
const LOCATION_TAG: &str = "location";
const PRICE_TAG: &str = "price";
const STATUS_TAG: &str = "status";

/// Spec-defined wire tokens for the `status` tag (with a
/// forward-compatible passthrough).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListingStatus {
    /// `active`.
    Active,
    /// `sold`.
    Sold,
    /// Forward-compatible passthrough for unknown tokens.
    Custom(String),
}

impl ListingStatus {
    /// Wire token.
    ///
    /// Returns the spec-defined lowercase string or, for
    /// [`Self::Custom`], the inner string slice. The borrow on the
    /// inner string prevents this from being `const`.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Sold => "sold",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown tokens decode
    /// as [`Self::Custom`].
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "active" => Self::Active,
            "sold" => Self::Sold,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// Spec-defined recurrence noun for [`Price::frequency`]. Free-form
/// per spec (`hour`, `day`, `week`, `month`, `year`, custom).
pub type PriceFrequency = String;

/// `price` tag bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    /// Amount as a string so producers can pin large or
    /// non-decimal representations verbatim.
    pub amount: String,
    /// ISO 4217 (or 4217-like) currency code (`USD`, `EUR`, `btc`).
    pub currency: String,
    /// Optional recurrence noun (`hour`, `day`, `week`, `month`,
    /// `year`, custom).
    pub frequency: Option<PriceFrequency>,
}

impl Price {
    /// Construct a one-time price.
    #[must_use]
    pub fn new(amount: impl Into<String>, currency: impl Into<String>) -> Self {
        Self {
            amount: amount.into(),
            currency: currency.into(),
            frequency: None,
        }
    }

    /// Attach a recurrence noun.
    #[must_use]
    pub fn frequency(mut self, frequency: impl Into<PriceFrequency>) -> Self {
        self.frequency = Some(frequency.into());
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(PRICE_TAG);
        self.frequency.as_ref().map_or_else(
            || Tag::with(&head, [self.amount.clone(), self.currency.clone()]),
            |freq| {
                Tag::with(
                    &head,
                    [self.amount.clone(), self.currency.clone(), freq.clone()],
                )
            },
        )
    }

    /// Parse a `price` tag.
    ///
    /// # Errors
    ///
    /// - [`ListingError::WrongPriceTag`] when the head is not `price`.
    /// - [`ListingError::MalformedPrice`] when the amount or
    ///   currency columns are absent.
    pub fn from_tag(tag: &Tag) -> Result<Self, ListingError> {
        if tag.name() != PRICE_TAG {
            return Err(ListingError::WrongPriceTag);
        }
        let amount = tag.get(1).ok_or(ListingError::MalformedPrice)?.to_owned();
        let currency = tag.get(2).ok_or(ListingError::MalformedPrice)?.to_owned();
        let frequency = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self {
            amount,
            currency,
            frequency,
        })
    }
}

/// `image` tag bundle, optionally carrying a `WxH` dimension column
/// (NIP-58 §"Badge Definition Event").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Image URL.
    pub url: Url,
    /// Optional dimensions (`WxH`).
    pub dim: Option<ImageDimensions>,
}

impl Image {
    /// Construct an image with no dimensions.
    #[must_use]
    pub const fn new(url: Url) -> Self {
        Self { url, dim: None }
    }

    /// Attach pixel dimensions.
    #[must_use]
    pub const fn dim(mut self, dim: ImageDimensions) -> Self {
        self.dim = Some(dim);
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(IMAGE_TAG);
        self.dim.map_or_else(
            || Tag::with(&head, [self.url.as_str().to_owned()]),
            |dim| Tag::with(&head, [self.url.as_str().to_owned(), dim.to_string()]),
        )
    }

    /// Parse an `image` tag.
    ///
    /// # Errors
    ///
    /// - [`ListingError::WrongImageTag`] when the head is not `image`.
    /// - [`ListingError::MalformedImage`] when the URL column is
    ///   absent.
    /// - URL / dim parser errors propagate.
    pub fn from_tag(tag: &Tag) -> Result<Self, ListingError> {
        if tag.name() != IMAGE_TAG {
            return Err(ListingError::WrongImageTag);
        }
        let url_str = tag.get(1).ok_or(ListingError::MalformedImage)?;
        let url = Url::parse(url_str)?;
        let dim = match tag.get(2) {
            Some(d) if !d.is_empty() => Some(d.parse::<ImageDimensions>()?),
            _ => None,
        };
        Ok(Self { url, dim })
    }
}

/// Typed bundle for a NIP-99 listing event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// `d`-tag identifier.
    pub identifier: String,
    /// Markdown body — `.content`.
    pub content: String,
    /// `title` tag.
    pub title: Option<String>,
    /// `summary` tag.
    pub summary: Option<String>,
    /// `published_at` tag.
    pub published_at: Option<Timestamp>,
    /// `location` tag.
    pub location: Option<String>,
    /// `g` geohash tag.
    pub geohash: Option<String>,
    /// `price` bundle.
    pub price: Option<Price>,
    /// `status` token.
    pub status: Option<ListingStatus>,
    /// `t` hashtags (lower-cased per NIP-24).
    pub hashtags: Vec<String>,
    /// `image` tags.
    pub images: Vec<Image>,
    /// `e` references with optional relay hint.
    pub event_refs: Vec<EventReference>,
    /// `a` references with optional relay hint.
    pub address_refs: Vec<AddressReference>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// `e` reference tag (event id + optional relay hint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReference {
    /// Referenced event id.
    pub id: EventId,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
}

/// `a` reference tag (coordinate + optional relay hint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressReference {
    /// Referenced addressable coordinate.
    pub coordinate: Coordinate,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
}

impl Listing {
    /// Construct an empty listing seeded with `identifier`.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ..Self::default()
        }
    }

    /// Set the markdown body.
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

    /// Set [`Self::published_at`].
    #[must_use]
    pub const fn published_at(mut self, published_at: Timestamp) -> Self {
        self.published_at = Some(published_at);
        self
    }

    /// Set [`Self::location`].
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Set [`Self::geohash`].
    #[must_use]
    pub fn geohash(mut self, geohash: impl Into<String>) -> Self {
        self.geohash = Some(geohash.into());
        self
    }

    /// Set [`Self::price`].
    #[must_use]
    pub fn price(mut self, price: Price) -> Self {
        self.price = Some(price);
        self
    }

    /// Set [`Self::status`].
    #[must_use]
    pub fn status(mut self, status: ListingStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Append a hashtag (auto lower-cased).
    #[must_use]
    pub fn hashtag(mut self, hashtag: impl AsRef<str>) -> Self {
        self.hashtags.push(hashtag.as_ref().to_lowercase());
        self
    }

    /// Append an image.
    #[must_use]
    pub fn image(mut self, image: Image) -> Self {
        self.images.push(image);
        self
    }

    /// Append an `e` reference.
    #[must_use]
    pub fn event_ref(mut self, reference: EventReference) -> Self {
        self.event_refs.push(reference);
        self
    }

    /// Append an `a` reference.
    #[must_use]
    pub fn address_ref(mut self, reference: AddressReference) -> Self {
        self.address_refs.push(reference);
        self
    }

    /// Build the listing's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: crate::PublicKey, kind: Kind) -> Coordinate {
        Coordinate::new(kind, author, self.identifier.clone())
    }

    /// Parse a `kind: 30402` or `kind: 30403` event back into a
    /// typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ListingError::WrongKind`] for any other kind.
    /// - [`ListingError::MissingIdentifier`] when the `d` tag is
    ///   absent.
    /// - Field-specific errors for malformed columns.
    pub fn from_event(event: &Event) -> Result<Self, ListingError> {
        if event.kind != KIND_CLASSIFIED_LISTING && event.kind != KIND_CLASSIFIED_LISTING_DRAFT {
            return Err(ListingError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(ListingError::MissingIdentifier)?
            .to_owned();
        let mut listing = Self {
            identifier,
            content: event.content.clone(),
            ..Self::default()
        };
        for tag in &event.tags {
            absorb_tag(tag, &mut listing)?;
        }
        Ok(listing)
    }
}

fn absorb_tag(tag: &Tag, listing: &mut Listing) -> Result<(), ListingError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(t) = tag.get(1) {
                listing.hashtags.push(t.to_owned());
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::G => {
            listing.geohash = tag.get(1).map(str::to_owned);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
            listing.event_refs.push(parse_event_ref(tag)?);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
            listing.address_refs.push(parse_address_ref(tag)?);
        }
        _ if tag.name() == TITLE_TAG => listing.title = tag.get(1).map(str::to_owned),
        _ if tag.name() == SUMMARY_TAG => listing.summary = tag.get(1).map(str::to_owned),
        _ if tag.name() == PUBLISHED_AT_TAG => {
            if let Some(raw) = tag.get(1) {
                listing.published_at = Some(raw.parse::<Timestamp>()?);
            }
        }
        _ if tag.name() == LOCATION_TAG => listing.location = tag.get(1).map(str::to_owned),
        _ if tag.name() == STATUS_TAG => {
            listing.status = tag.get(1).map(ListingStatus::parse);
        }
        _ if tag.name() == PRICE_TAG => listing.price = Some(Price::from_tag(tag)?),
        _ if tag.name() == IMAGE_TAG => listing.images.push(Image::from_tag(tag)?),
        _ => listing.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn parse_event_ref(tag: &Tag) -> Result<EventReference, ListingError> {
    let id_hex = tag.get(1).ok_or(ListingError::MalformedEventRef)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(EventReference { id, relay_hint })
}

fn parse_address_ref(tag: &Tag) -> Result<AddressReference, ListingError> {
    let coord_str = tag.get(1).ok_or(ListingError::MalformedAddressRef)?;
    let coordinate = Coordinate::parse(coord_str)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(AddressReference {
        coordinate,
        relay_hint,
    })
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

/// Errors raised by NIP-99 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ListingError {
    /// The event was neither `kind: 30402` nor `kind: 30403`.
    #[error("expected kind 30402 or 30403 (classified listing), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag is absent.
    #[error("NIP-99 listing missing `d` tag")]
    MissingIdentifier,
    /// `price` tag head was not `price`.
    #[error("expected `price` tag")]
    WrongPriceTag,
    /// `price` tag is missing the amount or currency column.
    #[error("`price` tag missing amount or currency")]
    MalformedPrice,
    /// `image` tag head was not `image`.
    #[error("expected `image` tag")]
    WrongImageTag,
    /// `image` tag is missing the URL column.
    #[error("`image` tag missing URL")]
    MalformedImage,
    /// `e` reference tag is missing the event id column.
    #[error("`e` reference tag missing event id")]
    MalformedEventRef,
    /// `a` reference tag is missing the coordinate column.
    #[error("`a` reference tag missing coordinate")]
    MalformedAddressRef,
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// Wrapped relay-url parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped image-dim parser error.
    #[error(transparent)]
    InvalidDim(#[from] ImageError),
    /// Wrapped `published_at` timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
}

impl EventBuilder {
    /// Author a NIP-99 listing event of `kind`.
    ///
    /// Use [`KIND_CLASSIFIED_LISTING`] for active listings or
    /// [`KIND_CLASSIFIED_LISTING_DRAFT`] for drafts; both share the
    /// same schema.
    #[must_use]
    pub fn classified_listing(listing: &Listing, kind: Kind) -> Self {
        let mut builder = Self::new(kind, listing.content.clone());
        builder = builder.tag(Tag::d(&listing.identifier));
        if let Some(title) = &listing.title {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TITLE_TAG), [title.clone()]));
        }
        if let Some(summary) = &listing.summary {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(SUMMARY_TAG),
                [summary.clone()],
            ));
        }
        if let Some(ts) = listing.published_at {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(PUBLISHED_AT_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        for hashtag in &listing.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        for image in &listing.images {
            builder = builder.tag(image.to_tag());
        }
        if let Some(location) = &listing.location {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(LOCATION_TAG),
                [location.clone()],
            ));
        }
        if let Some(geohash) = &listing.geohash {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G));
            builder = builder.tag(Tag::with(&head, [geohash.clone()]));
        }
        if let Some(price) = &listing.price {
            builder = builder.tag(price.to_tag());
        }
        if let Some(status) = &listing.status {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STATUS_TAG),
                [status.as_str().to_owned()],
            ));
        }
        for r in &listing.event_refs {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
            builder = builder.tag(r.relay_hint.as_ref().map_or_else(
                || Tag::with(&head, [r.id.to_hex()]),
                |relay| Tag::with(&head, [r.id.to_hex(), relay.as_str().to_owned()]),
            ));
        }
        for r in &listing.address_refs {
            builder = builder.tag(r.relay_hint.as_ref().map_or_else(
                || Tag::a(&r.coordinate),
                |relay| Tag::a_with_relay(&r.coordinate, relay),
            ));
        }
        for tag in &listing.extra_tags {
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
    fn round_trip_minimal_listing() {
        let listing = Listing::new("lorem-ipsum").content("**markdown**");
        let event = EventBuilder::classified_listing(&listing, KIND_CLASSIFIED_LISTING)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Listing::from_event(&event).unwrap();
        assert_eq!(parsed, listing);
    }

    #[test]
    fn round_trip_full_listing() {
        let listing = Listing::new("lorem-ipsum")
            .content("Lorem ipsum body.")
            .title("Lorem Ipsum")
            .summary("Brief")
            .published_at(Timestamp::from_secs(1_296_962_229))
            .location("NYC")
            .geohash("dr5regw3p")
            .price(Price::new("100", "USD"))
            .status(ListingStatus::Active)
            .hashtag("ELECTRONICS")
            .image(
                Image::new(Url::parse("https://example.com/p.jpg").unwrap())
                    .dim("256x256".parse().unwrap()),
            )
            .event_ref(EventReference {
                id: EventId::from_byte_array([0x7f; 32]),
                relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
            })
            .address_ref(AddressReference {
                coordinate: Coordinate::new(
                    Kind::new(30_023),
                    *keys().public_key(),
                    "post".to_owned(),
                ),
                relay_hint: Some(RelayUrl::parse("wss://relay.nostr/").unwrap()),
            });
        let event = EventBuilder::classified_listing(&listing, KIND_CLASSIFIED_LISTING)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Listing::from_event(&event).unwrap();
        // Hashtag should be lower-cased.
        assert_eq!(parsed.hashtags, vec!["electronics".to_owned()]);
        let expected = Listing {
            hashtags: vec!["electronics".to_owned()],
            ..listing
        };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn round_trip_draft() {
        let listing = Listing::new("draft-1").content("hidden");
        let event = EventBuilder::classified_listing(&listing, KIND_CLASSIFIED_LISTING_DRAFT)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Listing::from_event(&event).unwrap();
        assert_eq!(parsed, listing);
        assert_eq!(event.kind, KIND_CLASSIFIED_LISTING_DRAFT);
    }

    #[test]
    fn price_with_frequency_round_trips() {
        let price = Price::new("15", "EUR").frequency("month");
        let tag = price.to_tag();
        let parsed = Price::from_tag(&tag).unwrap();
        assert_eq!(parsed, price);
    }

    #[test]
    fn status_parses_unknown_tokens_as_custom() {
        let listing = Listing::new("status-test")
            .content("…")
            .status(ListingStatus::Custom("expired".into()));
        let event = EventBuilder::classified_listing(&listing, KIND_CLASSIFIED_LISTING)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Listing::from_event(&event).unwrap();
        assert_eq!(parsed.status, Some(ListingStatus::Custom("expired".into())));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Listing::from_event(&event),
            Err(ListingError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_identifier_is_rejected() {
        let event = EventBuilder::new(KIND_CLASSIFIED_LISTING, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Listing::from_event(&event),
            Err(ListingError::MissingIdentifier)
        ));
    }

    #[test]
    fn malformed_price_is_rejected() {
        let event = EventBuilder::new(KIND_CLASSIFIED_LISTING, "")
            .tag(Tag::d("listing-1"))
            .tag(Tag::with(&TagKind::from_wire(PRICE_TAG), ["100"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Listing::from_event(&event),
            Err(ListingError::MalformedPrice)
        ));
    }

    #[test]
    fn extra_tags_are_preserved() {
        let custom = Tag::with(&TagKind::Custom("note".to_owned()), ["preserve me"]);
        let listing = Listing::new("listing-x").content("body");
        let mut builder = EventBuilder::classified_listing(&listing, KIND_CLASSIFIED_LISTING);
        builder = builder.tag(custom.clone());
        let event = builder.sign_with_keys(&keys()).unwrap();
        let parsed = Listing::from_event(&event).unwrap();
        assert_eq!(parsed.extra_tags, vec![custom]);
    }
}
