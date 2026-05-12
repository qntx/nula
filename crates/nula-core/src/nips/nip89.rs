//! [NIP-89] Recommended Application Handlers.
//!
//! Two addressable event kinds plus one optional `client` tag:
//!
//! - **`kind: 31989`** — recommendation. The `d` tag is the
//!   recommended event-kind (rendered as a decimal string), and one
//!   or more `a` tags point at the handler events with an optional
//!   relay hint and platform marker.
//! - **`kind: 31990`** — handler. The `d` tag is a free-form
//!   identifier, the `content` is optional `kind: 0`-shaped metadata,
//!   each supported event-kind is listed in a `k` tag, and the entry
//!   URLs are encoded as platform tags (`web`, `ios`, …) carrying
//!   the URL template and an optional NIP-19 entity hint.
//! - **`client` tag** — events MAY include a `client` tag to advertise
//!   the authoring application (name + handler coordinate + relay
//!   hint). The tag is parsed by [`ClientTag::from_tag`] and built by
//!   [`ClientTag::to_tag`] / [`Tag::client`].
//!
//! # Forward compatibility
//!
//! - Platform names are opaque strings — new platforms work without a
//!   spec bump.
//! - Unknown extra tags survive a round-trip through `extra_tags` on
//!   both bundles.
//! - Recommendation `a` columns past the third position are preserved
//!   in [`HandlerRecommendationEntry::extra_columns`].
//!
//! [NIP-89]: https://github.com/nostr-protocol/nips/blob/master/89.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, Kind, SingleLetterTag, Tag,
    TagKind, Tags,
};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 31989` — recommendation event.
pub const KIND_APP_RECOMMENDATION: Kind = Kind::APP_RECOMMENDATION;

/// `kind: 31990` — handler event.
pub const KIND_APP_HANDLER: Kind = Kind::APP_HANDLER;

/// Wire name of the optional `client` tag.
pub const CLIENT_TAG: &str = "client";

/// One recommendation row inside a `kind: 31989` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerRecommendationEntry {
    /// Handler coordinate (`kind: 31990` addressable event).
    pub handler: Coordinate,
    /// Optional relay hint where the handler can be fetched.
    pub relay_hint: Option<RelayUrl>,
    /// Optional platform marker (`web`, `ios`, `android`, …).
    pub platform: Option<String>,
    /// Any further columns the producer attached. Preserved verbatim
    /// for forward compatibility.
    pub extra_columns: Vec<String>,
}

impl HandlerRecommendationEntry {
    /// Construct an entry pointing at `handler` with no relay hint
    /// and no platform marker.
    #[must_use]
    pub const fn new(handler: Coordinate) -> Self {
        Self {
            handler,
            relay_hint: None,
            platform: None,
            extra_columns: Vec::new(),
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Attach a platform marker.
    #[must_use]
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Render as a single `a` tag with the spec's column ordering:
    /// `["a", "<coordinate>", "<relay>", "<platform>"]`.
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let mut values: Vec<String> = Vec::with_capacity(4);
        values.push(self.handler.to_wire());
        match (&self.relay_hint, &self.platform) {
            (Some(relay), Some(platform)) => {
                values.push(relay.as_str().to_owned());
                values.push(platform.clone());
            }
            (Some(relay), None) => values.push(relay.as_str().to_owned()),
            (None, Some(platform)) => {
                // Per spec the relay slot stays an empty string so
                // the platform stays at index 3.
                values.push(String::new());
                values.push(platform.clone());
            }
            (None, None) => {}
        }
        values.extend(self.extra_columns.iter().cloned());
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        Tag::with(&head, values)
    }

    /// Parse a single `a` [`Tag`] into an entry.
    ///
    /// # Errors
    ///
    /// - [`HandlerError::MalformedAddressTag`] when the coordinate
    ///   column is absent.
    /// - [`HandlerError::InvalidCoordinate`] for malformed coordinates.
    /// - [`HandlerError::InvalidRelayUrl`] when the relay hint is
    ///   non-empty and fails to parse.
    pub fn from_tag(tag: &Tag) -> Result<Self, HandlerError> {
        let coord_str = tag.get(1).ok_or(HandlerError::MalformedAddressTag)?;
        let handler = Coordinate::parse(coord_str)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        let platform = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
        let extra_columns: Vec<String> =
            tag.values().iter().skip(4).map(ToOwned::to_owned).collect();
        Ok(Self {
            handler,
            relay_hint,
            platform,
            extra_columns,
        })
    }
}

/// Typed bundle for a `kind: 31989` recommendation event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerRecommendation {
    /// Kind being recommended (encodes as the `d` tag value).
    pub recommended_kind: Kind,
    /// Recommendation rows in the order the producer pinned them.
    pub entries: Vec<HandlerRecommendationEntry>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl HandlerRecommendation {
    /// Construct an empty recommendation for `kind`.
    #[must_use]
    pub const fn new(recommended_kind: Kind) -> Self {
        Self {
            recommended_kind,
            entries: Vec::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Append a recommendation entry.
    #[must_use]
    pub fn entry(mut self, entry: HandlerRecommendationEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Build the addressable coordinate for this recommendation.
    #[must_use]
    pub fn coordinate(&self, author: crate::PublicKey) -> Coordinate {
        Coordinate::new(
            KIND_APP_RECOMMENDATION,
            author,
            self.recommended_kind.as_u16().to_string(),
        )
    }

    /// Parse a `kind: 31989` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`HandlerError::WrongKind`] for any other kind.
    /// - [`HandlerError::MissingIdentifier`] when the `d` tag is
    ///   absent.
    /// - [`HandlerError::InvalidRecommendedKind`] when the `d` value
    ///   is not a `u16`.
    /// - Per-entry parser errors propagate as-is.
    pub fn from_event(event: &Event) -> Result<Self, HandlerError> {
        if event.kind != KIND_APP_RECOMMENDATION {
            return Err(HandlerError::WrongKind(event.kind));
        }
        let d = d_value(&event.tags).ok_or(HandlerError::MissingIdentifier)?;
        let recommended_kind: Kind = d
            .parse::<u16>()
            .map(Kind::from)
            .map_err(|_| HandlerError::InvalidRecommendedKind(d.to_owned()))?;
        let mut entries: Vec<HandlerRecommendationEntry> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    entries.push(HandlerRecommendationEntry::from_tag(tag)?);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            recommended_kind,
            entries,
            extra_tags,
        })
    }
}

/// One entry-point exposed by a handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerPlatformEntry {
    /// Platform name (`web`, `ios`, `android`, custom). Opaque to us.
    pub platform: String,
    /// URL or URI template. May contain `<bech32>` placeholders that
    /// the client must substitute with a NIP-19 entity.
    pub url_template: String,
    /// Optional NIP-19 entity-type hint such as `nevent`, `nprofile`,
    /// `naddr`. `None` matches the spec's "generic" handler shape.
    pub entity: Option<String>,
}

impl HandlerPlatformEntry {
    /// Construct an entry with no entity hint.
    #[must_use]
    pub fn new(platform: impl Into<String>, url_template: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            url_template: url_template.into(),
            entity: None,
        }
    }

    /// Attach a NIP-19 entity-type hint (`nevent`, `nprofile`, …).
    #[must_use]
    pub fn entity(mut self, entity: impl Into<String>) -> Self {
        self.entity = Some(entity.into());
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(&self.platform);
        self.entity.as_ref().map_or_else(
            || Tag::with(&head, [self.url_template.clone()]),
            |entity| Tag::with(&head, [self.url_template.clone(), entity.clone()]),
        )
    }

    /// Parse a tag emitted by a handler. The tag's head is the
    /// platform name; column 1 is the URL template; column 2, when
    /// present, is the entity hint.
    fn from_tag(tag: &Tag) -> Result<Self, HandlerError> {
        let platform = tag.name().to_owned();
        let url_template = tag
            .get(1)
            .ok_or(HandlerError::MalformedHandlerPlatform)?
            .to_owned();
        let entity = tag.get(2).filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self {
            platform,
            url_template,
            entity,
        })
    }
}

/// Typed bundle for a `kind: 31990` handler event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerInformation {
    /// `d`-tag value — handler identifier (free-form).
    pub identifier: String,
    /// `.content` — optional stringified `kind: 0`-shaped JSON.
    pub content: String,
    /// Supported event kinds (`k` tags).
    pub supported_kinds: Vec<Kind>,
    /// Platform-specific entry points.
    pub platforms: Vec<HandlerPlatformEntry>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl HandlerInformation {
    /// Construct an empty handler bundle bound to `identifier`.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            content: String::new(),
            supported_kinds: Vec::new(),
            platforms: Vec::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Replace [`Self::content`].
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append a supported event kind.
    #[must_use]
    pub fn kind(mut self, kind: Kind) -> Self {
        self.supported_kinds.push(kind);
        self
    }

    /// Append a platform entry.
    #[must_use]
    pub fn platform(mut self, entry: HandlerPlatformEntry) -> Self {
        self.platforms.push(entry);
        self
    }

    /// Build the handler's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: crate::PublicKey) -> Coordinate {
        Coordinate::new(KIND_APP_HANDLER, author, self.identifier.clone())
    }

    /// Parse a `kind: 31990` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`HandlerError::WrongKind`] for any other kind.
    /// - [`HandlerError::MissingIdentifier`] when the `d` tag is
    ///   absent.
    /// - [`HandlerError::InvalidKind`] when a `k` tag has a value
    ///   that is not a `u16`.
    pub fn from_event(event: &Event) -> Result<Self, HandlerError> {
        if event.kind != KIND_APP_HANDLER {
            return Err(HandlerError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(HandlerError::MissingIdentifier)?
            .to_owned();
        let mut supported_kinds: Vec<Kind> = Vec::new();
        let mut platforms: Vec<HandlerPlatformEntry> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::K => {
                    let raw = tag.get(1).ok_or(HandlerError::MalformedKindTag)?;
                    let kind = raw
                        .parse::<u16>()
                        .map(Kind::from)
                        .map_err(|_| HandlerError::InvalidKind(raw.to_owned()))?;
                    supported_kinds.push(kind);
                }
                TagKind::Custom(_) => match HandlerPlatformEntry::from_tag(tag) {
                    Ok(entry) => platforms.push(entry),
                    Err(_) => extra_tags.push(tag.clone()),
                },
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            identifier,
            content: event.content.clone(),
            supported_kinds,
            platforms,
            extra_tags,
        })
    }
}

/// `client` tag — identifies the publishing application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTag {
    /// Human-readable client name.
    pub name: String,
    /// Optional handler coordinate (`kind: 31990` event).
    pub handler: Option<Coordinate>,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
}

impl ClientTag {
    /// Construct a name-only client tag.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            handler: None,
            relay_hint: None,
        }
    }

    /// Attach a handler coordinate.
    #[must_use]
    pub fn handler(mut self, handler: Coordinate) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let mut values: Vec<String> = Vec::with_capacity(4);
        values.push(self.name.clone());
        match (&self.handler, &self.relay_hint) {
            (Some(coord), Some(relay)) => {
                values.push(coord.to_wire());
                values.push(relay.as_str().to_owned());
            }
            (Some(coord), None) => values.push(coord.to_wire()),
            (None, Some(relay)) => {
                values.push(String::new());
                values.push(relay.as_str().to_owned());
            }
            (None, None) => {}
        }
        Tag::with(&TagKind::from_wire(CLIENT_TAG), values)
    }

    /// Parse a `client` [`Tag`].
    ///
    /// # Errors
    ///
    /// - [`HandlerError::WrongTag`] when the tag's head is not
    ///   `client`.
    /// - [`HandlerError::MalformedClientTag`] when the name column
    ///   is absent.
    /// - Coordinate / relay parsing errors propagate.
    pub fn from_tag(tag: &Tag) -> Result<Self, HandlerError> {
        if tag.name() != CLIENT_TAG {
            return Err(HandlerError::WrongTag);
        }
        let name = tag
            .get(1)
            .ok_or(HandlerError::MalformedClientTag)?
            .to_owned();
        let handler = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(Coordinate::parse(s)?),
            _ => None,
        };
        let relay_hint = match tag.get(3) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        Ok(Self {
            name,
            handler,
            relay_hint,
        })
    }
}

impl Tag {
    /// Build a NIP-89 `client` tag.
    #[must_use]
    pub fn client(client: &ClientTag) -> Self {
        client.to_tag()
    }
}

/// Errors raised by NIP-89 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HandlerError {
    /// Event kind did not match the expected NIP-89 kind.
    #[error("unexpected kind for NIP-89 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// Tag head did not match the expected NIP-89 tag.
    #[error("unexpected tag for NIP-89")]
    WrongTag,
    /// `d` tag is absent.
    #[error("NIP-89 event must carry a `d` tag")]
    MissingIdentifier,
    /// `d`-tag value on a `kind: 31989` event is not a decimal `u16`.
    #[error("recommendation `d` tag must be a `u16` kind: `{0}`")]
    InvalidRecommendedKind(String),
    /// `k` tag value on a `kind: 31990` event is not a decimal `u16`.
    #[error("handler `k` tag must be a `u16` kind: `{0}`")]
    InvalidKind(String),
    /// `k` tag column 1 is absent.
    #[error("`k` handler tag missing kind value")]
    MalformedKindTag,
    /// `a` tag column 1 is absent.
    #[error("`a` recommendation tag missing handler coordinate")]
    MalformedAddressTag,
    /// `client` tag column 1 is absent.
    #[error("`client` tag missing name column")]
    MalformedClientTag,
    /// Handler platform tag missing URL template.
    #[error("handler platform tag missing URL template")]
    MalformedHandlerPlatform,
    /// Coordinate failed to parse.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// Relay URL failed to parse.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

impl EventBuilder {
    /// Author a NIP-89 `kind: 31989` recommendation event.
    #[must_use]
    pub fn handler_recommendation(rec: &HandlerRecommendation) -> Self {
        let mut builder = Self::new(KIND_APP_RECOMMENDATION, "");
        builder = builder.tag(Tag::d(rec.recommended_kind.as_u16().to_string()));
        for entry in &rec.entries {
            builder = builder.tag(entry.to_tag());
        }
        for tag in &rec.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-89 `kind: 31990` handler event.
    #[must_use]
    pub fn handler_information(handler: &HandlerInformation) -> Self {
        let mut builder = Self::new(KIND_APP_HANDLER, handler.content.clone());
        builder = builder.tag(Tag::d(&handler.identifier));
        for kind in &handler.supported_kinds {
            builder = builder.tag(Tag::k(*kind));
        }
        for entry in &handler.platforms {
            builder = builder.tag(entry.to_tag());
        }
        for tag in &handler.extra_tags {
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

    fn coord(kind: u16, identifier: &str) -> Coordinate {
        Coordinate::new(Kind::new(kind), *keys().public_key(), identifier.to_owned())
    }

    #[test]
    fn recommendation_round_trip() {
        let rec = HandlerRecommendation::new(Kind::new(31_337))
            .entry(
                HandlerRecommendationEntry::new(coord(31_990, "abcd"))
                    .relay_hint(relay())
                    .platform("web"),
            )
            .entry(HandlerRecommendationEntry::new(coord(31_990, "ios-bundle")).platform("ios"));
        let event = EventBuilder::handler_recommendation(&rec)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = HandlerRecommendation::from_event(&event).unwrap();
        assert_eq!(parsed, rec);
    }

    #[test]
    fn recommendation_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HandlerRecommendation::from_event(&event),
            Err(HandlerError::WrongKind(_))
        ));
    }

    #[test]
    fn recommendation_rejects_missing_identifier() {
        let event = EventBuilder::new(KIND_APP_RECOMMENDATION, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HandlerRecommendation::from_event(&event),
            Err(HandlerError::MissingIdentifier)
        ));
    }

    #[test]
    fn handler_round_trip_with_platforms() {
        let handler = HandlerInformation::new("handler-id-1")
            .content(r#"{"name":"Demo"}"#)
            .kind(Kind::new(1))
            .kind(Kind::new(30_023))
            .platform(
                HandlerPlatformEntry::new("web", "https://demo.example/a/<bech32>")
                    .entity("nevent"),
            )
            .platform(HandlerPlatformEntry::new("ios", "demo://a/<bech32>"));
        let event = EventBuilder::handler_information(&handler)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = HandlerInformation::from_event(&event).unwrap();
        assert_eq!(parsed, handler);
    }

    #[test]
    fn handler_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HandlerInformation::from_event(&event),
            Err(HandlerError::WrongKind(_))
        ));
    }

    #[test]
    fn handler_rejects_invalid_kind_tag() {
        let event = EventBuilder::new(KIND_APP_HANDLER, "")
            .tag(Tag::d("h-1"))
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::K)),
                ["not-a-number"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HandlerInformation::from_event(&event),
            Err(HandlerError::InvalidKind(_))
        ));
    }

    #[test]
    fn client_tag_round_trip() {
        let client = ClientTag::new("My Client")
            .handler(coord(31_990, "app-id"))
            .relay_hint(relay());
        let tag = client.to_tag();
        assert_eq!(tag.name(), CLIENT_TAG);
        let parsed = ClientTag::from_tag(&tag).unwrap();
        assert_eq!(parsed, client);
    }

    #[test]
    fn client_tag_name_only() {
        let client = ClientTag::new("Bare Client");
        let tag = client.to_tag();
        let parsed = ClientTag::from_tag(&tag).unwrap();
        assert_eq!(parsed, client);
    }

    #[test]
    fn client_tag_rejects_wrong_head() {
        let tag = Tag::title("not a client tag");
        assert!(matches!(
            ClientTag::from_tag(&tag),
            Err(HandlerError::WrongTag)
        ));
    }
}
