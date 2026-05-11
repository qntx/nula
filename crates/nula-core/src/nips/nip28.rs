//! [NIP-28] Public Chat.
//!
//! Five event kinds wire up Telegram-style public chat over relays:
//!
//! | Kind | Purpose                      | Payload                                                 |
//! |------|------------------------------|---------------------------------------------------------|
//! | 40   | [Channel creation]           | JSON metadata in `.content`                             |
//! | 41   | [Channel metadata update]    | JSON metadata in `.content`, `e` tag points at the kind 40 |
//! | 42   | [Channel message]            | Text in `.content`, NIP-10-marked `e`/`p` tags          |
//! | 43   | [Hide message] (per-viewer)  | Optional reason JSON, `e` tag points at the kind 42     |
//! | 44   | [Mute user] (per-viewer)     | Optional reason JSON, `p` tag points at the muted user  |
//!
//! [Channel creation]: https://github.com/nostr-protocol/nips/blob/master/28.md#kind-40-create-channel
//! [Channel metadata update]: https://github.com/nostr-protocol/nips/blob/master/28.md#kind-41-set-channel-metadata
//! [Channel message]: https://github.com/nostr-protocol/nips/blob/master/28.md#kind-42-create-channel-message
//! [Hide message]: https://github.com/nostr-protocol/nips/blob/master/28.md#kind-43-hide-message
//! [Mute user]: https://github.com/nostr-protocol/nips/blob/master/28.md#kind-44-mute-user
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` did not ship a dedicated NIP-28 module; the
//! channel builders are scattered across `event/builder.rs` and
//! callers re-parse the JSON metadata themselves. We bundle the
//! whole flow in one place:
//!
//! - [`ChannelMetadata`] — typed bundle for the kind 40 / 41 JSON
//!   `.content` body. `name`, `about`, `picture`, and `relays` are
//!   first-class fields; everything else round-trips through a
//!   `serde_json::Map` so future per-app metadata never gets lost.
//! - [`HideReason`] — typed bundle for the optional `.content` JSON
//!   used by kinds 43 and 44. Spec lists `reason` as the canonical
//!   key but explicitly leaves the body open-ended.
//! - [`EventBuilder`] gains six builders covering the full create /
//!   update / message-root / message-reply / hide / mute flow with
//!   NIP-10 marker tags applied per spec §"Kind 42".
//!
//! [NIP-28]: https://github.com/nostr-protocol/nips/blob/master/28.md

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::PublicKey;
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 40` — channel creation.
pub const KIND_CHANNEL_CREATE: Kind = Kind::CHANNEL_CREATION;
/// `kind: 41` — channel metadata update.
pub const KIND_CHANNEL_METADATA: Kind = Kind::CHANNEL_METADATA;
/// `kind: 42` — channel chat message.
pub const KIND_CHANNEL_MESSAGE: Kind = Kind::CHANNEL_MESSAGE;
/// `kind: 43` — channel hide-message moderation.
pub const KIND_CHANNEL_HIDE_MESSAGE: Kind = Kind::CHANNEL_HIDE_MESSAGE;
/// `kind: 44` — channel mute-user moderation.
pub const KIND_CHANNEL_MUTE_USER: Kind = Kind::CHANNEL_MUTE_USER;

/// JSON `.content` body for kinds 40 and 41.
///
/// The four spec-named fields (`name`, `about`, `picture`,
/// `relays`) are first-class. Any other JSON property the
/// originating app stamps on the metadata object survives via
/// [`Self::extra`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMetadata {
    /// Channel name (kind 40 / 41 §"name").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Long-form description (kind 40 / 41 §"about").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// URL of channel picture. Spec leaves the value unconstrained
    /// so we keep it as `String`; callers that need URL validation
    /// should round-trip through [`crate::Url`] themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Relays where the channel events are broadcast.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<RelayUrl>,
    /// Forward-compatible passthrough of every other JSON property.
    #[serde(flatten)]
    pub extra: IndexMap<String, serde_json::Value>,
}

impl ChannelMetadata {
    /// Construct an empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`Self::name`].
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set [`Self::about`].
    #[must_use]
    pub fn about(mut self, about: impl Into<String>) -> Self {
        self.about = Some(about.into());
        self
    }

    /// Set [`Self::picture`].
    #[must_use]
    pub fn picture(mut self, picture: impl Into<String>) -> Self {
        self.picture = Some(picture.into());
        self
    }

    /// Append a relay hint.
    #[must_use]
    pub fn relay(mut self, relay: RelayUrl) -> Self {
        self.relays.push(relay);
        self
    }

    /// Append several relay hints.
    #[must_use]
    pub fn relays<I>(mut self, relays: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        self.relays.extend(relays);
        self
    }

    /// Render to JSON ready for use as `.content`.
    ///
    /// # Errors
    ///
    /// Forwarded from `serde_json` — the only failure modes are
    /// non-`UTF-8` strings inside [`Self::extra`], which Rust strings
    /// cannot represent in the first place, or numeric overflow in
    /// callers that put `serde_json::Number::from_f64(f64::NAN)` in
    /// `extra`. Both are degenerate.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a JSON `.content` string into the typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ChannelMetadataError::InvalidJson`] when the input is not
    ///   a JSON object.
    /// - [`ChannelMetadataError::InvalidRelayUrl`] when a `relays[i]`
    ///   string fails [`RelayUrl::parse`].
    pub fn from_json(json: &str) -> Result<Self, ChannelMetadataError> {
        let raw: serde_json::Value =
            serde_json::from_str(json).map_err(ChannelMetadataError::InvalidJson)?;
        let serde_json::Value::Object(mut map) = raw else {
            return Err(ChannelMetadataError::NotAnObject);
        };

        let mut metadata = Self::default();
        if let Some(value) = map.remove("name") {
            metadata.name = string_field(value, "name")?;
        }
        if let Some(value) = map.remove("about") {
            metadata.about = string_field(value, "about")?;
        }
        if let Some(value) = map.remove("picture") {
            metadata.picture = string_field(value, "picture")?;
        }
        if let Some(value) = map.remove("relays") {
            metadata.relays = relays_field(value)?;
        }
        for (key, value) in map {
            metadata.extra.insert(key, value);
        }
        Ok(metadata)
    }
}

fn string_field(
    value: serde_json::Value,
    key: &'static str,
) -> Result<Option<String>, ChannelMetadataError> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        other => Err(ChannelMetadataError::InvalidStringField {
            key,
            actual: type_name(&other).to_owned(),
        }),
    }
}

fn relays_field(value: serde_json::Value) -> Result<Vec<RelayUrl>, ChannelMetadataError> {
    let serde_json::Value::Array(arr) = value else {
        return Err(ChannelMetadataError::InvalidRelaysField);
    };
    let mut relays: Vec<RelayUrl> = Vec::with_capacity(arr.len());
    for item in arr {
        let serde_json::Value::String(url) = item else {
            return Err(ChannelMetadataError::InvalidRelaysField);
        };
        relays.push(RelayUrl::parse(&url).map_err(ChannelMetadataError::InvalidRelayUrl)?);
    }
    Ok(relays)
}

const fn type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// JSON `.content` body for kinds 43 and 44.
///
/// Spec lists `reason` as the canonical key but says other
/// metadata is permitted; we keep the JSON flat so any
/// app-specific moderation rationale survives the round-trip.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HideReason {
    /// Free-form reason string (spec §"Kind 43" example).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Forward-compatible passthrough.
    #[serde(flatten)]
    pub extra: IndexMap<String, serde_json::Value>,
}

impl HideReason {
    /// Construct an empty reason bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`Self::reason`].
    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Render to JSON ready for use as `.content`.
    ///
    /// Returns the empty string when both `reason` and `extra` are
    /// empty, matching the spec's "may optionally include metadata"
    /// language.
    #[must_use]
    pub fn to_json(&self) -> String {
        if self.reason.is_none() && self.extra.is_empty() {
            return String::new();
        }
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse a JSON `.content` string into the typed bundle.
    ///
    /// An empty input yields a default-constructed bundle.
    ///
    /// # Errors
    ///
    /// - [`ChannelMetadataError::InvalidJson`] when the input is not
    ///   parseable JSON.
    pub fn from_json(json: &str) -> Result<Self, ChannelMetadataError> {
        if json.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(json).map_err(ChannelMetadataError::InvalidJson)
    }
}

/// Errors raised while parsing channel metadata JSON or hide-reason JSON.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChannelMetadataError {
    /// The `.content` was not parseable JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// The JSON was a valid value but not an object.
    #[error("expected a JSON object at the top level")]
    NotAnObject,
    /// A spec-named string field was something other than a string.
    #[error("`{key}` must be a JSON string, got {actual}")]
    InvalidStringField {
        /// Field name (`name` / `about` / `picture`).
        key: &'static str,
        /// Actual JSON type encountered.
        actual: String,
    },
    /// `relays` was not an array of strings.
    #[error("`relays` must be a JSON array of strings")]
    InvalidRelaysField,
    /// One of the `relays[i]` strings failed [`RelayUrl::parse`].
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
}

impl EventBuilder {
    /// Author a NIP-28 channel creation event (`kind: 40`).
    ///
    /// # Errors
    ///
    /// Forwarded from [`ChannelMetadata::to_json`].
    pub fn channel_create(metadata: &ChannelMetadata) -> Result<Self, serde_json::Error> {
        let json = metadata.to_json()?;
        Ok(Self::new(KIND_CHANNEL_CREATE, json))
    }

    /// Author a NIP-28 channel metadata update (`kind: 41`).
    ///
    /// `channel` is the kind 40 event id; `relay` is an optional
    /// recommended-relay hint placed in the `e` tag per NIP-10.
    ///
    /// # Errors
    ///
    /// Forwarded from [`ChannelMetadata::to_json`].
    pub fn channel_metadata_update(
        metadata: &ChannelMetadata,
        channel: EventId,
        relay: Option<&RelayUrl>,
    ) -> Result<Self, serde_json::Error> {
        let json = metadata.to_json()?;
        Ok(Self::new(KIND_CHANNEL_METADATA, json).tag(channel_root_tag(channel, relay)))
    }

    /// Author a root channel message (`kind: 42` with a single `e`
    /// tag marked `"root"`).
    #[must_use]
    pub fn channel_message_root(
        channel: EventId,
        relay: Option<&RelayUrl>,
        content: impl Into<String>,
    ) -> Self {
        Self::new(KIND_CHANNEL_MESSAGE, content).tag(channel_root_tag(channel, relay))
    }

    /// Author a reply channel message (`kind: 42` with a `"root"`
    /// tag pointing at the channel and a `"reply"` tag pointing at
    /// the parent message; a `p` tag references the replied-to
    /// author).
    #[must_use]
    pub fn channel_message_reply(
        channel: EventId,
        channel_relay: Option<&RelayUrl>,
        parent_message: EventId,
        parent_relay: Option<&RelayUrl>,
        parent_author: PublicKey,
        author_relay: Option<&RelayUrl>,
        content: impl Into<String>,
    ) -> Self {
        Self::new(KIND_CHANNEL_MESSAGE, content)
            .tag(channel_root_tag(channel, channel_relay))
            .tag(channel_reply_tag(parent_message, parent_relay))
            .tag(channel_p_tag(parent_author, author_relay))
    }

    /// Author a hide-message moderation event (`kind: 43`).
    ///
    /// `reason` is optional; pass `None` for a bare hide signal.
    #[must_use]
    pub fn channel_hide_message(target: EventId, reason: Option<&HideReason>) -> Self {
        let body = reason.map(HideReason::to_json).unwrap_or_default();
        Self::new(KIND_CHANNEL_HIDE_MESSAGE, body).tag(channel_e_tag(target))
    }

    /// Author a mute-user moderation event (`kind: 44`).
    ///
    /// `reason` is optional.
    #[must_use]
    pub fn channel_mute_user(target: PublicKey, reason: Option<&HideReason>) -> Self {
        let body = reason.map(HideReason::to_json).unwrap_or_default();
        Self::new(KIND_CHANNEL_MUTE_USER, body).tag(channel_p_tag(target, None))
    }
}

fn channel_root_tag(channel: EventId, relay: Option<&RelayUrl>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    let mut values: Vec<String> = Vec::with_capacity(4);
    values.push(channel.to_hex());
    values.push(relay.map(|r| r.as_str().to_owned()).unwrap_or_default());
    values.push("root".to_owned());
    Tag::with(&head, values)
}

fn channel_reply_tag(parent: EventId, relay: Option<&RelayUrl>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    let mut values: Vec<String> = Vec::with_capacity(4);
    values.push(parent.to_hex());
    values.push(relay.map(|r| r.as_str().to_owned()).unwrap_or_default());
    values.push("reply".to_owned());
    Tag::with(&head, values)
}

fn channel_e_tag(target: EventId) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    Tag::with(&head, [target.to_hex()])
}

fn channel_p_tag(target: PublicKey, relay: Option<&RelayUrl>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
    let mut values: Vec<String> = Vec::with_capacity(2);
    values.push(target.to_hex());
    if let Some(relay) = relay {
        values.push(relay.as_str().to_owned());
    }
    Tag::with(&head, values)
}

/// Look up the channel id (`e`-tag with `"root"` marker) on a
/// kind-41/42 event. Returns `None` when no such tag exists.
#[must_use]
pub fn channel_root_id(event: &Event) -> Option<EventId> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    for tag in event.tags.find_all(&head) {
        if tag.get(3) == Some("root")
            && let Some(id_hex) = tag.get(1)
            && let Ok(id) = EventId::parse(id_hex)
        {
            return Some(id);
        }
    }
    None
}

/// Look up the parent message id (`e`-tag with `"reply"` marker) on
/// a kind 42 event.
#[must_use]
pub fn channel_reply_id(event: &Event) -> Option<EventId> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    for tag in event.tags.find_all(&head) {
        if tag.get(3) == Some("reply")
            && let Some(id_hex) = tag.get(1)
            && let Ok(id) = EventId::parse(id_hex)
        {
            return Some(id);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn event_id_zero() -> EventId {
        EventId::from_byte_array([0x42; 32])
    }

    fn event_id_one() -> EventId {
        EventId::from_byte_array([0xab; 32])
    }

    #[test]
    fn channel_metadata_round_trips_through_json() {
        let metadata = ChannelMetadata::new()
            .name("Demo")
            .about("desc")
            .picture("https://example.com/p.png")
            .relays([
                RelayUrl::parse("wss://nos.lol").unwrap(),
                RelayUrl::parse("wss://relay.example/").unwrap(),
            ]);
        let json = metadata.to_json().unwrap();
        let parsed = ChannelMetadata::from_json(&json).unwrap();
        assert_eq!(parsed, metadata);
    }

    #[test]
    fn channel_metadata_extra_fields_round_trip() {
        let json = r#"{"name":"X","custom":[1,2,3]}"#;
        let parsed = ChannelMetadata::from_json(json).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("X"));
        assert_eq!(
            parsed
                .extra
                .get("custom")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(3),
        );
    }

    #[test]
    fn channel_metadata_rejects_non_string_picture() {
        let json = r#"{"picture":123}"#;
        let err = ChannelMetadata::from_json(json).unwrap_err();
        assert!(matches!(
            err,
            ChannelMetadataError::InvalidStringField { key: "picture", .. }
        ));
    }

    #[test]
    fn channel_metadata_rejects_invalid_relay_url() {
        let json = r#"{"relays":["not-a-relay"]}"#;
        let err = ChannelMetadata::from_json(json).unwrap_err();
        assert!(matches!(err, ChannelMetadataError::InvalidRelayUrl(_)));
    }

    #[test]
    fn channel_create_emits_kind_40_with_metadata_in_content() {
        let metadata = ChannelMetadata::new().name("hello");
        let event = EventBuilder::channel_create(&metadata)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CHANNEL_CREATE);
        let parsed = ChannelMetadata::from_json(&event.content).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("hello"));
    }

    #[test]
    fn channel_metadata_update_includes_root_marker() {
        let metadata = ChannelMetadata::new().name("upd");
        let channel = event_id_zero();
        let event = EventBuilder::channel_metadata_update(&metadata, channel, None)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CHANNEL_METADATA);
        assert_eq!(channel_root_id(&event), Some(channel));
    }

    #[test]
    fn channel_message_root_only_carries_one_e_tag() {
        let channel = event_id_zero();
        let event = EventBuilder::channel_message_root(channel, None, "hello")
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CHANNEL_MESSAGE);
        assert_eq!(channel_root_id(&event), Some(channel));
        assert_eq!(channel_reply_id(&event), None);
    }

    #[test]
    fn channel_message_reply_carries_root_reply_and_p() {
        let channel = event_id_zero();
        let parent = event_id_one();
        let parent_author = *keys().public_key();
        let event = EventBuilder::channel_message_reply(
            channel,
            None,
            parent,
            None,
            parent_author,
            None,
            "yo",
        )
        .sign_with_keys(&keys())
        .unwrap();
        assert_eq!(channel_root_id(&event), Some(channel));
        assert_eq!(channel_reply_id(&event), Some(parent));
    }

    #[test]
    fn hide_message_with_reason_emits_json_content() {
        let reason = HideReason::new().reason("dick pic");
        let event = EventBuilder::channel_hide_message(event_id_zero(), Some(&reason))
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CHANNEL_HIDE_MESSAGE);
        assert!(event.content.contains("\"reason\":\"dick pic\""));
    }

    #[test]
    fn hide_message_without_reason_has_empty_content() {
        let event = EventBuilder::channel_hide_message(event_id_zero(), None)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.content, "");
    }

    #[test]
    fn mute_user_carries_p_tag_for_target() {
        let target = *keys().public_key();
        let event = EventBuilder::channel_mute_user(target, None)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CHANNEL_MUTE_USER);
        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let p_tag = event.tags.find_first(&p_kind).unwrap();
        assert_eq!(p_tag.get(1), Some(target.to_hex().as_str()));
    }

    #[test]
    fn hide_reason_round_trips_extra_fields() {
        let json = r#"{"reason":"x","custom":42}"#;
        let parsed = HideReason::from_json(json).unwrap();
        assert_eq!(parsed.reason.as_deref(), Some("x"));
        assert_eq!(
            parsed
                .extra
                .get("custom")
                .and_then(serde_json::Value::as_i64),
            Some(42),
        );
    }
}
