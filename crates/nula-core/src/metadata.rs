// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! NIP-01 user metadata (kind `0` event content).
//!
//! Per [NIP-01], the content of a `kind: 0` event is a JSON-encoded user
//! profile. NIP-24 layered additional public-profile fields on top of the
//! original four (`name`, `about`, `picture`, `nip05`); this struct models
//! every standardised field and preserves any unknown ones inside
//! [`Metadata::custom`] so future NIP extensions stay round-trippable.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use serde::{Deserialize, Serialize};
use serde_json::Map as JsonMap;
use serde_json::Value as JsonValue;

use crate::event::{EventBuilder, Kind};
use crate::types::Url;

/// User profile metadata published as the content of a `kind: 0` event.
///
/// Every field is optional; unknown JSON properties survive a round-trip via
/// [`Metadata::custom`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Short username, e.g. `alice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Display name (NIP-24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Biographical description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Personal web site (NIP-24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<Url>,
    /// Profile picture URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<Url>,
    /// Banner image URL (NIP-24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<Url>,
    /// NIP-05 verification identifier (`alice@example.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    /// LNURL-pay identifier (legacy LUD-06).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud06: Option<String>,
    /// Lightning Address (LUD-16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    /// Forward-compatible escape hatch: any property the spec adds (or any
    /// project-specific custom property) is preserved verbatim here.
    #[serde(flatten)]
    pub custom: JsonMap<String, JsonValue>,
}

impl Metadata {
    /// Construct an empty profile.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `name` field.
    #[must_use]
    pub fn with_name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the `display_name` field (NIP-24).
    #[must_use]
    pub fn with_display_name<S: Into<String>>(mut self, name: S) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the `about` field.
    #[must_use]
    pub fn with_about<S: Into<String>>(mut self, about: S) -> Self {
        self.about = Some(about.into());
        self
    }

    /// Set the `website` field.
    #[must_use]
    pub fn with_website(mut self, website: Url) -> Self {
        self.website = Some(website);
        self
    }

    /// Set the `picture` field.
    #[must_use]
    pub fn with_picture(mut self, picture: Url) -> Self {
        self.picture = Some(picture);
        self
    }

    /// Set the `banner` field (NIP-24).
    #[must_use]
    pub fn with_banner(mut self, banner: Url) -> Self {
        self.banner = Some(banner);
        self
    }

    /// Set the `nip05` field.
    #[must_use]
    pub fn with_nip05<S: Into<String>>(mut self, nip05: S) -> Self {
        self.nip05 = Some(nip05.into());
        self
    }

    /// Set the `lud06` field (legacy LNURL-pay).
    #[must_use]
    pub fn with_lud06<S: Into<String>>(mut self, lud06: S) -> Self {
        self.lud06 = Some(lud06.into());
        self
    }

    /// Set the `lud16` field (Lightning Address).
    #[must_use]
    pub fn with_lud16<S: Into<String>>(mut self, lud16: S) -> Self {
        self.lud16 = Some(lud16.into());
        self
    }

    /// Insert a custom JSON property.
    ///
    /// Useful for extensions defined by future NIPs that this crate has not
    /// modelled yet.
    #[must_use]
    pub fn with_custom<S, V>(mut self, key: S, value: V) -> Self
    where
        S: Into<String>,
        V: Into<JsonValue>,
    {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Render `self` as the JSON string that goes into a `kind: 0` event's
    /// `content` field.
    ///
    /// # Errors
    ///
    /// Returns the underlying `serde_json` error if the metadata cannot be
    /// serialized (in practice impossible for user metadata, but `serde_json`
    /// keeps the type fallible).
    pub fn to_event_content(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse the `content` of a `kind: 0` event into a [`Metadata`].
    ///
    /// # Errors
    ///
    /// Returns a `serde_json` error if `content` is not a JSON object.
    pub fn from_event_content(content: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(content)
    }
}

impl EventBuilder {
    /// Construct an [`EventBuilder`] for a `kind: 0` profile event whose
    /// content is the JSON serialization of `metadata`.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json` error if `metadata` cannot be serialized.
    pub fn metadata(metadata: &Metadata) -> Result<Self, serde_json::Error> {
        let content = metadata.to_event_content()?;
        Ok(Self::new(Kind::METADATA, content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
    }

    #[test]
    fn empty_round_trip() {
        let meta = Metadata::default();
        let json = meta.to_event_content().unwrap();
        assert_eq!(json, "{}");
        let parsed = Metadata::from_event_content(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn populated_round_trip() {
        let meta = Metadata::new()
            .with_name("alice")
            .with_display_name("Alice")
            .with_about("Cypherpunk.")
            .with_website(Url::parse("https://alice.example").unwrap())
            .with_picture(Url::parse("https://alice.example/pfp.png").unwrap())
            .with_banner(Url::parse("https://alice.example/banner.png").unwrap())
            .with_nip05("alice@alice.example")
            .with_lud06("LNURL1...")
            .with_lud16("alice@getalby.com");
        let json = meta.to_event_content().unwrap();
        let parsed = Metadata::from_event_content(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn custom_fields_survive_round_trip() {
        let meta = Metadata::new()
            .with_name("alice")
            .with_custom("bot", true)
            .with_custom("custom_handle", "@alice");
        let json = meta.to_event_content().unwrap();
        let parsed = Metadata::from_event_content(&json).unwrap();
        assert_eq!(parsed, meta);
        assert_eq!(parsed.custom.get("bot"), Some(&JsonValue::Bool(true)));
    }

    #[test]
    fn unknown_fields_remain_in_custom() {
        let json = r#"{"name":"alice","future_field":42}"#;
        let meta = Metadata::from_event_content(json).unwrap();
        assert_eq!(meta.name.as_deref(), Some("alice"));
        assert_eq!(
            meta.custom.get("future_field"),
            Some(&JsonValue::Number(42.into()))
        );
    }

    #[test]
    fn event_builder_metadata_helper_signs_kind_zero() {
        let meta = Metadata::new()
            .with_name("alice")
            .with_about("Hello, Nostr.");
        let event = EventBuilder::metadata(&meta)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, Kind::METADATA);
        let parsed = Metadata::from_event_content(&event.content).unwrap();
        assert_eq!(parsed, meta);
        event.verify().unwrap();
    }
}
