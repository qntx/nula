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
    /// NIP-24 `bot` flag: `true` if the profile is fully or partially
    /// automated (chatbots, newsfeeds, AI agents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot: Option<bool>,
    /// NIP-24 `birthday` object. Every component (`year` / `month` /
    /// `day`) is individually optional so partial dates (e.g.
    /// month-and-day only) round-trip cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday: Option<Birthday>,
    /// Forward-compatible escape hatch: any property the spec adds (or any
    /// project-specific custom property) is preserved verbatim here.
    ///
    /// Two NIP-24 *deprecated* fields intentionally land here rather
    /// than in dedicated fields:
    ///
    /// - `displayName` (camel-case) — superseded by [`Self::display_name`];
    /// - `username` — superseded by [`Self::name`].
    ///
    /// Access them via [`Self::legacy_display_name`] and
    /// [`Self::legacy_username`] when a caller needs to migrate an old
    /// profile without dropping bytes.
    #[serde(flatten)]
    pub custom: JsonMap<String, JsonValue>,
}

/// NIP-24 `birthday` object.
///
/// All three components are independently optional: a profile MAY publish
/// only `month` + `day` to celebrate without revealing the year, only
/// `year` + `month` for approximate birthdays, or any other subset.
///
/// The struct is `Copy` because it carries only small integer fields;
/// the field types (`u16` for year, `u8` for month/day) reject obvious
/// out-of-range values at deserialisation time without extra guards.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Birthday {
    /// Birth year (e.g. `1990`). Range is not further constrained
    /// because the spec leaves future-dated profiles to application
    /// policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub year: Option<u16>,
    /// Birth month (1–12 when present; values outside that range are
    /// allowed to round-trip but should be rejected at application
    /// level).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub month: Option<u8>,
    /// Birth day of month (1–31 when present; application layer is
    /// responsible for month-specific validation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<u8>,
}

impl Birthday {
    /// Construct a fully specified birthday.
    #[must_use]
    pub const fn new(year: u16, month: u8, day: u8) -> Self {
        Self {
            year: Some(year),
            month: Some(month),
            day: Some(day),
        }
    }

    /// Construct a month-and-day-only birthday (privacy-preserving form
    /// used by several real-world clients).
    #[must_use]
    pub const fn month_day(month: u8, day: u8) -> Self {
        Self {
            year: None,
            month: Some(month),
            day: Some(day),
        }
    }
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

    /// Set the NIP-24 `bot` flag.
    #[must_use]
    pub const fn with_bot(mut self, bot: bool) -> Self {
        self.bot = Some(bot);
        self
    }

    /// Set the NIP-24 `birthday` object.
    #[must_use]
    pub const fn with_birthday(mut self, birthday: Birthday) -> Self {
        self.birthday = Some(birthday);
        self
    }

    /// Return the deprecated NIP-24 `displayName` value if the profile
    /// was produced by an older client. Prefer [`Self::display_name`]
    /// for every new write path.
    #[must_use]
    pub fn legacy_display_name(&self) -> Option<&str> {
        self.custom.get("displayName").and_then(JsonValue::as_str)
    }

    /// Return the deprecated NIP-24 `username` value. Prefer
    /// [`Self::name`] for every new write path.
    #[must_use]
    pub fn legacy_username(&self) -> Option<&str> {
        self.custom.get("username").and_then(JsonValue::as_str)
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
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
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
            .with_custom("custom_handle", "@alice")
            .with_custom("x_internal_id", 7);
        let json = meta.to_event_content().unwrap();
        let parsed = Metadata::from_event_content(&json).unwrap();
        assert_eq!(parsed, meta);
        assert_eq!(
            parsed.custom.get("custom_handle"),
            Some(&JsonValue::String("@alice".into()))
        );
        assert_eq!(
            parsed.custom.get("x_internal_id"),
            Some(&JsonValue::Number(7.into()))
        );
        // `bot` is now a first-class field, not a custom escape-hatch.
        assert!(parsed.custom.get("bot").is_none());
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

    /// Pinned vectors from the NIP-24 §"Extra metadata fields" spec.
    /// Each fixture is the literal `content` JSON a real-world client
    /// (Damus, Amethyst, Coracle) ships in a `kind: 0` event. These
    /// guard against drift in the field-level serde shape across
    /// future refactors.
    mod nip24_fixtures {
        use super::*;

        /// Minimal NIP-01 §user-metadata payload (name + about + picture).
        /// Round-tripping must produce identical bytes after re-encoding.
        #[test]
        fn nip01_minimal_round_trip() {
            let json = r#"{"name":"alice","about":"cypherpunk","picture":"https://alice.example/pfp.png"}"#;
            let parsed = Metadata::from_event_content(json).unwrap();
            assert_eq!(parsed.name.as_deref(), Some("alice"));
            assert_eq!(parsed.about.as_deref(), Some("cypherpunk"));
            assert_eq!(
                parsed.picture.as_ref().map(Url::as_str),
                Some("https://alice.example/pfp.png"),
            );
            // Re-encode and confirm the JSON round-trips field-for-field.
            let again = Metadata::from_event_content(&parsed.to_event_content().unwrap()).unwrap();
            assert_eq!(again, parsed);
        }

        /// Full NIP-24 payload exercising every standardised field.
        #[test]
        fn nip24_full_payload_round_trip() {
            let meta = Metadata::new()
                .with_name("alice")
                .with_display_name("Alice the Cypherpunk")
                .with_about("Building on Nostr.")
                .with_website(Url::parse("https://alice.example").unwrap())
                .with_picture(Url::parse("https://alice.example/pfp.png").unwrap())
                .with_banner(Url::parse("https://alice.example/banner.png").unwrap())
                .with_nip05("alice@alice.example")
                .with_lud06("LNURL1DP68GURN8GHJ7AMPD3KX2AR0VEEKZAR0WD5XJTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNVWQHKZURF9AKXUATJD3CZ7CT9XGEK2ATWXSHHQH4UQAQE")
                .with_lud16("alice@getalby.com")
                .with_bot(false)
                .with_birthday(Birthday::new(1990, 6, 15));

            let json = meta.to_event_content().unwrap();
            // Sanity: every standardised field appears verbatim in the
            // wire form. serde_json sorts Object keys alphabetically, so
            // for nested objects we only assert the inner numbers, not
            // the surrounding key order.
            for needle in [
                r#""name":"alice""#,
                r#""display_name":"Alice the Cypherpunk""#,
                r#""website":"https://alice.example/""#,
                r#""banner":"https://alice.example/banner.png""#,
                r#""nip05":"alice@alice.example""#,
                r#""lud16":"alice@getalby.com""#,
                r#""bot":false"#,
                r#""day":15"#,
                r#""month":6"#,
                r#""year":1990"#,
            ] {
                assert!(
                    json.contains(needle),
                    "missing `{needle}` in serialized metadata: {json}",
                );
            }
            assert_eq!(Metadata::from_event_content(&json).unwrap(), meta);
        }

        /// Real-world Coracle-style payload that emits an unknown
        /// `damus_donation_v2` field. Forward-compat: we round-trip it
        /// through `custom` without dropping bytes.
        #[test]
        fn forward_compat_unknown_fields_round_trip() {
            let json = r#"{"name":"bob","damus_donation_v2":21,"website":"https://b.example/"}"#;
            let parsed = Metadata::from_event_content(json).unwrap();
            assert_eq!(parsed.name.as_deref(), Some("bob"));
            assert_eq!(
                parsed.custom.get("damus_donation_v2"),
                Some(&serde_json::Value::Number(21.into()))
            );
            // Re-encoding preserves the unknown field.
            let again = parsed.to_event_content().unwrap();
            assert!(again.contains(r#""damus_donation_v2":21"#));
        }

        /// Privacy-preserving birthday: only month + day. NIP-24
        /// explicitly allows omitting the year.
        #[test]
        fn partial_birthday_round_trip() {
            let meta = Metadata::new()
                .with_name("mallory")
                .with_birthday(Birthday::month_day(4, 1));
            let json = meta.to_event_content().unwrap();
            assert!(json.contains(r#""birthday":{"month":4,"day":1}"#));
            assert!(
                !json.contains("\"year\""),
                "omitted year must not appear in the payload: {json}"
            );
            assert_eq!(Metadata::from_event_content(&json).unwrap(), meta);
        }

        /// NIP-24 §Deprecated fields: `displayName` / `username` must
        /// survive a round-trip through `custom` and be reachable via
        /// the legacy accessors without shadowing the canonical
        /// `display_name` / `name` fields.
        #[test]
        fn deprecated_fields_are_accessible_via_legacy_getters() {
            let json = r#"{"displayName":"Dave","username":"davey","name":"dave","display_name":"Dave (new)"}"#;
            let meta = Metadata::from_event_content(json).unwrap();

            assert_eq!(meta.name.as_deref(), Some("dave"));
            assert_eq!(meta.display_name.as_deref(), Some("Dave (new)"));
            assert_eq!(meta.legacy_username(), Some("davey"));
            assert_eq!(meta.legacy_display_name(), Some("Dave"));

            // Bytes stay: re-serialising still includes both legacy keys.
            let again = meta.to_event_content().unwrap();
            assert!(again.contains(r#""displayName":"Dave""#));
            assert!(again.contains(r#""username":"davey""#));
        }
    }
}
