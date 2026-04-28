// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-11] Relay Information Document.
//!
//! NIP-11 lets a relay describe itself by serving a JSON document over HTTPS
//! when the client sends `Accept: application/nostr+json`. Clients use the
//! document to discover supported NIPs, fee schedules, contact points, etc.
//!
//! Every field is optional and forward-compatible: the relay can drop or add
//! fields between releases without breaking older clients. The crate keeps
//! every documented field as a strongly typed [`Option`] / [`Vec`] and
//! tolerates unknown fields silently (`#[serde(default)]` plus the absence
//! of `deny_unknown_fields`).
//!
//! [NIP-11]: https://github.com/nostr-protocol/nips/blob/master/11.md

pub mod fees;
pub mod limitation;
pub mod retention;

pub use self::fees::{RelayFee, RelayFees};
pub use self::limitation::RelayLimitation;
pub use self::retention::{KindRange, RelayRetention};

use serde::{Deserialize, Serialize};

use crate::key::PublicKey;
use crate::types::Url;

/// The complete NIP-11 document.
///
/// All fields are optional. `Default` returns an empty document — useful as
/// the starting point of a builder.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayInformation {
    /// Operator-chosen name for the relay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Operator's public key (typically used for moderation messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<PublicKey>,
    /// Free-form contact string (email, Nostr profile, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// NIP numbers the relay claims to support.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_nips: Vec<u16>,
    /// URL of the relay's source code or product page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Url>,
    /// Software version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Optional icon URL (PNG/SVG).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Url>,
    /// Server-side limitations on client behaviour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<RelayLimitation>,
    /// Two-letter ISO country codes the relay primarily serves.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relay_countries: Vec<String>,
    /// IETF BCP-47 language tags the operator suggests for the relay.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub language_tags: Vec<String>,
    /// Free-form classification tags (`"spanish"`, `"music"`, …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Posting policy URL (terms of use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posting_policy: Option<Url>,
    /// Web page where users can pay fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payments_url: Option<Url>,
    /// Fee schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<RelayFees>,
    /// Per-class retention rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub retention: Vec<RelayRetention>,
}

impl RelayInformation {
    /// Construct an empty document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the relay advertises support for the given NIP number.
    #[must_use]
    pub fn supports_nip(&self, nip: u16) -> bool {
        self.supported_nips.contains(&nip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_pubkey() -> PublicKey {
        let keys =
            Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        *keys.public_key()
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        let json = serde_json::to_string(&RelayInformation::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn round_trip_full_document() {
        let info = RelayInformation {
            name: Some("Nula Relay".to_owned()),
            description: Some("A reliable Nostr relay.".to_owned()),
            pubkey: Some(fixture_pubkey()),
            contact: Some("ops@nula.example".to_owned()),
            supported_nips: vec![1, 9, 11, 19, 42],
            software: Some(Url::parse("https://github.com/qntx/nula").unwrap()),
            version: Some("0.1.0".to_owned()),
            icon: Some(Url::parse("https://nula.example/icon.png").unwrap()),
            limitation: Some(RelayLimitation {
                max_message_length: Some(16_384),
                max_subscriptions: Some(20),
                auth_required: Some(true),
                ..RelayLimitation::default()
            }),
            relay_countries: vec!["US".into(), "JP".into()],
            language_tags: vec!["en".into(), "ja".into()],
            tags: vec!["general".into()],
            posting_policy: Some(Url::parse("https://nula.example/policy").unwrap()),
            payments_url: Some(Url::parse("https://nula.example/billing").unwrap()),
            fees: Some(RelayFees {
                admission: vec![RelayFee {
                    amount: 1000,
                    unit: "msats".into(),
                    period: None,
                    kinds: None,
                }],
                ..RelayFees::default()
            }),
            retention: vec![RelayRetention {
                kinds: vec![KindRange::Single(crate::Kind::from(0_u16))],
                time: Some(3600),
                count: None,
            }],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: RelayInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{
            "name": "Future",
            "future_field": 42,
            "supported_nips": [1, 99]
        }"#;
        let info: RelayInformation = serde_json::from_str(json).unwrap();
        assert_eq!(info.name.as_deref(), Some("Future"));
        assert!(info.supports_nip(99));
        assert!(!info.supports_nip(7));
    }
}
