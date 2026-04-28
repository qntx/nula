// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Event kind.
//!
//! Per [NIP-01], every event carries a non-negative integer `kind` in the
//! range `0..=65535`. The integer encodes both the application-level meaning
//! (metadata, text note, reaction, …) and the relay-side persistence rule
//! through the following ranges:
//!
//! | Range             | Behaviour                              |
//! |-------------------|----------------------------------------|
//! | `0`               | Replaceable (user metadata)            |
//! | `3`               | Replaceable (contacts / NIP-02)        |
//! | `1`–`9999`        | Regular — relays SHOULD store          |
//! | `10000`–`19999`   | Replaceable — only the latest is kept  |
//! | `20000`–`29999`   | Ephemeral — relays MUST NOT persist    |
//! | `30000`–`39999`   | Parameterized replaceable (NIP-33/01)  |
//! | `40000`–`65535`   | Reserved for future categories         |
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;
use core::num::ParseIntError;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// Event kind (`u16`, NIP-01).
///
/// `Kind` is `Copy` and round-trips through JSON as a plain integer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Kind(u16);

impl Kind {
    /// User metadata (NIP-01).
    pub const METADATA: Self = Self(0);
    /// Short text note (NIP-01).
    pub const TEXT_NOTE: Self = Self(1);
    /// Recommend relay (NIP-01, deprecated by NIP-65).
    pub const RECOMMEND_RELAY: Self = Self(2);
    /// Contacts / follow list (NIP-02).
    pub const CONTACTS: Self = Self(3);
    /// Encrypted direct message (NIP-04, deprecated).
    pub const ENCRYPTED_DIRECT_MESSAGE: Self = Self(4);
    /// Event deletion request (NIP-09).
    pub const EVENT_DELETION: Self = Self(5);
    /// Repost (NIP-18).
    pub const REPOST: Self = Self(6);
    /// Reaction (NIP-25).
    pub const REACTION: Self = Self(7);
    /// Generic repost (NIP-18).
    pub const GENERIC_REPOST: Self = Self(16);
    /// Reporting (NIP-56).
    pub const REPORTING: Self = Self(1984);
    /// Relay authentication (NIP-42).
    pub const AUTHENTICATION: Self = Self(22242);
    /// Gift wrap (NIP-59).
    pub const GIFT_WRAP: Self = Self(1059);
    /// Long-form content (NIP-23).
    pub const LONG_FORM_TEXT_NOTE: Self = Self(30023);
    /// Relay list metadata (NIP-65).
    pub const RELAY_LIST: Self = Self(10002);

    /// Construct a kind from a raw `u16`.
    #[must_use]
    pub const fn new(kind: u16) -> Self {
        Self(kind)
    }

    /// Return the raw `u16`.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// True for the metadata, contacts, and `10000..=19999` ranges (NIP-01).
    #[must_use]
    pub const fn is_replaceable(self) -> bool {
        matches!(self.0, 0 | 3 | 10_000..=19_999)
    }

    /// True for the `30000..=39999` parameterized replaceable range
    /// (NIP-01 / NIP-33).
    #[must_use]
    pub const fn is_parameterized_replaceable(self) -> bool {
        matches!(self.0, 30_000..=39_999)
    }

    /// True for the `20000..=29999` ephemeral range (NIP-01).
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        matches!(self.0, 20_000..=29_999)
    }

    /// True for the regular `1..=9999` range (excluding metadata/contacts at
    /// `0` and `3`, which are replaceable). Regular events are persisted by
    /// relays without being replaced or evicted.
    #[must_use]
    pub const fn is_regular(self) -> bool {
        !self.is_replaceable() && !self.is_parameterized_replaceable() && !self.is_ephemeral()
    }

    /// True for kinds in the reserved range `40000..=65535`.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(self.0, 40_000..=65_535)
    }
}

impl From<u16> for Kind {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Kind> for u16 {
    fn from(value: Kind) -> Self {
        value.0
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for Kind {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u16>().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_round_trip() {
        let kind = Kind::new(1234);
        assert_eq!(kind.as_u16(), 1234);
    }

    #[test]
    fn replaceable_classification() {
        assert!(Kind::METADATA.is_replaceable());
        assert!(Kind::CONTACTS.is_replaceable());
        assert!(Kind::RELAY_LIST.is_replaceable());
        assert!(!Kind::TEXT_NOTE.is_replaceable());
    }

    #[test]
    fn parameterized_replaceable_classification() {
        assert!(Kind::LONG_FORM_TEXT_NOTE.is_parameterized_replaceable());
        assert!(!Kind::TEXT_NOTE.is_parameterized_replaceable());
    }

    #[test]
    fn ephemeral_range() {
        assert!(Kind::AUTHENTICATION.is_ephemeral());
        assert!(!Kind::TEXT_NOTE.is_ephemeral());
    }

    #[test]
    fn regular_range() {
        assert!(Kind::TEXT_NOTE.is_regular());
        assert!(Kind::REACTION.is_regular());
        assert!(Kind::GIFT_WRAP.is_regular());
        assert!(!Kind::METADATA.is_regular());
        assert!(!Kind::AUTHENTICATION.is_regular());
        assert!(!Kind::LONG_FORM_TEXT_NOTE.is_regular());
    }

    #[test]
    fn reserved_range() {
        assert!(Kind::new(40_000).is_reserved());
        assert!(Kind::new(65_535).is_reserved());
        assert!(!Kind::new(39_999).is_reserved());
    }

    #[test]
    fn classification_is_disjoint() {
        for raw in [0_u16, 1, 3, 1_059, 10_002, 22_242, 30_023, 50_000] {
            let kind = Kind::new(raw);
            let count = u32::from(kind.is_regular())
                + u32::from(kind.is_replaceable())
                + u32::from(kind.is_parameterized_replaceable())
                + u32::from(kind.is_ephemeral());
            assert_eq!(count, 1, "kind {raw} matched {count} categories");
        }
    }

    #[test]
    fn display_matches_integer() {
        assert_eq!(Kind::TEXT_NOTE.to_string(), "1");
    }

    #[test]
    fn parse_from_str() {
        let kind: Kind = "30023".parse().unwrap();
        assert_eq!(kind, Kind::LONG_FORM_TEXT_NOTE);
        assert!("abc".parse::<Kind>().is_err());
    }

    #[test]
    fn serde_is_integer() {
        let kind = Kind::TEXT_NOTE;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "1");
        let parsed: Kind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }
}
