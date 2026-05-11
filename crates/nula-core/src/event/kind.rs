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
    /// Wallet Connect info / capability advert (NIP-47).
    pub const WALLET_CONNECT_INFO: Self = Self(13_194);
    /// Wallet Connect request (NIP-47).
    pub const WALLET_CONNECT_REQUEST: Self = Self(23_194);
    /// Wallet Connect response (NIP-47).
    pub const WALLET_CONNECT_RESPONSE: Self = Self(23_195);
    /// Wallet Connect legacy NIP-04 notification (NIP-47).
    pub const WALLET_CONNECT_NOTIFICATION_LEGACY: Self = Self(23_196);
    /// Wallet Connect NIP-44 notification (NIP-47).
    pub const WALLET_CONNECT_NOTIFICATION: Self = Self(23_197);
    /// Badge award (NIP-58).
    pub const BADGE_AWARD: Self = Self(8);
    /// Zap request (NIP-57). Not published to relays; sent to the
    /// recipient's LNURL callback.
    pub const ZAP_REQUEST: Self = Self(9_734);
    /// Zap receipt (NIP-57).
    pub const ZAP_RECEIPT: Self = Self(9_735);
    /// Badge definition (NIP-58).
    pub const BADGE_DEFINITION: Self = Self(30_009);
    /// Public-channel creation (NIP-28).
    pub const CHANNEL_CREATION: Self = Self(40);
    /// Public-channel metadata update (NIP-28).
    pub const CHANNEL_METADATA: Self = Self(41);
    /// Public-channel chat message (NIP-28).
    pub const CHANNEL_MESSAGE: Self = Self(42);
    /// Public-channel hide-message moderation (NIP-28).
    pub const CHANNEL_HIDE_MESSAGE: Self = Self(43);
    /// Public-channel mute-user moderation (NIP-28).
    pub const CHANNEL_MUTE_USER: Self = Self(44);
    /// File metadata (NIP-94).
    pub const FILE_METADATA: Self = Self(1063);
    /// Generic repost (NIP-18).
    pub const GENERIC_REPOST: Self = Self(16);
    /// Reporting (NIP-56).
    pub const REPORTING: Self = Self(1984);
    /// Relay authentication (NIP-42).
    pub const AUTHENTICATION: Self = Self(22242);
    /// Seal (NIP-59) — the encrypted middle layer of a gift-wrapped event.
    pub const SEAL: Self = Self(13);
    /// Private direct message (NIP-17).
    pub const PRIVATE_DIRECT_MESSAGE: Self = Self(14);
    /// File message (NIP-17).
    pub const FILE_MESSAGE: Self = Self(15);
    /// Gift wrap (NIP-59).
    pub const GIFT_WRAP: Self = Self(1059);
    /// Direct-message relay list (NIP-17 §10050).
    pub const DM_RELAYS: Self = Self(10_050);
    /// Long-form content (NIP-23).
    pub const LONG_FORM_TEXT_NOTE: Self = Self(30023);
    /// Relay list metadata (NIP-65).
    pub const RELAY_LIST: Self = Self(10002);
    /// Mute list (NIP-51 §"Standard lists").
    pub const MUTE_LIST: Self = Self(10_000);
    /// Pinned-notes list (NIP-51).
    pub const PINNED_NOTES: Self = Self(10_001);
    /// Bookmarks list (NIP-51).
    pub const BOOKMARKS: Self = Self(10_003);
    /// Communities list (NIP-51 / NIP-72).
    pub const COMMUNITIES_LIST: Self = Self(10_004);
    /// Public-chats list (NIP-51 / NIP-28).
    pub const PUBLIC_CHATS_LIST: Self = Self(10_005);
    /// Blocked-relays list (NIP-51).
    pub const BLOCKED_RELAYS: Self = Self(10_006);
    /// Search-relays list (NIP-51).
    pub const SEARCH_RELAYS: Self = Self(10_007);
    /// Profile badges list (NIP-51 / NIP-58).
    pub const PROFILE_BADGES: Self = Self(10_008);
    /// Simple-groups list (NIP-51 / NIP-29).
    pub const SIMPLE_GROUPS_LIST: Self = Self(10_009);
    /// Relay feeds list (NIP-51).
    pub const RELAY_FEEDS: Self = Self(10_012);
    /// Interests list (NIP-51).
    pub const INTERESTS_LIST: Self = Self(10_015);
    /// Media-follows list (NIP-51).
    pub const MEDIA_FOLLOWS: Self = Self(10_020);
    /// Emojis list (NIP-51 / NIP-30).
    pub const EMOJIS_LIST: Self = Self(10_030);
    /// Blossom-servers list (NIP-51 / NIP-B7).
    pub const BLOSSOM_SERVERS: Self = Self(10_063);
    /// Follow set (NIP-51 §"Sets").
    pub const FOLLOW_SET: Self = Self(30_000);
    /// Relay set (NIP-51).
    pub const RELAY_SET: Self = Self(30_002);
    /// Bookmark set (NIP-51).
    pub const BOOKMARK_SET: Self = Self(30_003);
    /// Articles curation set (NIP-51).
    pub const ARTICLES_CURATION_SET: Self = Self(30_004);
    /// Videos curation set (NIP-51).
    pub const VIDEOS_CURATION_SET: Self = Self(30_005);
    /// Pictures curation set (NIP-51).
    pub const PICTURES_CURATION_SET: Self = Self(30_006);
    /// Kind-mute set (NIP-51).
    pub const KIND_MUTE_SET: Self = Self(30_007);
    /// Badge set (NIP-51 / NIP-58).
    pub const BADGE_SET: Self = Self(30_008);
    /// Interest set (NIP-51).
    pub const INTEREST_SET: Self = Self(30_015);
    /// Emoji set (NIP-51 / NIP-30).
    pub const EMOJI_SET: Self = Self(30_030);
    /// Release-artifact set (NIP-51).
    pub const RELEASE_ARTIFACT_SET: Self = Self(30_063);
    /// App-curation set (NIP-51).
    pub const APP_CURATION_SET: Self = Self(30_267);
    /// Calendar set (NIP-51 / NIP-52).
    pub const CALENDAR_SET: Self = Self(31_924);
    /// Starter pack (NIP-51).
    pub const STARTER_PACK: Self = Self(39_089);
    /// Media starter pack (NIP-51).
    pub const MEDIA_STARTER_PACK: Self = Self(39_092);

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

    /// True for the `30000..=39999` addressable range (NIP-01).
    ///
    /// Addressable events are uniquely identified by
    /// `(pubkey, kind, d-tag)` and are the modern term for what NIP-33
    /// originally called "parameterized replaceable events".
    #[must_use]
    pub const fn is_addressable(self) -> bool {
        matches!(self.0, 30_000..=39_999)
    }

    /// True for the `20000..=29999` ephemeral range (NIP-01).
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        matches!(self.0, 20_000..=29_999)
    }

    /// True for the regular ranges spelled out by NIP-01:
    /// `n == 1`, `n == 2`, `4 <= n < 45`, or `1000 <= n < 10000`.
    ///
    /// Note that NIP-01 leaves the kinds `45..=999` unclassified — they
    /// are *not* regular by the strict reading of the spec, even though
    /// many implementations historically lumped them in. Use
    /// [`Self::is_unclassified`] to detect those.
    #[must_use]
    pub const fn is_regular(self) -> bool {
        matches!(self.0, 1 | 2 | 4..45 | 1000..10_000)
    }

    /// True for kinds in the reserved range `40000..=65535`.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(self.0, 40_000..=65_535)
    }

    /// True for kinds that NIP-01 does *not* assign to any category:
    /// `45..=999` and the reserved `40000..=65535` block. Surface these so
    /// callers (relays, indexers) can decide how to treat the holes
    /// without having to invert every other classifier.
    #[must_use]
    pub const fn is_unclassified(self) -> bool {
        !(self.is_regular()
            || self.is_replaceable()
            || self.is_addressable()
            || self.is_ephemeral())
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
    fn addressable_classification() {
        assert!(Kind::LONG_FORM_TEXT_NOTE.is_addressable());
        assert!(!Kind::TEXT_NOTE.is_addressable());
    }

    #[test]
    fn ephemeral_range() {
        assert!(Kind::AUTHENTICATION.is_ephemeral());
        assert!(!Kind::TEXT_NOTE.is_ephemeral());
    }

    #[test]
    fn regular_range() {
        // NIP-01 spec: `n == 1 || n == 2 || 4 <= n < 45 || 1000 <= n < 10000`.
        assert!(Kind::TEXT_NOTE.is_regular());
        assert!(Kind::REACTION.is_regular());
        assert!(Kind::GIFT_WRAP.is_regular());
        assert!(Kind::new(44).is_regular());
        assert!(Kind::new(1_000).is_regular());
        assert!(Kind::new(9_999).is_regular());
        assert!(!Kind::METADATA.is_regular());
        assert!(!Kind::AUTHENTICATION.is_regular());
        assert!(!Kind::LONG_FORM_TEXT_NOTE.is_regular());
        // The 45..1000 hole is NOT regular per the strict spec reading.
        assert!(!Kind::new(45).is_regular());
        assert!(!Kind::new(999).is_regular());
    }

    #[test]
    fn reserved_range() {
        assert!(Kind::new(40_000).is_reserved());
        assert!(Kind::new(65_535).is_reserved());
        assert!(!Kind::new(39_999).is_reserved());
    }

    #[test]
    fn unclassified_range_is_distinct_from_every_category() {
        // The 45..1000 hole is unclassified.
        assert!(Kind::new(45).is_unclassified());
        assert!(Kind::new(500).is_unclassified());
        assert!(Kind::new(999).is_unclassified());
        // The reserved 40000..=65535 block is unclassified and reserved.
        assert!(Kind::new(40_000).is_unclassified());
        assert!(Kind::new(65_535).is_unclassified());
        // Each named category is *not* unclassified.
        assert!(!Kind::TEXT_NOTE.is_unclassified());
        assert!(!Kind::METADATA.is_unclassified());
        assert!(!Kind::AUTHENTICATION.is_unclassified());
        assert!(!Kind::LONG_FORM_TEXT_NOTE.is_unclassified());
    }

    #[test]
    fn classification_is_disjoint_and_complete() {
        for raw in 0_u16..=u16::MAX {
            let kind = Kind::new(raw);
            let count = u32::from(kind.is_regular())
                + u32::from(kind.is_replaceable())
                + u32::from(kind.is_addressable())
                + u32::from(kind.is_ephemeral())
                + u32::from(kind.is_unclassified());
            assert_eq!(
                count, 1,
                "kind {raw} matched {count} categories (must be exactly 1)"
            );
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
