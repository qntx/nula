//! [NIP-87] Ecash Mint Discoverability.
//!
//! Three event shapes let users discover ecash mints and the people
//! who vouch for them:
//!
//! | Kind    | Author   | Meaning                                     |
//! |---------|----------|---------------------------------------------|
//! | `38172` | mint     | Cashu mint announcement (`d` = mint pubkey) |
//! | `38173` | mint     | Fedimint announcement (`d` = federation id) |
//! | `38000` | user     | Mint recommendation (`d` = announced id)    |
//!
//! Announcements carry connection hints in `u` tags, the supported
//! capability list (`nuts` for Cashu, `modules` for Fedimint), and an
//! `n` network tag. Their `.content` is an optional `kind: 0`-style
//! metadata JSON; when empty, clients fall back to the author's
//! `kind: 0`.
//!
//! Recommendations point back at announcements through `a` tags with
//! relay hints, carry connection strings in `u` tags, and use
//! `.content` as a free-form review.
//!
//! [NIP-87]: https://github.com/nostr-protocol/nips/blob/master/87.md

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::types::RelayUrl;

/// `kind: 38172` — Cashu mint announcement.
pub const KIND_CASHU_MINT: Kind = Kind::CASHU_MINT_ANNOUNCEMENT;
/// `kind: 38173` — Fedimint announcement.
pub const KIND_FEDIMINT: Kind = Kind::FEDIMINT_ANNOUNCEMENT;
/// `kind: 38000` — mint recommendation.
pub const KIND_MINT_RECOMMENDATION: Kind = Kind::MINT_RECOMMENDATION;

const NUTS_TAG: &str = "nuts";
const MODULES_TAG: &str = "modules";

/// Bitcoin network a mint operates on (`n` tag).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MintNetwork {
    /// `mainnet`.
    Mainnet,
    /// `testnet`.
    Testnet,
    /// `signet`.
    Signet,
    /// `regtest`.
    Regtest,
    /// Forward-compatible passthrough for unknown networks.
    Other(String),
}

impl MintNetwork {
    /// Parse the `n` tag wire form. Unknown networks land in
    /// [`MintNetwork::Other`], so this never fails.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "mainnet" => Self::Mainnet,
            "testnet" => Self::Testnet,
            "signet" => Self::Signet,
            "regtest" => Self::Regtest,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Wire form used by the `n` tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
            Self::Other(raw) => raw,
        }
    }
}

impl fmt::Display for MintNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MintNetwork {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

/// Kind of ecash mint an announcement or recommendation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MintKind {
    /// Cashu mint (`kind: 38172`).
    Cashu,
    /// Fedimint (`kind: 38173`).
    Fedimint,
}

impl MintKind {
    /// The announcement event kind.
    #[must_use]
    pub const fn kind(self) -> Kind {
        match self {
            Self::Cashu => KIND_CASHU_MINT,
            Self::Fedimint => KIND_FEDIMINT,
        }
    }
}

/// Typed bundle for a `kind: 38172` / `kind: 38173` mint announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintAnnouncement {
    /// Which mint flavour this announcement describes.
    pub mint_kind: MintKind,
    /// Identifier (`d` tag): the mint pubkey for Cashu, the
    /// federation id for Fedimint.
    pub identifier: String,
    /// Connection hints (`u` tags): the mint URL for Cashu, invite
    /// codes for Fedimint.
    pub connections: Vec<String>,
    /// Supported capabilities: NUT numbers for Cashu (`nuts` tag),
    /// module names for Fedimint (`modules` tag). Comma-separated on
    /// the wire.
    pub capabilities: Vec<String>,
    /// Network the mint operates on (`n` tag).
    pub network: Option<MintNetwork>,
    /// Optional `kind: 0`-style metadata JSON mirrored from `.content`.
    pub metadata: String,
}

/// Errors raised while parsing NIP-87 events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MintError {
    /// Event kind is none of `38172` / `38173` / `38000`.
    #[error("unexpected kind for NIP-87: {}", .0.as_u16())]
    WrongKind(Kind),
    /// The required `d` tag is missing.
    #[error("NIP-87 event missing required `d` tag")]
    MissingIdentifier,
    /// An announcement has no `u` connection hint.
    #[error("NIP-87 announcement missing required `u` tag")]
    MissingConnection,
}

impl MintAnnouncement {
    /// Construct an announcement.
    ///
    /// # Errors
    ///
    /// Returns [`MintError::MissingConnection`] when `connections` is
    /// empty.
    pub fn new(
        mint_kind: MintKind,
        identifier: impl Into<String>,
        connections: Vec<String>,
    ) -> Result<Self, MintError> {
        if connections.is_empty() {
            return Err(MintError::MissingConnection);
        }
        Ok(Self {
            mint_kind,
            identifier: identifier.into(),
            connections,
            capabilities: Vec::new(),
            network: None,
            metadata: String::new(),
        })
    }

    /// Wire name of the capability tag for this mint flavour.
    const fn capability_tag(&self) -> &'static str {
        match self.mint_kind {
            MintKind::Cashu => NUTS_TAG,
            MintKind::Fedimint => MODULES_TAG,
        }
    }

    /// Parse a `kind: 38172` / `kind: 38173` announcement event.
    ///
    /// # Errors
    ///
    /// See [`MintError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, MintError> {
        let mint_kind = match event.kind {
            KIND_CASHU_MINT => MintKind::Cashu,
            KIND_FEDIMINT => MintKind::Fedimint,
            other => return Err(MintError::WrongKind(other)),
        };
        let identifier = event
            .tags
            .identifier()
            .ok_or(MintError::MissingIdentifier)?
            .to_owned();
        let connections: Vec<String> = event
            .tags
            .iter()
            .filter(|tag| tag.name() == "u")
            .filter_map(|tag| tag.content().map(str::to_owned))
            .collect();
        if connections.is_empty() {
            return Err(MintError::MissingConnection);
        }
        let capability_tag = match mint_kind {
            MintKind::Cashu => NUTS_TAG,
            MintKind::Fedimint => MODULES_TAG,
        };
        let capabilities = event
            .tags
            .find_first(&TagKind::custom(capability_tag))
            .and_then(Tag::content)
            .map(|raw| raw.split(',').map(|s| s.trim().to_owned()).collect())
            .unwrap_or_default();
        let network = event
            .tags
            .find_first(&TagKind::from_wire("n"))
            .and_then(Tag::content)
            .map(MintNetwork::parse);
        Ok(Self {
            mint_kind,
            identifier,
            connections,
            capabilities,
            network,
            metadata: event.content.clone(),
        })
    }
}

/// A recommendation target: the announcement coordinate, relay
/// hint, and optional mint-type label (`a` tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendedMint {
    /// Coordinate of the `kind: 38172` / `kind: 38173` announcement.
    pub coordinate: Coordinate,
    /// Relay where the announcement can be found.
    pub relay_hint: Option<RelayUrl>,
    /// Optional mint-type label (e.g. `"cashu"` / `"fedimint"`).
    pub mint_type: Option<String>,
}

/// Typed bundle for a `kind: 38000` mint recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRecommendation {
    /// Identifier of the recommended announcement (`d` tag).
    pub identifier: String,
    /// Announcement kind being recommended (`k` tag).
    pub recommended_kind: Kind,
    /// Connection hints (`u` tags): the value plus an optional
    /// mint-type label (e.g. `"cashu"` / `"fedimint"`).
    pub connections: Vec<(String, Option<String>)>,
    /// Pointers to announcement events (`a` tags).
    pub mints: Vec<RecommendedMint>,
    /// Free-form review mirrored from `.content`.
    pub review: String,
}

impl MintRecommendation {
    /// Construct a recommendation for the announcement identified by
    /// `identifier` and `mint_kind`.
    #[must_use]
    pub fn new(mint_kind: MintKind, identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            recommended_kind: mint_kind.kind(),
            connections: Vec::new(),
            mints: Vec::new(),
            review: String::new(),
        }
    }

    /// Parse a `kind: 38000` mint-recommendation event.
    ///
    /// # Errors
    ///
    /// See [`MintError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, MintError> {
        if event.kind != KIND_MINT_RECOMMENDATION {
            return Err(MintError::WrongKind(event.kind));
        }
        let identifier = event
            .tags
            .identifier()
            .ok_or(MintError::MissingIdentifier)?
            .to_owned();
        let recommended_kind = event
            .tags
            .find_first(&TagKind::from_wire("k"))
            .and_then(Tag::content)
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(KIND_CASHU_MINT);
        let connections = event
            .tags
            .iter()
            .filter(|tag| tag.name() == "u")
            .filter_map(|tag| {
                let value = tag.content()?.to_owned();
                let mint_type = tag.get(2).map(str::to_owned);
                Some((value, mint_type))
            })
            .collect();
        let mints = event
            .tags
            .iter()
            .filter(|tag| tag.name() == "a")
            .filter_map(|tag| {
                let coordinate = Coordinate::parse(tag.content()?).ok()?;
                let relay_hint = tag.get(2).and_then(|raw| RelayUrl::parse(raw).ok());
                let mint_type = tag.get(3).map(str::to_owned);
                Some(RecommendedMint {
                    coordinate,
                    relay_hint,
                    mint_type,
                })
            })
            .collect();
        Ok(Self {
            identifier,
            recommended_kind,
            connections,
            mints,
            review: event.content.clone(),
        })
    }
}

impl EventBuilder {
    /// Author a NIP-87 mint announcement (`kind: 38172` / `38173`).
    #[must_use]
    pub fn mint_announcement(announcement: &MintAnnouncement) -> Self {
        let mut builder = Self::new(announcement.mint_kind.kind(), announcement.metadata.clone())
            .tag(Tag::d(announcement.identifier.clone()));
        let u_head = TagKind::from_wire("u");
        for connection in &announcement.connections {
            builder = builder.tag(Tag::with(&u_head, [connection.clone()]));
        }
        if !announcement.capabilities.is_empty() {
            builder = builder.tag(Tag::with(
                &TagKind::custom(announcement.capability_tag()),
                [announcement.capabilities.join(",")],
            ));
        }
        if let Some(network) = &announcement.network {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire("n"),
                [network.as_str().to_owned()],
            ));
        }
        builder
    }

    /// Author a NIP-87 `kind: 38000` mint recommendation.
    #[must_use]
    pub fn mint_recommendation(recommendation: &MintRecommendation) -> Self {
        let mut builder = Self::new(KIND_MINT_RECOMMENDATION, recommendation.review.clone())
            .tag(Tag::d(recommendation.identifier.clone()))
            .tag(Tag::k(recommendation.recommended_kind));
        let u_head = TagKind::from_wire("u");
        for (connection, mint_type) in &recommendation.connections {
            let mut u_args = vec![connection.clone()];
            if let Some(label) = mint_type {
                u_args.push(label.clone());
            }
            builder = builder.tag(Tag::with(&u_head, u_args));
        }
        for mint in &recommendation.mints {
            let a_head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
            let mut a_args = vec![mint.coordinate.to_wire()];
            if let Some(relay) = &mint.relay_hint {
                a_args.push(relay.as_str().to_owned());
            }
            if let Some(label) = &mint.mint_type {
                a_args.push(label.clone());
            }
            builder = builder.tag(Tag::with(&a_head, a_args));
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::key::PublicKey;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn mint_pubkey() -> PublicKey {
        *keys().public_key()
    }

    #[test]
    fn cashu_announcement_round_trip() {
        let mut announcement = MintAnnouncement::new(
            MintKind::Cashu,
            mint_pubkey().to_hex(),
            vec!["https://cashu.example.com".to_owned()],
        )
        .unwrap();
        announcement.capabilities = vec!["1", "2", "3", "4"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        announcement.network = Some(MintNetwork::Mainnet);
        let event = EventBuilder::mint_announcement(&announcement)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_CASHU_MINT);
        let parsed = MintAnnouncement::from_event(&event).unwrap();
        assert_eq!(parsed, announcement);
    }

    #[test]
    fn fedimint_announcement_round_trip() {
        let mut announcement = MintAnnouncement::new(
            MintKind::Fedimint,
            "fed-id-1",
            vec!["fed11abc".to_owned(), "fed11xyz".to_owned()],
        )
        .unwrap();
        announcement.capabilities = vec!["lightning", "wallet", "mint"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        announcement.network = Some(MintNetwork::Signet);
        let event = EventBuilder::mint_announcement(&announcement)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_FEDIMINT);
        let parsed = MintAnnouncement::from_event(&event).unwrap();
        assert_eq!(parsed, announcement);
    }

    #[test]
    fn unknown_network_round_trips() {
        let network: MintNetwork = "mutinynet".parse().unwrap();
        assert_eq!(network, MintNetwork::Other("mutinynet".to_owned()));
        assert_eq!(network.as_str(), "mutinynet");
    }

    #[test]
    fn recommendation_round_trip() {
        let coordinate =
            Coordinate::parse(format!("38172:{}:mint-d-id", mint_pubkey().to_hex())).unwrap();
        let mut recommendation = MintRecommendation::new(MintKind::Cashu, "mint-d-id");
        recommendation.review = "I trust this mint with my life".to_owned();
        recommendation.connections = vec![
            (
                "https://cashu.example.com".to_owned(),
                Some("cashu".to_owned()),
            ),
            ("fed11abc".to_owned(), Some("fedimint".to_owned())),
        ];
        recommendation.mints = vec![RecommendedMint {
            coordinate,
            relay_hint: Some(RelayUrl::parse("wss://relay1.example/").unwrap()),
            mint_type: Some("cashu".to_owned()),
        }];
        let event = EventBuilder::mint_recommendation(&recommendation)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = MintRecommendation::from_event(&event).unwrap();
        assert_eq!(parsed, recommendation);
        assert_eq!(parsed.recommended_kind, KIND_CASHU_MINT);
    }

    #[test]
    fn recommendation_without_optional_labels_round_trip() {
        let coordinate =
            Coordinate::parse(format!("38172:{}:mint-d-id", mint_pubkey().to_hex())).unwrap();
        let mut recommendation = MintRecommendation::new(MintKind::Cashu, "mint-d-id");
        recommendation.connections = vec![("https://cashu.example.com".to_owned(), None)];
        recommendation.mints = vec![RecommendedMint {
            coordinate,
            relay_hint: None,
            mint_type: None,
        }];
        let event = EventBuilder::mint_recommendation(&recommendation)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = MintRecommendation::from_event(&event).unwrap();
        assert_eq!(parsed, recommendation);
    }

    #[test]
    fn missing_connection_is_rejected() {
        assert!(matches!(
            MintAnnouncement::new(MintKind::Cashu, "id", Vec::new()),
            Err(MintError::MissingConnection)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            MintAnnouncement::from_event(&event),
            Err(MintError::WrongKind(_))
        ));
        assert!(matches!(
            MintRecommendation::from_event(&event),
            Err(MintError::WrongKind(_))
        ));
    }
}
