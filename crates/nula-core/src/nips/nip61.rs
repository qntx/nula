//! [NIP-61] Nutzaps — typed event bundles.
//!
//! A Nutzap is a P2PK-locked Cashu token in which the payment itself
//! is the receipt: Alice mints (or swaps) ecash at a mint Bob has
//! whitelisted, P2PK-locks it to the pubkey Bob advertises, and
//! publishes a `kind:9321` event to the relays Bob lists in his
//! `kind:10019` informational event.
//!
//! | Kind   | Role                                      | Replaceable |
//! |--------|-------------------------------------------|-------------|
//! | 10019  | Nutzap informational event                | ✓           |
//! | 9321   | Nutzap (P2PK-locked Cashu proofs)         | —           |
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships nothing for NIP-61. We model:
//!
//! 1. [`NutzapInfo`] — the kind-10019 advert: read relays, accepted
//!    [`NutzapMint`]s (mint URL plus optional supported base units),
//!    and the dedicated P2PK pubkey clients MUST lock proofs to
//!    (which corresponds to the `privkey` slot of the author's
//!    NIP-60 [`crate::nips::nip60::WalletInfo`] — **NOT** the
//!    user's main Nostr identity key).
//! 2. [`Nutzap`] — the kind-9321 event: P2PK-locked
//!    [`crate::nips::nip60::CashuProof`]s, the `unit`, the `u` mint
//!    URL (which MUST match the recipient's whitelist exactly), the
//!    optional target event reference, the optional target kind, and
//!    the recipient `p` tag.
//!
//! Each bundle ships an [`EventBuilder`] integration plus a
//! `from_event` parser.
//!
//! [NIP-61]: https://github.com/nostr-protocol/nips/blob/master/61.md

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventBuilderError, EventId, EventIdError, Kind, SingleLetterTag,
    Tag, TagError, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::nips::nip60::CashuProof;
use crate::types::{RelayUrl, RelayUrlError, Url, UrlError};

/// `kind: 9321` — nutzap event.
pub const KIND_NUTZAP: Kind = Kind::NUTZAP;
/// `kind: 10019` — nutzap informational event.
pub const KIND_NUTZAP_INFO: Kind = Kind::NUTZAP_INFO;

mod tag_names {
    pub(super) const RELAY: &str = "relay";
    pub(super) const MINT: &str = "mint";
    pub(super) const PUBKEY: &str = "pubkey";
    pub(super) const PROOF: &str = "proof";
    pub(super) const UNIT: &str = "unit";
    pub(super) const U: &str = "u";
    pub(super) const K: &str = "k";
}

/// Errors raised by the NIP-61 typed bundles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip61Error {
    /// Event kind did not match the expected NIP-61 kind.
    #[error("expected kind {expected}, got {got}")]
    WrongKind {
        /// Kind the caller asked for.
        expected: Kind,
        /// Kind the event actually carried.
        got: Kind,
    },
    /// `kind:10019` advert had no `mint` rows (recipient cannot
    /// receive a nutzap without listing at least one mint).
    #[error("NIP-61 informational event must list at least one mint")]
    NoMints,
    /// `kind:10019` advert had no `pubkey` row (recipient cannot
    /// receive a nutzap without a P2PK lock target).
    #[error("NIP-61 informational event missing `pubkey` row")]
    MissingPubkey,
    /// `kind:9321` event carried no `proof` tags.
    #[error("NIP-61 nutzap event must carry at least one `proof` tag")]
    NoProofs,
    /// `kind:9321` event carried no `u` mint tag.
    #[error("NIP-61 nutzap event missing `u` mint tag")]
    MissingMintUrl,
    /// `kind:9321` event carried no recipient `p` tag.
    #[error("NIP-61 nutzap event missing recipient `p` tag")]
    MissingRecipient,
    /// JSON serialisation / deserialisation failed inside a `proof`
    /// tag.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A relay URL was malformed.
    #[error(transparent)]
    RelayUrl(#[from] RelayUrlError),
    /// A mint URL was malformed.
    #[error(transparent)]
    Url(#[from] UrlError),
    /// A `pubkey`, `p`, or sender pubkey was malformed.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// A target event id was malformed.
    #[error(transparent)]
    EventId(#[from] EventIdError),
    /// A target kind value was not a valid `u16`.
    #[error("NIP-61 nutzap `k` tag is not a valid kind integer")]
    MalformedKind,
    /// A typed [`Tag`] could not be constructed.
    #[error(transparent)]
    Tag(#[from] TagError),
    /// [`EventBuilder`] signing failed.
    #[error(transparent)]
    Builder(#[from] EventBuilderError),
}


/// One mint entry on a [`NutzapInfo`] advert.
///
/// The `mint` tag's wire form is `["mint", <url>, <unit-1>?, <unit-2>?, ...]`.
/// Both [`NutzapInfo::from_event`] and [`NutzapInfo::to_tags`] preserve the
/// optional unit list verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NutzapMint {
    /// Mint URL the recipient agrees to receive at.
    pub url: Url,
    /// Optional list of base units the mint supports (`sat`, `usd`,
    /// `eur`, …).
    pub units: Vec<String>,
}

impl NutzapMint {
    /// Construct a mint entry with no unit markers.
    #[must_use]
    pub const fn new(url: Url) -> Self {
        Self {
            url,
            units: Vec::new(),
        }
    }

    /// Append a supported base-unit marker.
    #[must_use]
    pub fn unit(mut self, unit: impl Into<String>) -> Self {
        self.units.push(unit.into());
        self
    }
}

/// Typed bundle for the replaceable `kind: 10019` informational
/// event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NutzapInfo {
    /// Relays the recipient reads nutzap events from. Senders SHOULD
    /// publish their `kind:9321` events to these relays.
    pub relays: Vec<RelayUrl>,
    /// Mints the recipient agrees to receive at (≥ 1 per spec).
    pub mints: Vec<NutzapMint>,
    /// P2PK lock target. **MUST** be the dedicated NIP-60 wallet
    /// pubkey, **NOT** the recipient's main Nostr identity key.
    pub pubkey: PublicKey,
}

impl NutzapInfo {
    /// Build an informational advert.
    #[must_use]
    pub const fn new(pubkey: PublicKey, mints: Vec<NutzapMint>, relays: Vec<RelayUrl>) -> Self {
        Self {
            relays,
            mints,
            pubkey,
        }
    }

    /// Render the typed bundle to the public tag list a kind-10019
    /// event MUST carry.
    ///
    /// # Errors
    ///
    /// Returns [`Nip61Error::NoMints`] when [`Self::mints`] is empty.
    pub fn to_tags(&self) -> Result<Vec<Tag>, Nip61Error> {
        if self.mints.is_empty() {
            return Err(Nip61Error::NoMints);
        }
        let mut tags: Vec<Tag> = Vec::with_capacity(self.relays.len() + self.mints.len() + 1);
        for relay in &self.relays {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::RELAY),
                [relay.as_str().to_owned()],
            ));
        }
        for mint in &self.mints {
            let mut row: Vec<String> = Vec::with_capacity(1 + mint.units.len());
            row.push(mint.url.as_str().to_owned());
            for unit in &mint.units {
                row.push(unit.clone());
            }
            tags.push(Tag::with(&TagKind::custom(tag_names::MINT), row));
        }
        tags.push(Tag::with(
            &TagKind::custom(tag_names::PUBKEY),
            [self.pubkey.to_hex()],
        ));
        Ok(tags)
    }

    /// Parse a signed kind-10019 event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip61Error::WrongKind`] when the event's kind is
    /// not `10019`, [`Nip61Error::MissingPubkey`] when no `pubkey`
    /// tag is present, and [`Nip61Error::NoMints`] when no `mint`
    /// tag is present; otherwise forwards every URL / pubkey parse
    /// error.
    pub fn from_event(event: &Event) -> Result<Self, Nip61Error> {
        if event.kind != KIND_NUTZAP_INFO {
            return Err(Nip61Error::WrongKind {
                expected: KIND_NUTZAP_INFO,
                got: event.kind,
            });
        }
        let mut relays: Vec<RelayUrl> = Vec::new();
        let mut mints: Vec<NutzapMint> = Vec::new();
        let mut pubkey: Option<PublicKey> = None;
        for tag in &event.tags {
            let values = tag.values();
            // Skip empty rows defensively (the head is values[0]).
            let Some(first) = values.get(1) else {
                continue;
            };
            match tag.name() {
                tag_names::RELAY => relays.push(RelayUrl::parse(first)?),
                tag_names::MINT => {
                    let url = Url::parse(first)?;
                    let units: Vec<String> = values.iter().skip(2).cloned().collect();
                    mints.push(NutzapMint { url, units });
                }
                tag_names::PUBKEY => pubkey = Some(PublicKey::parse(first)?),
                _ => {}
            }
        }
        let pubkey = pubkey.ok_or(Nip61Error::MissingPubkey)?;
        if mints.is_empty() {
            return Err(Nip61Error::NoMints);
        }
        Ok(Self {
            relays,
            mints,
            pubkey,
        })
    }
}


/// Typed bundle for the `kind: 9321` nutzap event.
///
/// `proofs` MUST be non-empty per spec; the proofs are P2PK-locked
/// to the recipient's [`NutzapInfo::pubkey`] (with the `02` Cashu
/// prefix applied at the mint level — `nula-core` does not perform
/// the actual minting). `mint_url` MUST exactly match one of the
/// URLs the recipient listed in their `kind:10019`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nutzap {
    /// Optional `.content` comment.
    pub comment: String,
    /// One or more P2PK-locked Cashu proofs.
    pub proofs: Vec<CashuProof>,
    /// Base unit (`sat`, `usd`, `eur`, …); spec default is `sat`
    /// when omitted.
    pub unit: Option<String>,
    /// Mint URL the proofs were minted at — MUST match one of the
    /// recipient's `kind:10019` `mint` tags exactly.
    pub mint_url: Url,
    /// Optional event being nutzapped.
    pub target_event: Option<EventId>,
    /// Optional kind of [`Self::target_event`].
    pub target_kind: Option<Kind>,
    /// Recipient's main Nostr identity pubkey (the `p` tag).
    pub recipient: PublicKey,
}

impl Nutzap {
    /// Construct a nutzap with the spec-required columns.
    #[must_use]
    pub const fn new(recipient: PublicKey, mint_url: Url, proofs: Vec<CashuProof>) -> Self {
        Self {
            comment: String::new(),
            proofs,
            unit: None,
            mint_url,
            target_event: None,
            target_kind: None,
            recipient,
        }
    }

    /// Set the optional `.content` comment.
    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Set the optional `unit` tag.
    #[must_use]
    pub fn unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Set the optional target event (`e` tag).
    #[must_use]
    pub const fn target_event(mut self, event: EventId) -> Self {
        self.target_event = Some(event);
        self
    }

    /// Set the optional target kind (`k` tag).
    #[must_use]
    pub const fn target_kind(mut self, kind: Kind) -> Self {
        self.target_kind = Some(kind);
        self
    }

    /// Sum of the proof amounts.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.proofs.iter().map(|p| p.amount).sum()
    }

    /// Render the typed bundle to the public tag list.
    ///
    /// # Errors
    ///
    /// Returns [`Nip61Error::NoProofs`] when [`Self::proofs`] is
    /// empty, or [`Nip61Error::Json`] when serialising any proof
    /// fails (which should not happen for the well-formed
    /// [`CashuProof`] type but is surfaced for completeness).
    pub fn to_tags(&self) -> Result<Vec<Tag>, Nip61Error> {
        if self.proofs.is_empty() {
            return Err(Nip61Error::NoProofs);
        }
        let mut tags: Vec<Tag> = Vec::with_capacity(self.proofs.len() + 5);
        for proof in &self.proofs {
            let json = serde_json::to_string(proof)?;
            tags.push(Tag::with(&TagKind::custom(tag_names::PROOF), [json]));
        }
        if let Some(unit) = &self.unit {
            tags.push(Tag::with(&TagKind::custom(tag_names::UNIT), [unit.clone()]));
        }
        tags.push(Tag::with(
            &TagKind::custom(tag_names::U),
            [self.mint_url.as_str().to_owned()],
        ));
        if let Some(event) = self.target_event {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
                [event.to_hex(), String::new()],
            ));
        }
        if let Some(kind) = self.target_kind {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::K),
                [kind.as_u16().to_string()],
            ));
        }
        tags.push(Tag::with(
            &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
            [self.recipient.to_hex()],
        ));
        Ok(tags)
    }

    /// Parse a signed kind-9321 event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip61Error::WrongKind`] when the event's kind is
    /// not `9321`, [`Nip61Error::NoProofs`] /
    /// [`Nip61Error::MissingMintUrl`] / [`Nip61Error::MissingRecipient`]
    /// when the spec-required columns are absent, and forwards
    /// every parse / JSON error.
    pub fn from_event(event: &Event) -> Result<Self, Nip61Error> {
        if event.kind != KIND_NUTZAP {
            return Err(Nip61Error::WrongKind {
                expected: KIND_NUTZAP,
                got: event.kind,
            });
        }
        let mut proofs: Vec<CashuProof> = Vec::new();
        let mut unit: Option<String> = None;
        let mut mint_url: Option<Url> = None;
        let mut target_event: Option<EventId> = None;
        let mut target_kind: Option<Kind> = None;
        let mut recipient: Option<PublicKey> = None;
        for tag in &event.tags {
            let values = tag.values();
            let Some(first) = values.get(1) else {
                continue;
            };
            match tag.name() {
                tag_names::PROOF => {
                    let proof: CashuProof = serde_json::from_str(first)?;
                    proofs.push(proof);
                }
                tag_names::UNIT => unit = Some(first.clone()),
                tag_names::U => mint_url = Some(Url::parse(first)?),
                "e" => target_event = Some(EventId::parse(first)?),
                tag_names::K => {
                    let raw: u16 = first.parse().map_err(|_| Nip61Error::MalformedKind)?;
                    target_kind = Some(Kind::new(raw));
                }
                "p" => recipient = Some(PublicKey::parse(first)?),
                _ => {}
            }
        }
        if proofs.is_empty() {
            return Err(Nip61Error::NoProofs);
        }
        let mint_url = mint_url.ok_or(Nip61Error::MissingMintUrl)?;
        let recipient = recipient.ok_or(Nip61Error::MissingRecipient)?;
        Ok(Self {
            comment: event.content.clone(),
            proofs,
            unit,
            mint_url,
            target_event,
            target_kind,
            recipient,
        })
    }
}


impl EventBuilder {
    /// Author a NIP-61 informational event (`kind: 10019`) from a
    /// typed [`NutzapInfo`].
    ///
    /// # Errors
    ///
    /// Forwards every error from [`NutzapInfo::to_tags`].
    pub fn nutzap_info(info: &NutzapInfo) -> Result<Self, Nip61Error> {
        let mut builder = Self::new(KIND_NUTZAP_INFO, "");
        for tag in info.to_tags()? {
            builder = builder.tag(tag);
        }
        Ok(builder)
    }

    /// Author a NIP-61 nutzap event (`kind: 9321`) from a typed
    /// [`Nutzap`] bundle.
    ///
    /// # Errors
    ///
    /// Forwards every error from [`Nutzap::to_tags`].
    pub fn nutzap(zap: &Nutzap) -> Result<Self, Nip61Error> {
        let mut builder = Self::new(KIND_NUTZAP, zap.comment.clone());
        for tag in zap.to_tags()? {
            builder = builder.tag(tag);
        }
        Ok(builder)
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

    fn mint_url() -> Url {
        Url::parse("https://stablenut.umint.cash").unwrap()
    }

    fn relay_url() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    fn proof(amount: u64) -> CashuProof {
        CashuProof {
            id: "000a93d6f8a1d2c4".to_owned(),
            amount,
            secret:
                "[\"P2PK\",{\"nonce\":\"deadbeef\",\"data\":\"02eaee8939e3565e48cc62967e2fde9d8e2a4b3ec0081f29eceff5c64ef10ac1ed\"}]"
                    .to_owned(),
            c: "02277c66191736eb72fce9d975d08e3191f8f96afb73ab1eec37e4465683066d3f"
                .to_owned(),
        }
    }

    #[test]
    fn nutzap_info_round_trips_through_event() {
        let info = NutzapInfo::new(
            *other_keys().public_key(),
            vec![NutzapMint::new(mint_url()).unit("sat").unit("usd")],
            vec![relay_url()],
        );
        let event = EventBuilder::nutzap_info(&info)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_NUTZAP_INFO);
        let recovered = NutzapInfo::from_event(&event).unwrap();
        assert_eq!(recovered, info);
    }

    #[test]
    fn nutzap_info_to_tags_rejects_empty_mints() {
        let info = NutzapInfo::new(*other_keys().public_key(), Vec::new(), vec![relay_url()]);
        assert!(matches!(info.to_tags(), Err(Nip61Error::NoMints)));
    }

    #[test]
    fn nutzap_info_from_event_requires_pubkey() {
        let event = EventBuilder::new(KIND_NUTZAP_INFO, "")
            .tag(Tag::with(
                &TagKind::custom(tag_names::MINT),
                [mint_url().as_str().to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            NutzapInfo::from_event(&event),
            Err(Nip61Error::MissingPubkey),
        ));
    }

    #[test]
    fn nutzap_info_from_event_requires_mint() {
        let event = EventBuilder::new(KIND_NUTZAP_INFO, "")
            .tag(Tag::with(
                &TagKind::custom(tag_names::PUBKEY),
                [other_keys().public_key().to_hex()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            NutzapInfo::from_event(&event),
            Err(Nip61Error::NoMints),
        ));
    }

    #[test]
    fn nutzap_info_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("not info")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            NutzapInfo::from_event(&event),
            Err(Nip61Error::WrongKind { .. }),
        ));
    }

    #[test]
    fn nutzap_round_trips_through_event() {
        let zap = Nutzap::new(
            *other_keys().public_key(),
            mint_url(),
            vec![proof(1), proof(2)],
        )
        .comment("Thanks for this great idea.")
        .unit("sat")
        .target_event(EventId::from_byte_array([0xab; 32]))
        .target_kind(Kind::TEXT_NOTE);
        let event = EventBuilder::nutzap(&zap)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_NUTZAP);
        assert_eq!(event.content, "Thanks for this great idea.");
        let recovered = Nutzap::from_event(&event).unwrap();
        assert_eq!(recovered, zap);
        assert_eq!(recovered.amount(), 3);
    }

    #[test]
    fn nutzap_to_tags_rejects_empty_proofs() {
        let zap = Nutzap::new(*other_keys().public_key(), mint_url(), Vec::new());
        assert!(matches!(zap.to_tags(), Err(Nip61Error::NoProofs)));
    }

    #[test]
    fn nutzap_from_event_requires_proofs() {
        let event = EventBuilder::new(KIND_NUTZAP, "")
            .tag(Tag::with(
                &TagKind::custom(tag_names::U),
                [mint_url().as_str().to_owned()],
            ))
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
                [other_keys().public_key().to_hex()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Nutzap::from_event(&event),
            Err(Nip61Error::NoProofs),
        ));
    }

    #[test]
    fn nutzap_from_event_requires_recipient() {
        let event = EventBuilder::new(KIND_NUTZAP, "")
            .tag(Tag::with(
                &TagKind::custom(tag_names::PROOF),
                [serde_json::to_string(&proof(1)).unwrap()],
            ))
            .tag(Tag::with(
                &TagKind::custom(tag_names::U),
                [mint_url().as_str().to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Nutzap::from_event(&event),
            Err(Nip61Error::MissingRecipient),
        ));
    }

    #[test]
    fn nutzap_from_event_requires_mint_url() {
        let event = EventBuilder::new(KIND_NUTZAP, "")
            .tag(Tag::with(
                &TagKind::custom(tag_names::PROOF),
                [serde_json::to_string(&proof(1)).unwrap()],
            ))
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
                [other_keys().public_key().to_hex()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Nutzap::from_event(&event),
            Err(Nip61Error::MissingMintUrl),
        ));
    }

    #[test]
    fn nutzap_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("not a nutzap")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Nutzap::from_event(&event),
            Err(Nip61Error::WrongKind { .. }),
        ));
    }
}
