//! [NIP-57] Lightning Zaps.
//!
//! Two events stitch Lightning payments to Nostr identities:
//!
//! - **Zap request** (`kind: 9734`) — built and signed by the
//!   payer, *never published to relays*; instead URL-encoded into
//!   the `nostr=…` query parameter of the recipient's LNURL-pay
//!   callback (Appendix B).
//! - **Zap receipt** (`kind: 9735`) — emitted by the recipient's
//!   LNURL provider once the BOLT-11 invoice it minted in response
//!   has been settled (Appendix E). Receipts carry the BOLT-11
//!   string, the JSON-encoded zap request, and the optional
//!   payment preimage.
//!
//! NIP-57 also defines a `zap` *tag* (Appendix G) that lets a
//! regular event split incoming zaps across multiple recipients,
//! each with an optional weight.
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships only a free-form
//! `EventBuilder::zap_request` taking a [`Vec<Tag>`]. We instead
//! model:
//!
//! - [`ZapRequest`] / [`ZapReceipt`] — typed bundles with the full
//!   set of MUST / MAY tags from spec §"Appendix A" / §"Appendix
//!   E";
//! - [`ZapRequest::validate`] — the intra-event MUST/SHOULD checks
//!   from §"Appendix D" (single `p`, ≤ 1 `e`, ≤ 1 `P`, optional
//!   `amount` consistency);
//! - [`ZapReceipt::description_request`] — parse the
//!   `description` tag (which spec §"Appendix E" mandates be the
//!   JSON-encoded zap request) back into a [`ZapRequest`] so
//!   clients can cross-check Appendix F invariants;
//! - [`ZapSplitTarget`] / [`ZapSplitTarget::to_tag`] /
//!   [`parse_zap_split_targets`] — the `zap` tag (Appendix G)
//!   surfaced as a typed value with weight handling.
//!
//! [NIP-57]: https://github.com/nostr-protocol/nips/blob/master/57.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};
use crate::util::JsonUtil;

/// `kind: 9734` — zap request (sent to LNURL callback, never
/// published to relays).
pub const KIND_ZAP_REQUEST: Kind = Kind::ZAP_REQUEST;
/// `kind: 9735` — zap receipt (emitted by the LNURL provider).
pub const KIND_ZAP_RECEIPT: Kind = Kind::ZAP_RECEIPT;

/// Tag head names used by NIP-57 (string constants kept here so a
/// caller can reuse them without re-typing the literal).
pub mod tag_names {
    /// `relays` tag — multi-value list of relay URLs.
    pub const RELAYS: &str = "relays";
    /// `amount` tag — millisats as a decimal string.
    pub const AMOUNT: &str = "amount";
    /// `lnurl` tag — bech32-encoded LNURL.
    pub const LNURL: &str = "lnurl";
    /// `bolt11` tag — settled BOLT-11 invoice on a receipt.
    pub const BOLT11: &str = "bolt11";
    /// `description` tag — JSON-encoded zap request on a receipt.
    pub const DESCRIPTION: &str = "description";
    /// `preimage` tag — optional payment preimage on a receipt.
    pub const PREIMAGE: &str = "preimage";
    /// `zap` tag — split-zap target on a regular event.
    pub const ZAP: &str = "zap";
}

/// Typed bundle for a `kind: 9734` zap request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapRequest {
    /// `p` — recipient pubkey (MUST).
    pub recipient: PublicKey,
    /// `relays` — relays the LNURL provider SHOULD publish the
    /// receipt to (MUST).
    pub relays: Vec<RelayUrl>,
    /// `amount` — millisats the payer intends to pay (MAY).
    pub amount_msats: Option<u64>,
    /// `lnurl` — bech32-encoded LNURL of the recipient (MAY).
    pub lnurl: Option<String>,
    /// `e` — event being zapped (MAY).
    pub event_target: Option<EventId>,
    /// `a` — addressable event coordinate being zapped (MAY).
    pub address_target: Option<Coordinate>,
    /// `k` — kind of the zapped event (MAY).
    pub kind_target: Option<Kind>,
    /// Free-form payer message — surfaces as `event.content`.
    pub message: String,
}

impl ZapRequest {
    /// Construct a minimal zap-request bundle. The `relays` list
    /// is required by spec §"Appendix A"; pass at least one URL.
    #[must_use]
    pub const fn new(recipient: PublicKey, relays: Vec<RelayUrl>) -> Self {
        Self {
            recipient,
            relays,
            amount_msats: None,
            lnurl: None,
            event_target: None,
            address_target: None,
            kind_target: None,
            message: String::new(),
        }
    }

    /// Set [`Self::amount_msats`].
    #[must_use]
    pub const fn amount_msats(mut self, amount: u64) -> Self {
        self.amount_msats = Some(amount);
        self
    }

    /// Set [`Self::lnurl`].
    #[must_use]
    pub fn lnurl(mut self, lnurl: impl Into<String>) -> Self {
        self.lnurl = Some(lnurl.into());
        self
    }

    /// Set [`Self::event_target`].
    #[must_use]
    pub const fn event_target(mut self, id: EventId) -> Self {
        self.event_target = Some(id);
        self
    }

    /// Set [`Self::address_target`].
    #[must_use]
    pub fn address_target(mut self, coord: Coordinate) -> Self {
        self.address_target = Some(coord);
        self
    }

    /// Set [`Self::kind_target`].
    #[must_use]
    pub const fn kind_target(mut self, kind: Kind) -> Self {
        self.kind_target = Some(kind);
        self
    }

    /// Set [`Self::message`].
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Render to the tag list of a `kind: 9734` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(7);
        if !self.relays.is_empty() {
            let mut values: Vec<String> = Vec::with_capacity(self.relays.len());
            for r in &self.relays {
                values.push(r.as_str().to_owned());
            }
            tags.push(custom_tag(tag_names::RELAYS, values));
        }
        if let Some(amount) = self.amount_msats {
            tags.push(custom_tag(tag_names::AMOUNT, [amount.to_string()]));
        }
        if let Some(lnurl) = &self.lnurl {
            tags.push(custom_tag(tag_names::LNURL, [lnurl.clone()]));
        }
        tags.push(letter_tag(Alphabet::P, [self.recipient.to_hex()]));
        if let Some(id) = self.event_target {
            tags.push(letter_tag(Alphabet::E, [id.to_hex()]));
        }
        if let Some(coord) = &self.address_target {
            tags.push(letter_tag(Alphabet::A, [coord.to_wire()]));
        }
        if let Some(k) = self.kind_target {
            tags.push(letter_tag(Alphabet::K, [k.as_u16().to_string()]));
        }
        tags
    }

    /// Parse a `kind: 9734` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ZapError::WrongKind`] for unrelated kinds.
    /// - [`ZapError::MissingRecipient`] when no `p` tag is present.
    /// - Forwarded parse errors for malformed values.
    pub fn from_event(event: &Event) -> Result<Self, ZapError> {
        if event.kind != KIND_ZAP_REQUEST {
            return Err(ZapError::WrongKind(event.kind));
        }
        Self::from_tags_and_content(&event.tags, &event.content)
    }

    fn from_tags_and_content(tags: &Tags, content: &str) -> Result<Self, ZapError> {
        let mut recipient: Option<PublicKey> = None;
        let mut relays: Vec<RelayUrl> = Vec::new();
        let mut amount_msats: Option<u64> = None;
        let mut lnurl: Option<String> = None;
        let mut event_target: Option<EventId> = None;
        let mut address_target: Option<Coordinate> = None;
        let mut kind_target: Option<Kind> = None;

        for tag in tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(ZapError::MalformedRecipient)?;
                    recipient = Some(PublicKey::parse(pk_hex).map_err(ZapError::InvalidPublicKey)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    let id_hex = tag.get(1).ok_or(ZapError::MalformedEventTarget)?;
                    event_target = Some(EventId::parse(id_hex).map_err(ZapError::InvalidEventId)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    let coord_str = tag.get(1).ok_or(ZapError::MalformedAddressTarget)?;
                    address_target =
                        Some(Coordinate::parse(coord_str).map_err(ZapError::InvalidCoordinate)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::K => {
                    parse_kind_tag(tag, &mut kind_target)?;
                }
                _ if tag.name() == tag_names::RELAYS => {
                    parse_relays_tag(tag, &mut relays)?;
                }
                _ if tag.name() == tag_names::AMOUNT => {
                    parse_amount_tag(tag, &mut amount_msats)?;
                }
                _ if tag.name() == tag_names::LNURL => {
                    lnurl = tag.get(1).map(str::to_owned);
                }
                _ => {}
            }
        }

        let recipient = recipient.ok_or(ZapError::MissingRecipient)?;
        Ok(Self {
            recipient,
            relays,
            amount_msats,
            lnurl,
            event_target,
            address_target,
            kind_target,
            message: content.to_owned(),
        })
    }

    /// Validate the intra-event invariants from spec §"Appendix D":
    ///
    /// 2. event has tags;
    /// 3. exactly one `p` tag (already enforced by [`Self::recipient`]);
    /// 4. zero or one `e` tags (the bundle stores `Option<EventId>`,
    ///    so duplicate `e` tags would have surfaced as the *last*
    ///    one when parsing — this method recounts to make sure the
    ///    raw event was conformant).
    /// 8. zero or one `P` tags (NB: this is the *uppercase* tag
    ///    used on the receipt; not validated here because the
    ///    request must not carry it).
    ///
    /// `expected_amount_msats` lets the LNURL server enforce check
    /// 6 (`amount` query parameter equality) when one was sent.
    ///
    /// # Errors
    ///
    /// One of the [`ZapValidationError`] variants.
    pub fn validate(
        &self,
        raw_tags: &Tags,
        expected_amount_msats: Option<u64>,
    ) -> Result<(), ZapValidationError> {
        if raw_tags.iter().count() == 0 {
            return Err(ZapValidationError::MissingTags);
        }
        let p_count = count_lowercase_letter(raw_tags, Alphabet::P);
        if p_count != 1 {
            return Err(ZapValidationError::WrongPCount(p_count));
        }
        let e_count = count_lowercase_letter(raw_tags, Alphabet::E);
        if e_count > 1 {
            return Err(ZapValidationError::TooManyECount(e_count));
        }
        if let (Some(expected), Some(actual)) = (expected_amount_msats, self.amount_msats)
            && expected != actual
        {
            return Err(ZapValidationError::AmountMismatch { expected, actual });
        }
        Ok(())
    }
}

/// Typed bundle for a `kind: 9735` zap receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapReceipt {
    /// `p` — zap recipient (MUST).
    pub recipient: PublicKey,
    /// `P` — zap sender (MAY).
    pub sender: Option<PublicKey>,
    /// `e` — event being zapped (MAY, copied from request).
    pub event_target: Option<EventId>,
    /// `a` — addressable event coordinate (MAY, copied).
    pub address_target: Option<Coordinate>,
    /// `k` — kind of the zapped event (MAY).
    pub kind_target: Option<Kind>,
    /// `bolt11` — the description-hash invoice that was paid
    /// (MUST).
    pub bolt11: String,
    /// `description` — JSON-encoded zap request that committed to
    /// the BOLT-11 description hash (MUST).
    pub description: String,
    /// `preimage` — payment preimage (MAY). Not a proof of
    /// payment; spec §"Appendix E" calls it out explicitly.
    pub preimage: Option<String>,
}

impl ZapReceipt {
    /// Construct from the minimum required fields. `bolt11` and
    /// `description` are MUST per spec; build them via the LNURL
    /// server's response and the original zap-request JSON.
    #[must_use]
    pub fn new(
        recipient: PublicKey,
        bolt11: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            recipient,
            sender: None,
            event_target: None,
            address_target: None,
            kind_target: None,
            bolt11: bolt11.into(),
            description: description.into(),
            preimage: None,
        }
    }

    /// Set [`Self::sender`].
    #[must_use]
    pub const fn sender(mut self, sender: PublicKey) -> Self {
        self.sender = Some(sender);
        self
    }

    /// Set [`Self::event_target`].
    #[must_use]
    pub const fn event_target(mut self, id: EventId) -> Self {
        self.event_target = Some(id);
        self
    }

    /// Set [`Self::address_target`].
    #[must_use]
    pub fn address_target(mut self, coord: Coordinate) -> Self {
        self.address_target = Some(coord);
        self
    }

    /// Set [`Self::kind_target`].
    #[must_use]
    pub const fn kind_target(mut self, kind: Kind) -> Self {
        self.kind_target = Some(kind);
        self
    }

    /// Set [`Self::preimage`].
    #[must_use]
    pub fn preimage(mut self, preimage: impl Into<String>) -> Self {
        self.preimage = Some(preimage.into());
        self
    }

    /// Render to the tag list of a `kind: 9735` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(8);
        tags.push(letter_tag(Alphabet::P, [self.recipient.to_hex()]));
        if let Some(sender) = self.sender {
            tags.push(letter_tag_uppercase(Alphabet::P, [sender.to_hex()]));
        }
        if let Some(id) = self.event_target {
            tags.push(letter_tag(Alphabet::E, [id.to_hex()]));
        }
        if let Some(coord) = &self.address_target {
            tags.push(letter_tag(Alphabet::A, [coord.to_wire()]));
        }
        if let Some(k) = self.kind_target {
            tags.push(letter_tag(Alphabet::K, [k.as_u16().to_string()]));
        }
        tags.push(custom_tag(tag_names::BOLT11, [self.bolt11.clone()]));
        tags.push(custom_tag(
            tag_names::DESCRIPTION,
            [self.description.clone()],
        ));
        if let Some(preimage) = &self.preimage {
            tags.push(custom_tag(tag_names::PREIMAGE, [preimage.clone()]));
        }
        tags
    }

    /// Parse a `kind: 9735` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ZapError::WrongKind`] for unrelated kinds.
    /// - [`ZapError::MissingRecipient`] / `MissingBolt11` /
    ///   `MissingDescription` per spec §"Appendix E".
    /// - Forwarded parse errors.
    pub fn from_event(event: &Event) -> Result<Self, ZapError> {
        if event.kind != KIND_ZAP_RECEIPT {
            return Err(ZapError::WrongKind(event.kind));
        }
        let mut recipient: Option<PublicKey> = None;
        let mut sender: Option<PublicKey> = None;
        let mut event_target: Option<EventId> = None;
        let mut address_target: Option<Coordinate> = None;
        let mut kind_target: Option<Kind> = None;
        let mut bolt11: Option<String> = None;
        let mut description: Option<String> = None;
        let mut preimage: Option<String> = None;

        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(ZapError::MalformedRecipient)?;
                    recipient = Some(PublicKey::parse(pk_hex).map_err(ZapError::InvalidPublicKey)?);
                }
                TagKind::SingleLetter(s) if s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(ZapError::MalformedSender)?;
                    sender = Some(PublicKey::parse(pk_hex).map_err(ZapError::InvalidPublicKey)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    let id_hex = tag.get(1).ok_or(ZapError::MalformedEventTarget)?;
                    event_target = Some(EventId::parse(id_hex).map_err(ZapError::InvalidEventId)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    let coord_str = tag.get(1).ok_or(ZapError::MalformedAddressTarget)?;
                    address_target =
                        Some(Coordinate::parse(coord_str).map_err(ZapError::InvalidCoordinate)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::K => {
                    parse_kind_tag(tag, &mut kind_target)?;
                }
                _ if tag.name() == tag_names::BOLT11 => {
                    bolt11 = tag.get(1).map(str::to_owned);
                }
                _ if tag.name() == tag_names::DESCRIPTION => {
                    description = tag.get(1).map(str::to_owned);
                }
                _ if tag.name() == tag_names::PREIMAGE => {
                    preimage = tag.get(1).map(str::to_owned);
                }
                _ => {}
            }
        }

        Ok(Self {
            recipient: recipient.ok_or(ZapError::MissingRecipient)?,
            sender,
            event_target,
            address_target,
            kind_target,
            bolt11: bolt11.ok_or(ZapError::MissingBolt11)?,
            description: description.ok_or(ZapError::MissingDescription)?,
            preimage,
        })
    }

    /// Parse [`Self::description`] as the JSON-encoded zap-request
    /// event that committed to this receipt's BOLT-11 description
    /// hash (spec §"Appendix E" step 1).
    ///
    /// This does *not* verify the embedded event's signature —
    /// callers chasing Appendix F invariants SHOULD run
    /// [`Event::verify`] on the returned event before trusting it.
    ///
    /// # Errors
    ///
    /// - [`ZapError::DescriptionParse`] when the JSON is malformed.
    /// - Forwarded errors from [`ZapRequest::from_event`].
    pub fn description_request(&self) -> Result<(Event, ZapRequest), ZapError> {
        let event: Event =
            Event::from_json(&self.description).map_err(ZapError::DescriptionParse)?;
        let request = ZapRequest::from_event(&event)?;
        Ok((event, request))
    }
}

/// One target inside a split-zap `zap` tag (Appendix G).
///
/// Weights are *generalised percentages*: clients SHOULD sum the
/// weights of every `zap` tag and divide each receiver's share
/// proportionally. If a tag omits the weight, the spec's
/// behaviour depends on whether *any* sibling tag carries one:
///
/// - **None of them carry weights** → split equally.
/// - **Some of them carry weights** → those without one MUST be
///   skipped (`weight = 0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapSplitTarget {
    /// Recipient pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint where the recipient's metadata can be
    /// fetched.
    pub relay: Option<RelayUrl>,
    /// Optional split weight.
    pub weight: Option<u64>,
}

impl ZapSplitTarget {
    /// Construct without a relay hint or weight.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay: None,
            weight: None,
        }
    }

    /// Set the relay hint.
    #[must_use]
    pub fn relay(mut self, relay: RelayUrl) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Set the weight.
    #[must_use]
    pub const fn weight(mut self, weight: u64) -> Self {
        self.weight = Some(weight);
        self
    }

    /// Render to a wire `zap` tag.
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let mut values: Vec<String> = Vec::with_capacity(4);
        values.push(self.pubkey.to_hex());
        match (&self.relay, self.weight) {
            (Some(relay), Some(weight)) => {
                values.push(relay.as_str().to_owned());
                values.push(weight.to_string());
            }
            (Some(relay), None) => {
                values.push(relay.as_str().to_owned());
            }
            (None, Some(weight)) => {
                values.push(String::new()); // empty relay slot
                values.push(weight.to_string());
            }
            (None, None) => {}
        }
        custom_tag(tag_names::ZAP, values)
    }

    /// Parse a wire `zap` tag.
    ///
    /// # Errors
    ///
    /// Forwarded from [`PublicKey::parse`] / [`RelayUrl::parse`].
    pub fn from_tag(tag: &Tag) -> Result<Self, ZapError> {
        if tag.name() != tag_names::ZAP {
            return Err(ZapError::NotZapSplitTag);
        }
        let pk_hex = tag.get(1).ok_or(ZapError::MalformedRecipient)?;
        let pubkey = PublicKey::parse(pk_hex).map_err(ZapError::InvalidPublicKey)?;
        let relay = match tag.get(2) {
            Some(s) if !s.is_empty() => {
                Some(RelayUrl::parse(s).map_err(ZapError::InvalidRelayUrl)?)
            }
            _ => None,
        };
        let weight = match tag.get(3) {
            Some(s) if !s.is_empty() => Some(
                s.parse::<u64>()
                    .map_err(|_| ZapError::InvalidWeight(s.to_owned()))?,
            ),
            _ => None,
        };
        Ok(Self {
            pubkey,
            relay,
            weight,
        })
    }
}

/// Collect every split-zap target announced by an event's `zap`
/// tags (Appendix G).
///
/// # Errors
///
/// Forwarded from [`ZapSplitTarget::from_tag`] for any malformed
/// row.
pub fn parse_zap_split_targets(event: &Event) -> Result<Vec<ZapSplitTarget>, ZapError> {
    let mut out: Vec<ZapSplitTarget> = Vec::new();
    for tag in &event.tags {
        if tag.name() == tag_names::ZAP {
            out.push(ZapSplitTarget::from_tag(tag)?);
        }
    }
    Ok(out)
}

fn parse_kind_tag(tag: &Tag, target: &mut Option<Kind>) -> Result<(), ZapError> {
    let Some(k) = tag.get(1) else { return Ok(()) };
    let parsed = k.parse::<u16>().map_err(|_| ZapError::InvalidKindTag)?;
    *target = Some(Kind::new(parsed));
    Ok(())
}

fn parse_relays_tag(tag: &Tag, relays: &mut Vec<RelayUrl>) -> Result<(), ZapError> {
    for v in tag.values().iter().skip(1) {
        let url = RelayUrl::parse(v).map_err(ZapError::InvalidRelayUrl)?;
        relays.push(url);
    }
    Ok(())
}

fn parse_amount_tag(tag: &Tag, target: &mut Option<u64>) -> Result<(), ZapError> {
    let Some(a) = tag.get(1) else { return Ok(()) };
    let parsed = a
        .parse::<u64>()
        .map_err(|_| ZapError::InvalidAmount(a.to_owned()))?;
    *target = Some(parsed);
    Ok(())
}

fn count_lowercase_letter(tags: &Tags, letter: Alphabet) -> usize {
    tags.iter()
        .filter(|t| {
            matches!(t.kind(), TagKind::SingleLetter(s)
                if !s.uppercase && s.character == letter)
        })
        .count()
}

fn custom_tag<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::from_wire(name), args)
}

fn letter_tag<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(alphabet));
    Tag::with(&head, args)
}

fn letter_tag_uppercase<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::uppercase(alphabet));
    Tag::with(&head, args)
}

/// Errors raised while building or parsing a zap-related event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ZapError {
    /// Wrapping event was not the expected kind.
    #[error("unexpected kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `p` tag absent on a request or receipt.
    #[error("missing recipient `p` tag")]
    MissingRecipient,
    /// `bolt11` tag absent on a receipt.
    #[error("missing `bolt11` tag")]
    MissingBolt11,
    /// `description` tag absent on a receipt.
    #[error("missing `description` tag")]
    MissingDescription,
    /// `p` tag column missing.
    #[error("malformed `p` recipient tag")]
    MalformedRecipient,
    /// `P` tag column missing.
    #[error("malformed `P` sender tag")]
    MalformedSender,
    /// `e` tag column missing.
    #[error("malformed `e` event-target tag")]
    MalformedEventTarget,
    /// `a` tag column missing.
    #[error("malformed `a` address-target tag")]
    MalformedAddressTarget,
    /// `k` value did not parse as `u16`.
    #[error("invalid `k` kind tag")]
    InvalidKindTag,
    /// `amount` value did not parse as `u64`.
    #[error("invalid `amount`: {0}")]
    InvalidAmount(String),
    /// `weight` value did not parse as `u64`.
    #[error("invalid `zap` weight: {0}")]
    InvalidWeight(String),
    /// Pubkey hex did not parse.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// Event id hex did not parse.
    #[error("invalid event id: {0}")]
    InvalidEventId(#[source] EventIdError),
    /// Coordinate string did not parse.
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(#[source] CoordinateError),
    /// Relay URL did not parse.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
    /// `description` JSON did not deserialise.
    #[error("invalid description JSON: {0}")]
    DescriptionParse(#[source] serde_json::Error),
    /// Tag passed to [`ZapSplitTarget::from_tag`] was not a
    /// `zap` tag.
    #[error("not a `zap` split tag")]
    NotZapSplitTag,
}

/// Errors raised by [`ZapRequest::validate`] (NIP-57 Appendix D).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ZapValidationError {
    /// The event had no tags at all (rule 2).
    #[error("zap request has no tags")]
    MissingTags,
    /// `p` tag count was not exactly one (rule 3).
    #[error("zap request must have exactly one `p` tag, found {0}")]
    WrongPCount(usize),
    /// `e` tag count exceeded one (rule 4).
    #[error("zap request must have at most one `e` tag, found {0}")]
    TooManyECount(usize),
    /// `amount` tag did not match the expected query-string value
    /// (rule 6).
    #[error("`amount` tag mismatch: expected {expected}, got {actual}")]
    AmountMismatch {
        /// `amount` query-parameter value.
        expected: u64,
        /// `amount` tag value.
        actual: u64,
    },
}

impl EventBuilder {
    /// Author a NIP-57 zap-request event from a typed bundle.
    #[must_use]
    pub fn zap_request(request: &ZapRequest) -> Self {
        let mut builder = Self::new(KIND_ZAP_REQUEST, request.message.clone());
        for tag in request.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-57 zap-receipt event from a typed bundle.
    #[must_use]
    pub fn zap_receipt(receipt: &ZapReceipt) -> Self {
        let mut builder = Self::new(KIND_ZAP_RECEIPT, "");
        for tag in receipt.to_tags() {
            builder = builder.tag(tag);
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

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    #[test]
    fn zap_request_round_trips_full_bundle() {
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()])
            .amount_msats(21_000)
            .lnurl("lnurl1abcdef")
            .event_target(EventId::from_byte_array([0xee; 32]))
            .kind_target(Kind::TEXT_NOTE)
            .message("Zap!");
        let event = EventBuilder::zap_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_ZAP_REQUEST);
        assert_eq!(event.content, "Zap!");
        let parsed = ZapRequest::from_event(&event).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn zap_request_validate_rejects_missing_p() {
        let event = EventBuilder::new(KIND_ZAP_REQUEST, "")
            .tag(custom_tag(tag_names::RELAYS, [relay().as_str()]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ZapRequest::from_event(&event),
            Err(ZapError::MissingRecipient)
        ));
    }

    #[test]
    fn zap_request_validate_rejects_double_p() {
        // Two `p` tags — must fail rule 3.
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()]);
        let event = EventBuilder::zap_request(&req)
            .tag(letter_tag(Alphabet::P, [keys().public_key().to_hex()]))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapRequest::from_event(&event).unwrap();
        let err = parsed.validate(&event.tags, None).unwrap_err();
        assert!(matches!(err, ZapValidationError::WrongPCount(2)));
    }

    #[test]
    fn zap_request_validate_rejects_double_e() {
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()]);
        let event = EventBuilder::zap_request(&req)
            .tag(letter_tag(
                Alphabet::E,
                [EventId::from_byte_array([1; 32]).to_hex()],
            ))
            .tag(letter_tag(
                Alphabet::E,
                [EventId::from_byte_array([2; 32]).to_hex()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapRequest::from_event(&event).unwrap();
        let err = parsed.validate(&event.tags, None).unwrap_err();
        assert!(matches!(err, ZapValidationError::TooManyECount(2)));
    }

    #[test]
    fn zap_request_validate_amount_mismatch() {
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()]).amount_msats(21_000);
        let event = EventBuilder::zap_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapRequest::from_event(&event).unwrap();
        let err = parsed.validate(&event.tags, Some(42_000)).unwrap_err();
        assert!(matches!(err, ZapValidationError::AmountMismatch { .. }));
    }

    #[test]
    fn zap_receipt_round_trips() {
        let recipient = *other_keys().public_key();
        let sender = *keys().public_key();
        let receipt = ZapReceipt::new(recipient, "lnbc1...invoice", "{\"kind\":9734}")
            .sender(sender)
            .event_target(EventId::from_byte_array([0xab; 32]))
            .kind_target(Kind::TEXT_NOTE)
            .preimage("deadbeef".repeat(8));
        let event = EventBuilder::zap_receipt(&receipt)
            .sign_with_keys(&other_keys())
            .unwrap();
        assert_eq!(event.kind, KIND_ZAP_RECEIPT);
        let parsed = ZapReceipt::from_event(&event).unwrap();
        assert_eq!(parsed, receipt);
    }

    #[test]
    fn zap_receipt_missing_bolt11_is_rejected() {
        let event = EventBuilder::new(KIND_ZAP_RECEIPT, "")
            .tag(letter_tag(Alphabet::P, [keys().public_key().to_hex()]))
            .tag(custom_tag(tag_names::DESCRIPTION, ["{}"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ZapReceipt::from_event(&event),
            Err(ZapError::MissingBolt11)
        ));
    }

    #[test]
    fn description_request_round_trips() {
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()]).message("yo");
        let req_event = EventBuilder::zap_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let description = req_event.try_to_json().unwrap();
        let receipt = ZapReceipt::new(*other_keys().public_key(), "lnbc1...invoice", description);
        let (_event, parsed_req) = receipt.description_request().unwrap();
        assert_eq!(parsed_req, req);
    }

    #[test]
    fn zap_split_tag_round_trips() {
        let target = ZapSplitTarget::new(*other_keys().public_key())
            .relay(relay())
            .weight(2);
        let tag = target.to_tag();
        let parsed = ZapSplitTarget::from_tag(&tag).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn zap_split_tag_round_trips_without_weight() {
        let target = ZapSplitTarget::new(*other_keys().public_key()).relay(relay());
        let tag = target.to_tag();
        let parsed = ZapSplitTarget::from_tag(&tag).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn zap_split_tag_round_trips_minimal() {
        let target = ZapSplitTarget::new(*other_keys().public_key());
        let tag = target.to_tag();
        let parsed = ZapSplitTarget::from_tag(&tag).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn parse_zap_split_targets_picks_only_zap_tags() {
        let a = ZapSplitTarget::new(*keys().public_key()).weight(1);
        let b = ZapSplitTarget::new(*other_keys().public_key()).weight(3);
        let event = EventBuilder::text_note("split me")
            .tag(a.to_tag())
            .tag(b.to_tag())
            .tag(letter_tag(Alphabet::P, [keys().public_key().to_hex()]))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = parse_zap_split_targets(&event).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], a);
        assert_eq!(parsed[1], b);
    }

    #[test]
    fn unknown_method_passes_round_trip_via_kind_target() {
        let req = ZapRequest::new(*other_keys().public_key(), vec![relay()])
            .kind_target(Kind::new(31_337));
        let event = EventBuilder::zap_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapRequest::from_event(&event).unwrap();
        assert_eq!(parsed.kind_target, Some(Kind::new(31_337)));
    }

    #[test]
    fn relays_tag_supports_multiple_values() {
        let req = ZapRequest::new(
            *other_keys().public_key(),
            vec![
                RelayUrl::parse("wss://relay.one/").unwrap(),
                RelayUrl::parse("wss://relay.two/").unwrap(),
            ],
        );
        let event = EventBuilder::zap_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapRequest::from_event(&event).unwrap();
        assert_eq!(parsed.relays.len(), 2);
    }
}
