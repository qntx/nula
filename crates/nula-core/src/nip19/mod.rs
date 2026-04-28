// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-19] bech32 encoding for Nostr entities.
//!
//! NIP-19 covers two families of identifiers:
//!
//! 1. **Plain identifiers** — a single 32-byte payload labelled by its HRP:
//!    `npub` ([`PublicKey`]), `nsec` ([`SecretKey`]), and `note`
//!    ([`EventId`]).
//! 2. **Compound identifiers** — TLV-encoded structures: `nprofile`
//!    ([`Nip19Profile`]), `nevent` ([`Nip19Event`]), and `naddr`
//!    ([`Nip19Coordinate`]).
//!
//! Use the [`ToBech32`] / [`FromBech32`] traits when you want compile-time
//! certainty about the HRP, or [`Nip19Entity`] when you only know that the
//! input is *some* NIP-19 string (for example, a value pasted by an end
//! user).
//!
//! # Wire-format placement
//!
//! Per **NIP-19 §Notes**, bech32-encoded entities are **only** for human
//! display, copy-paste, and QR codes. They MUST NOT appear inside:
//!
//! - the `pubkey` / `id` / `tags` fields of a [`crate::Event`] (NIP-01),
//! - the `ids` / `authors` fields of a [`crate::Filter`],
//! - the `#e` / `#p` filter values, or
//! - NIP-05 JSON responses.
//!
//! These places strictly require the underlying lowercase hex form. The
//! Nip19* types in this module always decode back to those primitive
//! types ([`PublicKey`], [`EventId`], [`crate::event::Coordinate`]) so
//! callers should pass *those* downstream rather than the bech32
//! strings.
//!
//! [NIP-19]: https://github.com/nostr-protocol/nips/blob/master/19.md
//! [`PublicKey`]: crate::PublicKey
//! [`SecretKey`]: crate::SecretKey
//! [`EventId`]: crate::EventId

pub mod coordinate;
pub mod event;
pub mod hrp;
pub mod profile;
pub mod tlv;

use core::str;
use core::str::Utf8Error;

use bech32::Bech32;
use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use thiserror::Error;

pub use self::coordinate::Nip19Coordinate;
pub use self::event::Nip19Event;
pub use self::profile::Nip19Profile;
pub use self::tlv::{Record as TlvRecord, TlvError};
use crate::event::{EventId, EventIdError, Kind};
use crate::key::{PublicKey, PublicKeyError, SecretKey, SecretKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// Maximum accepted length, in characters, of any NIP-19 bech32 string.
///
/// NIP-19 §Notes recommends limiting bech32 strings to 5000 characters; we
/// turn that recommendation into a hard cap so untrusted input cannot
/// trigger pathological allocations during decoding.
pub const MAX_NIP19_LENGTH: usize = 5000;

/// Error produced when encoding a value to its NIP-19 representation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ToBech32Error {
    /// `bech32` rejected the encoding (typically: HRP + data is too long for
    /// the underlying checksum algorithm).
    #[error("bech32 encoding failed: {0}")]
    Encode(#[from] bech32::EncodeError),
    /// A TLV value exceeded its 255-byte cap (relay URL, identifier, …).
    #[error(transparent)]
    Tlv(#[from] TlvError),
}

/// Error produced when decoding a NIP-19 string.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FromBech32Error {
    /// The input exceeded [`MAX_NIP19_LENGTH`].
    #[error("NIP-19 string is too long: {len} characters (max {max})")]
    TooLong {
        /// Length of the rejected input.
        len: usize,
        /// The cap that was exceeded.
        max: usize,
    },
    /// The string is not valid bech32 with the expected checksum.
    #[error("bech32 decoding failed: {0}")]
    Decode(#[from] CheckedHrpstringError),
    /// The HRP is not one of the NIP-19 prefixes.
    #[error("unknown NIP-19 prefix `{0}`")]
    UnknownHrp(String),
    /// The HRP did not match the expected entity type.
    #[error("expected NIP-19 prefix `{expected}`, got `{got}`")]
    UnexpectedHrp {
        /// Expected lowercase HRP.
        expected: &'static str,
        /// Actual lowercase HRP.
        got: String,
    },
    /// A fixed-size payload had the wrong length.
    #[error("expected {expected} bytes of payload, got {got}")]
    InvalidPayloadLength {
        /// Required number of bytes.
        expected: usize,
        /// Number of bytes seen.
        got: usize,
    },
    /// A required TLV record was missing.
    #[error("required TLV record (tag {tag}) is missing")]
    MissingTlv {
        /// Tag of the missing record.
        tag: u8,
    },
    /// A `kind` TLV had the wrong length (must be 4 bytes).
    #[error("kind TLV must be 4 bytes (got {got})")]
    InvalidKindLength {
        /// Number of bytes provided.
        got: usize,
    },
    /// A `kind` TLV held a value that exceeds [`u16::MAX`]; nula's [`Kind`]
    /// only stores 16-bit kinds even though NIP-19 reserves 32 bits.
    #[error("kind value {raw} exceeds the supported 16-bit range")]
    KindOutOfRange {
        /// Raw 32-bit value decoded from the TLV.
        raw: u32,
    },
    /// A relay TLV was not valid UTF-8.
    #[error("relay TLV is not valid UTF-8: {0}")]
    InvalidRelayUtf8(#[from] Utf8Error),
    /// Forwarded TLV decoding error.
    #[error(transparent)]
    Tlv(#[from] TlvError),
    /// Forwarded public-key validation error.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// Forwarded secret-key validation error.
    #[error(transparent)]
    SecretKey(#[from] SecretKeyError),
    /// Forwarded event-id validation error.
    #[error(transparent)]
    EventId(#[from] EventIdError),
    /// Forwarded relay-URL validation error.
    #[error(transparent)]
    RelayUrl(#[from] RelayUrlError),
}

/// Encode `Self` into its bech32 NIP-19 representation.
///
/// This trait is **sealed**: it can only be implemented for types defined
/// in this crate. Downstream crates must not implement it because doing so
/// would break the [NIP-19] HRP / TLV invariants we rely on for
/// round-trip safety. To extend the encoding, contribute to `nula-core`.
///
/// [NIP-19]: https://github.com/nostr-protocol/nips/blob/master/19.md
pub trait ToBech32: sealed::Sealed {
    /// Produce the NIP-19 bech32 string.
    ///
    /// # Errors
    ///
    /// Returns [`ToBech32Error`] if the underlying bech32 encoder rejects
    /// the input or if a TLV value exceeds 255 bytes.
    fn to_bech32(&self) -> Result<String, ToBech32Error>;
}

/// Decode `Self` from its bech32 NIP-19 representation.
///
/// This trait is **sealed** for the same reason as [`ToBech32`]: NIP-19
/// HRPs and TLV layouts are defined by spec and any downstream
/// implementation could violate the round-trip contract.
pub trait FromBech32: sealed::Sealed + Sized {
    /// Parse the given NIP-19 bech32 string.
    ///
    /// # Errors
    ///
    /// Returns [`FromBech32Error`] if the input is not valid bech32, the HRP
    /// is wrong, or any contained payload fails validation.
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error>;
}

/// Discriminated union over every NIP-19 entity.
///
/// Use [`Nip19Entity::from_bech32`] when you need to accept any NIP-19
/// identifier from end-user input. The enum intentionally does **not**
/// derive `Hash`: bundling secret keys with hashable variants would invite
/// accidental side-channels through `HashSet`/`HashMap` use.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Nip19Entity {
    /// `npub`
    PublicKey(PublicKey),
    /// `nsec`
    SecretKey(SecretKey),
    /// `note`
    EventId(EventId),
    /// `nprofile`
    Profile(Nip19Profile),
    /// `nevent`
    Event(Nip19Event),
    /// `naddr`
    Coordinate(Nip19Coordinate),
}

impl ToBech32 for Nip19Entity {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        match self {
            Self::PublicKey(pk) => pk.to_bech32(),
            Self::SecretKey(sk) => sk.to_bech32(),
            Self::EventId(id) => id.to_bech32(),
            Self::Profile(p) => p.to_bech32(),
            Self::Event(e) => e.to_bech32(),
            Self::Coordinate(c) => c.to_bech32(),
        }
    }
}

impl FromBech32 for Nip19Entity {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let (hrp_str, data) = decode_bech32(s)?;
        match hrp_str.as_str() {
            hrp::NPUB => Ok(Self::PublicKey(decode_pubkey(&data)?)),
            hrp::NSEC => Ok(Self::SecretKey(decode_seckey(&data)?)),
            hrp::NOTE => Ok(Self::EventId(decode_event_id(&data)?)),
            hrp::NPROFILE => Ok(Self::Profile(decode_profile(&data)?)),
            hrp::NEVENT => Ok(Self::Event(decode_nevent(&data)?)),
            hrp::NADDR => Ok(Self::Coordinate(decode_naddr(&data)?)),
            _ => Err(FromBech32Error::UnknownHrp(hrp_str)),
        }
    }
}

impl ToBech32 for PublicKey {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        encode_raw(hrp::NPUB, &self.to_byte_array())
    }
}

impl FromBech32 for PublicKey {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NPUB)?;
        decode_pubkey(&data)
    }
}

impl ToBech32 for SecretKey {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        encode_raw(hrp::NSEC, &self.to_byte_array())
    }
}

impl FromBech32 for SecretKey {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NSEC)?;
        decode_seckey(&data)
    }
}

impl ToBech32 for EventId {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        encode_raw(hrp::NOTE, &self.to_byte_array())
    }
}

impl FromBech32 for EventId {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NOTE)?;
        decode_event_id(&data)
    }
}

impl ToBech32 for Nip19Profile {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        let pk_bytes = self.public_key.to_byte_array();

        let mut records: Vec<(u8, &[u8])> = Vec::with_capacity(1 + self.relays.len());
        records.push((tlv::SPECIAL, pk_bytes.as_slice()));
        for relay in &self.relays {
            records.push((tlv::RELAY, relay.as_str().as_bytes()));
        }

        let payload = tlv::encode(records)?;
        encode_raw(hrp::NPROFILE, &payload)
    }
}

impl FromBech32 for Nip19Profile {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NPROFILE)?;
        decode_profile(&data)
    }
}

impl ToBech32 for Nip19Event {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        let id_bytes = self.event_id.to_byte_array();
        let author_bytes = self.author.map(PublicKey::to_byte_array);
        let kind_bytes = self.kind.map(|k| u32::from(k.as_u16()).to_be_bytes());

        let mut records: Vec<(u8, &[u8])> = Vec::with_capacity(1 + self.relays.len() + 2);
        records.push((tlv::SPECIAL, id_bytes.as_slice()));
        for relay in &self.relays {
            records.push((tlv::RELAY, relay.as_str().as_bytes()));
        }
        if let Some(bytes) = author_bytes.as_ref() {
            records.push((tlv::AUTHOR, bytes.as_slice()));
        }
        if let Some(bytes) = kind_bytes.as_ref() {
            records.push((tlv::KIND, bytes.as_slice()));
        }

        let payload = tlv::encode(records)?;
        encode_raw(hrp::NEVENT, &payload)
    }
}

impl FromBech32 for Nip19Event {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NEVENT)?;
        decode_nevent(&data)
    }
}

impl ToBech32 for Nip19Coordinate {
    fn to_bech32(&self) -> Result<String, ToBech32Error> {
        let identifier_bytes = self.coordinate.identifier.as_bytes();
        let author_bytes = self.coordinate.author.to_byte_array();
        let kind_bytes = u32::from(self.coordinate.kind.as_u16()).to_be_bytes();

        let mut records: Vec<(u8, &[u8])> = Vec::with_capacity(3 + self.relays.len());
        records.push((tlv::SPECIAL, identifier_bytes));
        for relay in &self.relays {
            records.push((tlv::RELAY, relay.as_str().as_bytes()));
        }
        records.push((tlv::AUTHOR, author_bytes.as_slice()));
        records.push((tlv::KIND, kind_bytes.as_slice()));

        let payload = tlv::encode(records)?;
        encode_raw(hrp::NADDR, &payload)
    }
}

impl FromBech32 for Nip19Coordinate {
    fn from_bech32(s: &str) -> Result<Self, FromBech32Error> {
        let data = decode_with_hrp(s, hrp::NADDR)?;
        decode_naddr(&data)
    }
}

/// Private module that prevents downstream crates from implementing
/// [`ToBech32`] / [`FromBech32`] for their own types.
mod sealed {
    use super::{
        EventId, Nip19Coordinate, Nip19Entity, Nip19Event, Nip19Profile, PublicKey, SecretKey,
    };

    /// Marker trait that limits the set of `ToBech32` / `FromBech32`
    /// implementors to the types defined in this crate.
    pub trait Sealed {}

    impl Sealed for PublicKey {}
    impl Sealed for SecretKey {}
    impl Sealed for EventId {}
    impl Sealed for Nip19Profile {}
    impl Sealed for Nip19Event {}
    impl Sealed for Nip19Coordinate {}
    impl Sealed for Nip19Entity {}
}

fn encode_raw(hrp_value: &'static str, data: &[u8]) -> Result<String, ToBech32Error> {
    let hrp = hrp::hrp_unchecked(hrp_value);
    let encoded = bech32::encode::<Bech32>(hrp, data)?;
    Ok(encoded)
}

fn decode_bech32(s: &str) -> Result<(String, Vec<u8>), FromBech32Error> {
    // Enforce the NIP-19 §Notes cap before touching the bech32 state machine
    // so adversarial input can never allocate more than ~5 KiB even when the
    // checksum check would otherwise sweep the full string.
    if s.len() > MAX_NIP19_LENGTH {
        return Err(FromBech32Error::TooLong {
            len: s.len(),
            max: MAX_NIP19_LENGTH,
        });
    }
    let parsed = CheckedHrpstring::new::<Bech32>(s)?;
    let hrp_str = parsed.hrp().to_lowercase();
    let data: Vec<u8> = parsed.byte_iter().collect();
    Ok((hrp_str, data))
}

fn decode_with_hrp(s: &str, expected: &'static str) -> Result<Vec<u8>, FromBech32Error> {
    let (hrp_str, data) = decode_bech32(s)?;
    if hrp_str != expected {
        return Err(FromBech32Error::UnexpectedHrp {
            expected,
            got: hrp_str,
        });
    }
    Ok(data)
}

fn decode_pubkey(data: &[u8]) -> Result<PublicKey, FromBech32Error> {
    expect_len(data, 32)?;
    Ok(PublicKey::from_slice(data)?)
}

fn decode_seckey(data: &[u8]) -> Result<SecretKey, FromBech32Error> {
    expect_len(data, 32)?;
    Ok(SecretKey::from_slice(data)?)
}

fn decode_event_id(data: &[u8]) -> Result<EventId, FromBech32Error> {
    expect_len(data, 32)?;
    Ok(EventId::from_slice(data)?)
}

const fn expect_len(data: &[u8], expected: usize) -> Result<(), FromBech32Error> {
    if data.len() != expected {
        return Err(FromBech32Error::InvalidPayloadLength {
            expected,
            got: data.len(),
        });
    }
    Ok(())
}

fn decode_profile(data: &[u8]) -> Result<Nip19Profile, FromBech32Error> {
    let mut public_key: Option<PublicKey> = None;
    let mut relays: Vec<RelayUrl> = Vec::new();

    for record in tlv::iter(data) {
        let record = record?;
        match record.tag {
            tlv::SPECIAL => {
                public_key = Some(decode_pubkey(record.value)?);
            }
            tlv::RELAY => {
                relays.push(parse_relay(record.value)?);
            }
            _ => {} // Forward-compatible: ignore unknown tags.
        }
    }

    let public_key = public_key.ok_or(FromBech32Error::MissingTlv { tag: tlv::SPECIAL })?;
    Ok(Nip19Profile { public_key, relays })
}

fn decode_nevent(data: &[u8]) -> Result<Nip19Event, FromBech32Error> {
    let mut event_id: Option<EventId> = None;
    let mut author: Option<PublicKey> = None;
    let mut kind: Option<Kind> = None;
    let mut relays: Vec<RelayUrl> = Vec::new();

    for record in tlv::iter(data) {
        let record = record?;
        match record.tag {
            tlv::SPECIAL => event_id = Some(decode_event_id(record.value)?),
            tlv::RELAY => relays.push(parse_relay(record.value)?),
            tlv::AUTHOR => author = Some(decode_pubkey(record.value)?),
            tlv::KIND => kind = Some(decode_kind(record.value)?),
            _ => {}
        }
    }

    let event_id = event_id.ok_or(FromBech32Error::MissingTlv { tag: tlv::SPECIAL })?;
    Ok(Nip19Event {
        event_id,
        author,
        kind,
        relays,
    })
}

fn decode_naddr(data: &[u8]) -> Result<Nip19Coordinate, FromBech32Error> {
    let mut identifier: Option<String> = None;
    let mut author: Option<PublicKey> = None;
    let mut kind: Option<Kind> = None;
    let mut relays: Vec<RelayUrl> = Vec::new();

    for record in tlv::iter(data) {
        let record = record?;
        match record.tag {
            tlv::SPECIAL => identifier = Some(str::from_utf8(record.value)?.to_owned()),
            tlv::RELAY => relays.push(parse_relay(record.value)?),
            tlv::AUTHOR => author = Some(decode_pubkey(record.value)?),
            tlv::KIND => kind = Some(decode_kind(record.value)?),
            _ => {}
        }
    }

    let identifier = identifier.ok_or(FromBech32Error::MissingTlv { tag: tlv::SPECIAL })?;
    let author = author.ok_or(FromBech32Error::MissingTlv { tag: tlv::AUTHOR })?;
    let kind = kind.ok_or(FromBech32Error::MissingTlv { tag: tlv::KIND })?;
    Ok(Nip19Coordinate {
        coordinate: crate::event::Coordinate::new(kind, author, identifier),
        relays,
    })
}

fn decode_kind(value: &[u8]) -> Result<Kind, FromBech32Error> {
    let bytes: [u8; 4] = value
        .try_into()
        .map_err(|_| FromBech32Error::InvalidKindLength { got: value.len() })?;
    let raw = u32::from_be_bytes(bytes);
    let narrowed = u16::try_from(raw).map_err(|_| FromBech32Error::KindOutOfRange { raw })?;
    Ok(Kind::from(narrowed))
}

fn parse_relay(value: &[u8]) -> Result<RelayUrl, FromBech32Error> {
    let s = str::from_utf8(value)?;
    Ok(RelayUrl::parse(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::parse(url).unwrap()
    }

    #[test]
    fn npub_round_trip() {
        let pk = *fixture_keys().public_key();
        let encoded = pk.to_bech32().unwrap();
        assert!(encoded.starts_with("npub1"));
        let parsed = PublicKey::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn nsec_round_trip() {
        let sk = fixture_keys().secret_key().clone();
        let encoded = sk.to_bech32().unwrap();
        assert!(encoded.starts_with("nsec1"));
        let parsed = SecretKey::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, sk);
    }

    #[test]
    fn note_round_trip() {
        let id = EventId::from_byte_array([0xab; 32]);
        let encoded = id.to_bech32().unwrap();
        assert!(encoded.starts_with("note1"));
        let parsed = EventId::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn nprofile_round_trip_with_relays() {
        let pk = *fixture_keys().public_key();
        let profile = Nip19Profile::new(pk, [relay("wss://relay.one"), relay("wss://relay.two")]);
        let encoded = profile.to_bech32().unwrap();
        assert!(encoded.starts_with("nprofile1"));
        let parsed = Nip19Profile::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, profile);
    }

    #[test]
    fn nprofile_round_trip_without_relays() {
        let pk = *fixture_keys().public_key();
        let profile = Nip19Profile::new(pk, []);
        let encoded = profile.to_bech32().unwrap();
        let parsed = Nip19Profile::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, profile);
    }

    #[test]
    fn nevent_round_trip_full() {
        let pk = *fixture_keys().public_key();
        let event = Nip19Event::new(EventId::from_byte_array([0xab; 32]))
            .with_author(pk)
            .with_kind(Kind::TEXT_NOTE)
            .with_relays([relay("wss://relay.example")]);
        let encoded = event.to_bech32().unwrap();
        assert!(encoded.starts_with("nevent1"));
        let parsed = Nip19Event::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn nevent_round_trip_minimal() {
        let event = Nip19Event::new(EventId::from_byte_array([0x01; 32]));
        let encoded = event.to_bech32().unwrap();
        let parsed = Nip19Event::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn naddr_round_trip() {
        let pk = *fixture_keys().public_key();
        let coord = Nip19Coordinate::new(
            "long-form-1",
            pk,
            Kind::from(30_023_u16),
            [relay("wss://relay.example")],
        );
        let encoded = coord.to_bech32().unwrap();
        assert!(encoded.starts_with("naddr1"));
        let parsed = Nip19Coordinate::from_bech32(&encoded).unwrap();
        assert_eq!(parsed, coord);
    }

    #[test]
    fn entity_dispatch_npub() {
        let pk = *fixture_keys().public_key();
        let s = pk.to_bech32().unwrap();
        let parsed = Nip19Entity::from_bech32(&s).unwrap();
        assert_eq!(parsed, Nip19Entity::PublicKey(pk));
    }

    #[test]
    fn entity_dispatch_naddr() {
        let pk = *fixture_keys().public_key();
        let coord = Nip19Coordinate::new("alpha", pk, Kind::from(30_001_u16), []);
        let s = coord.to_bech32().unwrap();
        let parsed = Nip19Entity::from_bech32(&s).unwrap();
        assert_eq!(parsed, Nip19Entity::Coordinate(coord));
    }

    #[test]
    fn entity_round_trip_via_to_bech32() {
        let pk = *fixture_keys().public_key();
        let entity = Nip19Entity::PublicKey(pk);
        let s = entity.to_bech32().unwrap();
        assert_eq!(Nip19Entity::from_bech32(&s).unwrap(), entity);
    }

    #[test]
    fn unexpected_hrp_is_rejected() {
        let pk = *fixture_keys().public_key();
        let s = pk.to_bech32().unwrap();
        let err = SecretKey::from_bech32(&s).unwrap_err();
        assert!(matches!(
            err,
            FromBech32Error::UnexpectedHrp {
                expected: hrp::NSEC,
                ..
            }
        ));
    }

    #[test]
    fn unknown_hrp_is_rejected() {
        // Generate any bech32 string with an unrelated HRP.
        let hrp = bech32::Hrp::parse("xyz").unwrap();
        let bogus = bech32::encode::<Bech32>(hrp, &[0u8; 32]).unwrap();
        let err = Nip19Entity::from_bech32(&bogus).unwrap_err();
        assert!(matches!(err, FromBech32Error::UnknownHrp(s) if s == "xyz"));
    }

    #[test]
    fn malformed_string_is_rejected() {
        let err = Nip19Entity::from_bech32("definitely not bech32").unwrap_err();
        assert!(matches!(err, FromBech32Error::Decode(_)));
    }

    #[test]
    fn missing_required_tlv_is_rejected() {
        // Build an empty TLV payload and wrap it in a valid `nprofile`.
        let payload = tlv::encode([(tlv::RELAY, b"wss://relay.example".as_slice())]).unwrap();
        let encoded = encode_raw(hrp::NPROFILE, &payload).unwrap();
        let err = Nip19Profile::from_bech32(&encoded).unwrap_err();
        assert!(matches!(
            err,
            FromBech32Error::MissingTlv { tag: tlv::SPECIAL }
        ));
    }

    /// Vectors copied verbatim from the [NIP-19 specification].
    ///
    /// [NIP-19 specification]: https://github.com/nostr-protocol/nips/blob/master/19.md
    mod nip19_vectors {
        use super::*;

        #[test]
        fn npub_matches_spec() {
            let pubkey = PublicKey::parse(
                "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
            )
            .unwrap();
            let expected = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
            assert_eq!(pubkey.to_bech32().unwrap(), expected);
            assert_eq!(PublicKey::from_bech32(expected).unwrap(), pubkey);
        }

        #[test]
        fn nsec_matches_spec() {
            let sk = SecretKey::parse(
                "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
            )
            .unwrap();
            let expected = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
            assert_eq!(sk.to_bech32().unwrap(), expected);
            assert_eq!(SecretKey::from_bech32(expected).unwrap(), sk);
        }

        #[test]
        fn nprofile_round_trip_with_canonical_relays() {
            // The historical NIP-19 example uses URLs without a trailing slash
            // (`wss://r.x.com`); modern URL parsers (RFC 3986 + WHATWG) always
            // normalise them to `wss://r.x.com/`. We mirror rust-nostr by
            // testing against the canonical form, which is what every
            // production stack actually emits today.
            let pk = PublicKey::parse(
                "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            )
            .unwrap();
            let profile = Nip19Profile::new(
                pk,
                [
                    RelayUrl::parse("wss://r.x.com/").unwrap(),
                    RelayUrl::parse("wss://djbas.sadkb.com/").unwrap(),
                ],
            );
            let expected = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gppemhxue69uhhytnc9e3k7mf0qyt8wumn8ghj7er2vfshxtnnv9jxkc3wvdhk6tclr7lsh";
            assert_eq!(profile.to_bech32().unwrap(), expected);
            assert_eq!(Nip19Profile::from_bech32(expected).unwrap(), profile);
        }
    }

    /// Cross-implementation fixtures sourced from `3rdparty/nostr-tools` and
    /// real-world clients. These pin our decoder against bytes produced by
    /// other implementations, especially the ones that emit a different
    /// TLV ordering than nula-core does. NIP-19 leaves TLV order
    /// unspecified, so the only invariant the decoder may rely on is the
    /// per-record `(tag, length, value)` shape — never the position.
    mod cross_impl_fixtures {
        use super::*;

        /// `naddr` produced by [habla.news](https://habla.news), pinned in
        /// `3rdparty/nostr-tools/nip19.test.ts`. The relays vector is
        /// empty; this guards the no-relay path.
        #[test]
        fn habla_news_naddr_decodes() {
            let raw = "naddr1qq98yetxv4ex2mnrv4esygrl54h466tz4v0re4pyuavvxqptsejl0vxcmnhfl60z3rth2xkpjspsgqqqw4rsf34vl5";
            let decoded = Nip19Coordinate::from_bech32(raw).unwrap();
            assert_eq!(
                decoded.coordinate.author.to_hex(),
                "7fa56f5d6962ab1e3cd424e758c3002b8665f7b0d8dcee9fe9e288d7751ac194"
            );
            assert_eq!(decoded.coordinate.kind.as_u16(), 30_023);
            assert_eq!(decoded.coordinate.identifier, "references");
            assert!(decoded.relays.is_empty());
        }

        /// `naddr` produced by [go-nostr](https://github.com/nbd-wtf/go-nostr)
        /// with TLV records in a *different* order than nula emits. NIP-19
        /// allows any ordering, so the decoder must not assume position.
        /// Pinned in `3rdparty/nostr-tools/nip19.test.ts`.
        #[test]
        fn go_nostr_naddr_with_alternate_tlv_ordering_decodes() {
            let raw = "naddr1qqrxyctwv9hxzq3q80cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsxpqqqp65wqfwwaehxw309aex2mrp0yhxummnw3ezuetcv9khqmr99ekhjer0d4skjm3wv4uxzmtsd3jjucm0d5q3vamnwvaz7tmwdaehgu3wvfskuctwvyhxxmmd0zfmwx";
            let decoded = Nip19Coordinate::from_bech32(raw).unwrap();
            assert_eq!(
                decoded.coordinate.author.to_hex(),
                "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
            );
            assert_eq!(decoded.coordinate.kind.as_u16(), 30_023);
            assert_eq!(decoded.coordinate.identifier, "banana");
            // Both relays from the fixture must round-trip; check membership
            // because the TLV ordering does not promise relay-list order.
            let relay_strs: Vec<&str> = decoded.relays.iter().map(RelayUrl::as_str).collect();
            assert!(
                relay_strs
                    .iter()
                    .any(|r| r == &"wss://relay.nostr.example.mydomain.example.com/"),
                "missing primary relay; got {relay_strs:?}",
            );
            assert!(
                relay_strs.iter().any(|r| r == &"wss://nostr.banana.com/"),
                "missing secondary relay; got {relay_strs:?}",
            );
        }

        /// `nprofile` in the trivial form pinned in nostr-tools'
        /// `NostrTypeGuard.isNProfile` test. Confirms that npub-only
        /// profiles (no relay TLV) round-trip through our decoder
        /// regardless of where the producer placed the `special` record.
        #[test]
        fn nostr_tools_nprofile_no_relays_decodes() {
            let raw = "nprofile1qqsvc6ulagpn7kwrcwdqgp797xl7usumqa6s3kgcelwq6m75x8fe8yc5usxdg";
            let decoded = Nip19Profile::from_bech32(raw).unwrap();
            assert!(decoded.relays.is_empty());
            // The decoded pubkey must be a valid x-only point; we do not
            // pin its bytes because the test in nostr-tools also leaves
            // them implicit. Round-tripping through to_bech32 would then
            // emit our canonical TLV order, which may differ from this
            // wire form.
            assert_eq!(decoded.public_key.to_byte_array().len(), 32);
        }

        /// `nevent` from nostr-tools' `NostrTypeGuard.isNEvent` test. The
        /// fixture relies on TLV records `(SPECIAL, RELAY, RELAY)`.
        #[test]
        fn nostr_tools_nevent_with_relays_decodes() {
            let raw = "nevent1qqst8cujky046negxgwwm5ynqwn53t8aqjr6afd8g59nfqwxpdhylpcpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mg8arnc9";
            let decoded = Nip19Event::from_bech32(raw).unwrap();
            // The id is 32 bytes; we just confirm shape, mirroring
            // nostr-tools' boolean-returning type guard.
            assert_eq!(decoded.event_id.to_byte_array().len(), 32);
            assert!(!decoded.relays.is_empty(), "fixture carries relay hints");
        }
    }

    #[test]
    fn rejects_input_above_max_length() {
        // Construct a string that is *syntactically* a bech32 candidate
        // (lowercase ascii + a `1` separator) but longer than the cap.
        // The length check must fire before any expensive bech32 work.
        let oversized: String = core::iter::repeat_n('q', MAX_NIP19_LENGTH + 1).collect();
        let err = Nip19Entity::from_bech32(&oversized).unwrap_err();
        assert!(matches!(
            err,
            FromBech32Error::TooLong {
                len,
                max: MAX_NIP19_LENGTH,
            } if len == MAX_NIP19_LENGTH + 1
        ));
    }

    #[test]
    fn accepts_input_at_max_length_boundary() {
        // A npub is 63 characters; padding it up to exactly 5000 with extra
        // garbage data is rejected by the bech32 decoder, but the length
        // check must *not* fire — that decision belongs to the checksum.
        let pk = *fixture_keys().public_key();
        let mut s = pk.to_bech32().unwrap();
        while s.len() < MAX_NIP19_LENGTH {
            s.push('q');
        }
        assert_eq!(s.len(), MAX_NIP19_LENGTH);
        let err = Nip19Entity::from_bech32(&s).unwrap_err();
        // The cap did not fire; the bech32 checksum did instead.
        assert!(!matches!(err, FromBech32Error::TooLong { .. }));
    }

    #[test]
    fn unknown_tlv_tag_is_ignored_for_forward_compat() {
        let pk = *fixture_keys().public_key();
        let pk_bytes = pk.to_byte_array();
        let future_value: &[u8] = b"future";
        let payload =
            tlv::encode([(tlv::SPECIAL, pk_bytes.as_slice()), (250_u8, future_value)]).unwrap();
        let encoded = encode_raw(hrp::NPROFILE, &payload).unwrap();
        let parsed = Nip19Profile::from_bech32(&encoded).unwrap();
        assert_eq!(parsed.public_key, pk);
    }
}
