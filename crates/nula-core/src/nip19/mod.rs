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
use bech32::primitives::decode::CheckedHrpstring;
use thiserror::Error;

pub use self::coordinate::Nip19Coordinate;
pub use self::event::Nip19Event;
pub use self::profile::Nip19Profile;
pub use self::tlv::{Record as TlvRecord, TlvError};
use crate::event::{EventId, EventIdError, Kind};
use crate::key::{PublicKey, PublicKeyError, SecretKey, SecretKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// Error produced when encoding a value to its NIP-19 representation.
#[derive(Debug, Error)]
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
pub enum FromBech32Error {
    /// The string is not valid bech32 with the expected checksum.
    #[error("bech32 decoding failed: {0}")]
    Decode(String),
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
pub trait ToBech32 {
    /// Produce the NIP-19 bech32 string.
    ///
    /// # Errors
    ///
    /// Returns [`ToBech32Error`] if the underlying bech32 encoder rejects
    /// the input or if a TLV value exceeds 255 bytes.
    fn to_bech32(&self) -> Result<String, ToBech32Error>;
}

/// Decode `Self` from its bech32 NIP-19 representation.
pub trait FromBech32: Sized {
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
        let identifier_bytes = self.identifier.as_bytes();
        let author_bytes = self.author.to_byte_array();
        let kind_bytes = u32::from(self.kind.as_u16()).to_be_bytes();

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

fn encode_raw(hrp_value: &'static str, data: &[u8]) -> Result<String, ToBech32Error> {
    let hrp = hrp::hrp_unchecked(hrp_value);
    let encoded = bech32::encode::<Bech32>(hrp, data)?;
    Ok(encoded)
}

fn decode_bech32(s: &str) -> Result<(String, Vec<u8>), FromBech32Error> {
    let parsed = CheckedHrpstring::new::<Bech32>(s).map_err(
        |err: bech32::primitives::decode::CheckedHrpstringError| {
            FromBech32Error::Decode(err.to_string())
        },
    )?;
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

    Ok(Nip19Coordinate {
        identifier: identifier.ok_or(FromBech32Error::MissingTlv { tag: tlv::SPECIAL })?,
        author: author.ok_or(FromBech32Error::MissingTlv { tag: tlv::AUTHOR })?,
        kind: kind.ok_or(FromBech32Error::MissingTlv { tag: tlv::KIND })?,
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
            .author(pk)
            .kind(Kind::TEXT_NOTE)
            .relays([relay("wss://relay.example")]);
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
            let expected =
                "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gppemhxue69uhhytnc9e3k7mf0qyt8wumn8ghj7er2vfshxtnnv9jxkc3wvdhk6tclr7lsh";
            assert_eq!(profile.to_bech32().unwrap(), expected);
            assert_eq!(Nip19Profile::from_bech32(expected).unwrap(), profile);
        }
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
