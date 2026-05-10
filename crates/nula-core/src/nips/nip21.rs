//! [NIP-21] `nostr:` URI scheme.
//!
//! NIP-21 packages every NIP-19 bech32 entity — **except the secret
//! key** — into a URI with the `nostr:` scheme. The secret-key variant
//! (`nsec`) is deliberately refused: embedding a signing key inside a
//! URL is an operational hazard that leaks through browser history,
//! clipboard, referrer headers, search-engine indexers, server access
//! logs, and QR-code readers. The encoder here therefore makes it
//! impossible at compile time to construct a `nostr:nsec…` URI from
//! a [`crate::SecretKey`]: only types that implement the sealed
//! [`ToNostrUri`] trait are accepted, and [`crate::SecretKey`] is
//! intentionally excluded from that trait's implementor list.
//!
//! The reverse direction ([`Nip21::parse`]) rejects any `nostr:nsec…`
//! URI with [`Nip21Error::SecretKeyRefused`].
//!
//! # Spec ↔ source map
//!
//! | NIP-21 string                 | Rust type                     |
//! |-------------------------------|-------------------------------|
//! | `nostr:npub…`                 | [`crate::PublicKey`]          |
//! | `nostr:note…`                 | [`crate::EventId`]            |
//! | `nostr:nprofile…`             | [`Nip19Profile`]              |
//! | `nostr:nevent…`               | [`Nip19Event`]                |
//! | `nostr:naddr…`                | [`Nip19Coordinate`]           |
//! | any of the above (discriminated) | [`Nip21`]                  |
//!
//! # Usage
//!
//! ```
//! use nula_core::PublicKey;
//! use nula_core::nips::nip21::{FromNostrUri, Nip21, ToNostrUri};
//!
//! let pk = PublicKey::parse(
//!     "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4",
//! )
//! .unwrap();
//!
//! let uri = pk.to_nostr_uri().unwrap();
//! assert!(uri.starts_with("nostr:npub"));
//!
//! let round_trip = PublicKey::from_nostr_uri(&uri).unwrap();
//! assert_eq!(round_trip, pk);
//!
//! // The discriminated form is handy when end-user input could be any
//! // NIP-21 shape.
//! let discriminated = Nip21::parse(&uri).unwrap();
//! assert!(matches!(discriminated, Nip21::Pubkey(_)));
//! ```
//!
//! [NIP-21]: https://github.com/nostr-protocol/nips/blob/master/21.md

use thiserror::Error;

use super::nip19::{
    FromBech32, FromBech32Error, Nip19Coordinate, Nip19Entity, Nip19Event, Nip19Profile, ToBech32,
    ToBech32Error,
};
use crate::event::EventId;
use crate::key::PublicKey;

/// The URI scheme defined by NIP-21.
pub const SCHEME: &str = "nostr";

/// The URI scheme including its delimiter, ready to prepend to a bech32
/// body.
pub const SCHEME_PREFIX: &str = "nostr:";

/// Errors raised by the NIP-21 encoder / decoder.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip21Error {
    /// The input did not start with `nostr:` or had an empty body.
    #[error("invalid `nostr:` URI: expected `nostr:<bech32>` with a non-empty body")]
    InvalidUri,
    /// The URI contained a bech32 secret key (`nsec…` or `ncryptsec…`),
    /// which NIP-21 forbids on safety grounds.
    #[error(
        "NIP-21 does not permit secret keys in URIs; pass a public key, profile, or event instead"
    )]
    SecretKeyRefused,
    /// The bech32 body of the URI failed to decode.
    #[error(transparent)]
    Decode(#[from] FromBech32Error),
    /// The NIP-19 encoder refused to re-encode the payload as bech32.
    #[error(transparent)]
    Encode(#[from] ToBech32Error),
}

/// Discriminated union over every NIP-21-expressible entity.
///
/// Use [`Nip21::parse`] when you need to accept any `nostr:` URI from
/// end-user input. The enum mirrors [`Nip19Entity`] with the
/// secret-key variant removed; the bidirectional conversions between
/// the two are provided so callers can fluidly move between bech32 and
/// URI representations without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Nip21 {
    /// `nostr:npub…`.
    Pubkey(PublicKey),
    /// `nostr:note…`.
    EventId(EventId),
    /// `nostr:nprofile…`.
    Profile(Nip19Profile),
    /// `nostr:nevent…`.
    Event(Nip19Event),
    /// `nostr:naddr…`.
    Coordinate(Nip19Coordinate),
}

impl Nip21 {
    /// Parse a `nostr:<bech32>` URI.
    ///
    /// # Errors
    ///
    /// - [`Nip21Error::InvalidUri`] if the input does not start with
    ///   `nostr:` or the body is empty.
    /// - [`Nip21Error::SecretKeyRefused`] if the body decodes as `nsec`
    ///   (or `ncryptsec` under the `nip49` feature).
    /// - [`Nip21Error::Decode`] for any underlying NIP-19 failure.
    pub fn parse(uri: &str) -> Result<Self, Nip21Error> {
        let body = strip_scheme(uri).ok_or(Nip21Error::InvalidUri)?;
        let entity = Nip19Entity::from_bech32(body)?;
        Self::try_from(entity)
    }

    /// Render this entity as its canonical NIP-19 bech32 body (without
    /// the `nostr:` scheme).
    ///
    /// This is an inherent helper rather than a [`ToBech32`] impl
    /// because [`ToBech32`] is sealed for round-trip safety with the
    /// 6-variant [`Nip19Entity`]; adding [`Nip21`] to the sealed set
    /// would break that guarantee.
    ///
    /// # Errors
    ///
    /// Returns [`Nip21Error::Encode`] on any underlying bech32 failure.
    pub fn to_bech32_body(&self) -> Result<String, Nip21Error> {
        let body = match self {
            Self::Pubkey(pk) => pk.to_bech32()?,
            Self::EventId(id) => id.to_bech32()?,
            Self::Profile(p) => p.to_bech32()?,
            Self::Event(e) => e.to_bech32()?,
            Self::Coordinate(c) => c.to_bech32()?,
        };
        Ok(body)
    }

    /// Render this entity as its canonical `nostr:` URI.
    ///
    /// # Errors
    ///
    /// Returns [`Nip21Error::Encode`] if the underlying bech32 encoder
    /// rejects the payload (e.g. a profile with too many relay hints).
    pub fn to_nostr_uri(&self) -> Result<String, Nip21Error> {
        let body = self.to_bech32_body()?;
        Ok(format!("{SCHEME_PREFIX}{body}"))
    }

    /// Return the event id carried by this URI, if any.
    ///
    /// `note` and `nevent` carry event ids directly; every other
    /// variant returns `None`.
    #[must_use]
    pub const fn event_id(&self) -> Option<EventId> {
        match self {
            Self::EventId(id) => Some(*id),
            Self::Event(e) => Some(e.event_id),
            Self::Pubkey(_) | Self::Profile(_) | Self::Coordinate(_) => None,
        }
    }

    /// Return the public key carried by this URI, if any.
    ///
    /// `npub`, `nprofile`, and `naddr` all reference an author; the
    /// other variants identify a particular event on the wire and do
    /// not embed a public key.
    #[must_use]
    pub const fn pubkey(&self) -> Option<PublicKey> {
        match self {
            Self::Pubkey(pk) => Some(*pk),
            Self::Profile(p) => Some(p.public_key),
            Self::Coordinate(c) => Some(*c.author()),
            Self::EventId(_) | Self::Event(_) => None,
        }
    }
}

impl From<Nip21> for Nip19Entity {
    fn from(value: Nip21) -> Self {
        match value {
            Nip21::Pubkey(pk) => Self::PublicKey(pk),
            Nip21::EventId(id) => Self::EventId(id),
            Nip21::Profile(p) => Self::Profile(p),
            Nip21::Event(e) => Self::Event(e),
            Nip21::Coordinate(c) => Self::Coordinate(c),
        }
    }
}

impl TryFrom<Nip19Entity> for Nip21 {
    type Error = Nip21Error;

    fn try_from(value: Nip19Entity) -> Result<Self, Self::Error> {
        match value {
            Nip19Entity::SecretKey(_) => Err(Nip21Error::SecretKeyRefused),
            Nip19Entity::PublicKey(pk) => Ok(Self::Pubkey(pk)),
            Nip19Entity::EventId(id) => Ok(Self::EventId(id)),
            Nip19Entity::Profile(p) => Ok(Self::Profile(p)),
            Nip19Entity::Event(e) => Ok(Self::Event(e)),
            Nip19Entity::Coordinate(c) => Ok(Self::Coordinate(c)),
        }
    }
}

/// Render a value as its `nostr:` URI.
///
/// This trait is **sealed**: only types defined in this crate whose
/// bech32 encoding is a valid NIP-21 body can implement it. The
/// sealing exists for the same reason NIP-19's traits are sealed
/// (round-trip guarantees) **and** to prevent downstream code from
/// accidentally implementing it for [`crate::SecretKey`], which would
/// silently defeat the safety rationale of NIP-21.
pub trait ToNostrUri: sealed::ToSealed {
    /// Produce the `nostr:<bech32>` URI for this value.
    ///
    /// # Errors
    ///
    /// Returns [`Nip21Error::Encode`] if bech32 encoding fails.
    fn to_nostr_uri(&self) -> Result<String, Nip21Error>;
}

/// Parse a value from its `nostr:` URI.
///
/// Sealed for the same reasons as [`ToNostrUri`].
pub trait FromNostrUri: sealed::FromSealed + Sized {
    /// Parse a `nostr:<bech32>` URI whose body matches `Self`.
    ///
    /// # Errors
    ///
    /// - [`Nip21Error::InvalidUri`] for a missing `nostr:` prefix.
    /// - [`Nip21Error::Decode`] for an underlying NIP-19 failure
    ///   (wrong HRP, bad checksum, malformed TLV, …).
    fn from_nostr_uri(uri: &str) -> Result<Self, Nip21Error>;
}

mod sealed {
    use super::{EventId, Nip19Coordinate, Nip19Event, Nip19Profile, Nip21, PublicKey};

    /// Sealed marker for [`super::ToNostrUri`]. Notice that
    /// [`crate::SecretKey`] is **not** a member — that is the point.
    pub trait ToSealed {}
    /// Sealed marker for [`super::FromNostrUri`].
    pub trait FromSealed {}

    impl ToSealed for PublicKey {}
    impl ToSealed for EventId {}
    impl ToSealed for Nip19Profile {}
    impl ToSealed for Nip19Event {}
    impl ToSealed for Nip19Coordinate {}
    impl ToSealed for Nip21 {}
    impl FromSealed for PublicKey {}
    impl FromSealed for EventId {}
    impl FromSealed for Nip19Profile {}
    impl FromSealed for Nip19Event {}
    impl FromSealed for Nip19Coordinate {}
    impl FromSealed for Nip21 {}
}

fn strip_scheme(uri: &str) -> Option<&str> {
    let body = uri.strip_prefix(SCHEME_PREFIX)?;
    if body.is_empty() { None } else { Some(body) }
}

macro_rules! impl_to_nostr_uri_via_bech32 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ToNostrUri for $ty {
                fn to_nostr_uri(&self) -> Result<String, Nip21Error> {
                    let body = ToBech32::to_bech32(self)?;
                    Ok(format!("{SCHEME_PREFIX}{body}"))
                }
            }
        )+
    };
}

macro_rules! impl_from_nostr_uri_via_bech32 {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl FromNostrUri for $ty {
                fn from_nostr_uri(uri: &str) -> Result<Self, Nip21Error> {
                    let body = strip_scheme(uri).ok_or(Nip21Error::InvalidUri)?;
                    Self::from_bech32(body).map_err(Nip21Error::Decode)
                }
            }
        )+
    };
}

impl_to_nostr_uri_via_bech32!(
    PublicKey,
    EventId,
    Nip19Profile,
    Nip19Event,
    Nip19Coordinate
);
impl_from_nostr_uri_via_bech32!(
    PublicKey,
    EventId,
    Nip19Profile,
    Nip19Event,
    Nip19Coordinate
);

impl ToNostrUri for Nip21 {
    fn to_nostr_uri(&self) -> Result<String, Nip21Error> {
        Self::to_nostr_uri(self)
    }
}

impl FromNostrUri for Nip21 {
    fn from_nostr_uri(uri: &str) -> Result<Self, Nip21Error> {
        Self::parse(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventId, Kind};
    use crate::types::RelayUrl;

    const FIXTURE_PUBKEY_HEX: &str =
        "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    const FIXTURE_NPUB_URI: &str =
        "nostr:npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";

    fn fixture_pubkey() -> PublicKey {
        PublicKey::parse(FIXTURE_PUBKEY_HEX).expect("fixture hex parses")
    }

    #[test]
    fn pubkey_round_trip_matches_upstream_fixture() {
        let pk = fixture_pubkey();
        assert_eq!(pk.to_nostr_uri().unwrap(), FIXTURE_NPUB_URI);
        assert_eq!(PublicKey::from_nostr_uri(FIXTURE_NPUB_URI).unwrap(), pk);

        // Discriminated form agrees.
        let parsed = Nip21::parse(FIXTURE_NPUB_URI).unwrap();
        assert_eq!(parsed, Nip21::Pubkey(pk));
        assert_eq!(parsed.pubkey(), Some(pk));
        assert_eq!(parsed.event_id(), None);
        assert_eq!(parsed.to_nostr_uri().unwrap(), FIXTURE_NPUB_URI);
    }

    #[test]
    fn profile_round_trip() {
        let pk = fixture_pubkey();
        let profile = Nip19Profile::new(
            pk,
            [RelayUrl::parse("wss://relay.damus.io/").expect("fixture relay parses")],
        );

        let uri = profile.to_nostr_uri().unwrap();
        assert!(uri.starts_with("nostr:nprofile"));
        let round_trip = Nip19Profile::from_nostr_uri(&uri).unwrap();
        assert_eq!(round_trip, profile);
        assert_eq!(Nip21::parse(&uri).unwrap(), Nip21::Profile(profile));
    }

    #[test]
    fn event_round_trip_preserves_discriminator_accessors() {
        let id = EventId::parse("b2f61aa5ce66cef9f9e3dcbfa9a17b16b6b9d43f7e0a8e2b7c5f1e6f80a7f123")
            .expect("fixture event id parses");
        let nevent = Nip19Event::new(id)
            .with_author(fixture_pubkey())
            .with_kind(Kind::TEXT_NOTE)
            .with_relays([RelayUrl::parse("wss://relay.damus.io/").unwrap()]);

        let uri = nevent.to_nostr_uri().unwrap();
        assert!(uri.starts_with("nostr:nevent"));

        let parsed = Nip21::parse(&uri).unwrap();
        assert_eq!(parsed.event_id(), Some(id));
        assert_eq!(parsed.pubkey(), None);
        assert!(matches!(parsed, Nip21::Event(_)));
    }

    #[test]
    fn secret_key_is_refused_at_parse() {
        // Fixture from upstream rust-nostr (nip21.rs tests).
        let nsec_uri = "nostr:nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
        let err = Nip21::parse(nsec_uri).expect_err("nsec URIs are forbidden");
        assert!(matches!(err, Nip21Error::SecretKeyRefused));
    }

    #[test]
    fn missing_scheme_is_rejected() {
        for bad in [
            "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy",
            "nostr:",
        ] {
            let err = Nip21::parse(bad).expect_err("Nip21::parse accepts only `nostr:<bech32>`");
            assert!(
                matches!(err, Nip21Error::InvalidUri),
                "unexpected error for {bad:?}: {err:?}"
            );
        }

        let trait_err =
            PublicKey::from_nostr_uri("bolt11:lnbc1…").expect_err("foreign scheme is not NIP-21");
        assert!(matches!(trait_err, Nip21Error::InvalidUri));
    }

    #[test]
    fn nip19_entity_bidirectional_conversion() {
        let pk = fixture_pubkey();
        let as_entity: Nip19Entity = Nip21::Pubkey(pk).into();
        assert_eq!(as_entity, Nip19Entity::PublicKey(pk));

        let back = Nip21::try_from(as_entity).unwrap();
        assert_eq!(back, Nip21::Pubkey(pk));

        // Secret keys cannot be laundered through the conversion.
        let sk = crate::SecretKey::parse(
            "0000000000000000000000000000000000000000000000000000000000000003",
        )
        .unwrap();
        let err = Nip21::try_from(Nip19Entity::SecretKey(sk))
            .expect_err("secret keys must not become NIP-21 values");
        assert!(matches!(err, Nip21Error::SecretKeyRefused));
    }
}
