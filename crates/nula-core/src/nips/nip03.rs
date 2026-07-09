//! [NIP-03] `OpenTimestamps` Attestations for Events.
//!
//! `kind: 1040` carries a base64-encoded [OpenTimestamps] `.ots` proof
//! whose digest is the id of the attested event. The spec pins:
//!
//! - an `e` tag pointing at the attested event (with optional relay
//!   hint), and
//! - a `k` tag mirroring the attested event's kind,
//! - `.content` holding the raw `.ots` file bytes, base64-encoded,
//!   containing at least one Bitcoin attestation.
//!
//! This module ships the typed bundle plus base64 round-trip helpers;
//! actually *verifying* the Bitcoin attestation requires chain access
//! and stays out of scope for a protocol crate.
//!
//! [NIP-03]: https://github.com/nostr-protocol/nips/blob/master/03.md
//! [OpenTimestamps]: https://opentimestamps.org/

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

use crate::event::{Event, EventBuilder, EventId, Kind, Tag};
use crate::types::RelayUrl;

/// `kind: 1040` — `OpenTimestamps` attestation.
pub const KIND_OTS_ATTESTATION: Kind = Kind::OTS_ATTESTATION;

/// Typed bundle for a `kind: 1040` `OpenTimestamps` attestation event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsAttestation {
    /// Id of the attested event (`e` tag).
    pub event_id: EventId,
    /// Optional relay hint carried on the `e` tag.
    pub relay_hint: Option<RelayUrl>,
    /// Kind of the attested event (`k` tag).
    pub attested_kind: Option<Kind>,
    /// Raw `.ots` file bytes (decoded from the base64 `.content`).
    pub proof: Vec<u8>,
}

/// Errors raised while parsing a NIP-03 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OtsError {
    /// Event kind is not `1040`.
    #[error("unexpected kind for NIP-03 attestation: {}", .0.as_u16())]
    WrongKind(Kind),
    /// The required `e` tag is missing or malformed.
    #[error("NIP-03 event missing a valid `e` tag")]
    MissingEventId,
    /// `.content` is not valid base64.
    #[error("NIP-03 content is not valid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    /// `.content` decoded to an empty proof.
    #[error("NIP-03 proof is empty")]
    EmptyProof,
}

impl OtsAttestation {
    /// Construct an attestation for `event_id` from raw `.ots` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OtsError::EmptyProof`] when `proof` is empty.
    pub fn new(event_id: EventId, proof: Vec<u8>) -> Result<Self, OtsError> {
        if proof.is_empty() {
            return Err(OtsError::EmptyProof);
        }
        Ok(Self {
            event_id,
            relay_hint: None,
            attested_kind: None,
            proof,
        })
    }

    /// Attach a relay hint to the `e` tag.
    #[must_use]
    pub fn with_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Attach the attested event's kind (`k` tag).
    #[must_use]
    pub const fn with_attested_kind(mut self, kind: Kind) -> Self {
        self.attested_kind = Some(kind);
        self
    }

    /// Base64-encode the proof exactly as it goes on the wire.
    #[must_use]
    pub fn proof_base64(&self) -> String {
        BASE64.encode(&self.proof)
    }

    /// Parse a `kind: 1040` `OpenTimestamps` attestation event.
    ///
    /// # Errors
    ///
    /// See [`OtsError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, OtsError> {
        if event.kind != KIND_OTS_ATTESTATION {
            return Err(OtsError::WrongKind(event.kind));
        }
        let e_tag = event
            .tags
            .iter()
            .find(|tag| tag.name() == "e")
            .ok_or(OtsError::MissingEventId)?;
        let event_id = e_tag
            .content()
            .and_then(|raw| EventId::parse(raw).ok())
            .ok_or(OtsError::MissingEventId)?;
        let relay_hint = e_tag.get(2).and_then(|raw| RelayUrl::parse(raw).ok());
        let attested_kind = event
            .tags
            .iter()
            .find(|tag| tag.name() == "k")
            .and_then(Tag::content)
            .and_then(|raw| raw.parse::<Kind>().ok());
        let proof = BASE64.decode(event.content.trim())?;
        if proof.is_empty() {
            return Err(OtsError::EmptyProof);
        }
        Ok(Self {
            event_id,
            relay_hint,
            attested_kind,
            proof,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-03 `kind: 1040` `OpenTimestamps` attestation.
    #[must_use]
    pub fn ots_attestation(attestation: &OtsAttestation) -> Self {
        let e_tag = attestation.relay_hint.as_ref().map_or_else(
            || Tag::e(attestation.event_id),
            |relay| Tag::e_with_relay(attestation.event_id, relay),
        );
        let mut builder = Self::new(KIND_OTS_ATTESTATION, attestation.proof_base64()).tag(e_tag);
        if let Some(kind) = attestation.attested_kind {
            builder = builder.tag(Tag::k(kind));
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

    fn target_id() -> EventId {
        EventId::parse("e71c6ea722987debdb60f81f9ea4f604b5ac0664120dd64fb9d23abc4ec7c323").unwrap()
    }

    #[test]
    fn round_trip() {
        let att = OtsAttestation::new(target_id(), vec![0x00, 0x4f, 0x54, 0x53])
            .unwrap()
            .with_relay_hint(RelayUrl::parse("wss://relay.example/").unwrap())
            .with_attested_kind(Kind::TEXT_NOTE);
        let event = EventBuilder::ots_attestation(&att)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = OtsAttestation::from_event(&event).unwrap();
        assert_eq!(parsed, att);
    }

    #[test]
    fn empty_proof_is_rejected() {
        assert!(matches!(
            OtsAttestation::new(target_id(), Vec::new()),
            Err(OtsError::EmptyProof)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            OtsAttestation::from_event(&event),
            Err(OtsError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_e_tag_is_rejected() {
        let event = EventBuilder::new(KIND_OTS_ATTESTATION, BASE64.encode(b"proof"))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            OtsAttestation::from_event(&event),
            Err(OtsError::MissingEventId)
        ));
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let event = EventBuilder::new(KIND_OTS_ATTESTATION, "!!! not base64 !!!")
            .tag(Tag::e(target_id()))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            OtsAttestation::from_event(&event),
            Err(OtsError::InvalidBase64(_))
        ));
    }
}
