// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Signed Nostr event.
//!
//! [`Event`] is the canonical on-the-wire representation. Construction always
//! goes through [`super::UnsignedEvent::sign_with_keys`] (or the equivalent
//! signer trait); deserialization preserves the full structure but does not
//! automatically verify the cryptographic invariants — call
//! [`Event::verify`] when ingesting events from an untrusted source.

use core::fmt;

use secp256k1::SECP256K1;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::compute_event_id;
use super::id::EventId;
use super::kind::Kind;
use super::tag::Tags;
use crate::JsonUtil;
use crate::key::PublicKey;
use crate::types::Timestamp;

/// Errors raised when validating an [`Event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EventError {
    /// The event's `id` did not match the SHA-256 of its canonical
    /// serialization.
    #[error("event id does not match the canonical serialization")]
    InvalidId,
    /// The Schnorr signature did not verify against the event's `id` and
    /// `pubkey`.
    #[error("event signature verification failed")]
    InvalidSignature,
}

/// A signed Nostr event (NIP-01).
///
/// Field order matches the JSON the protocol uses on the wire (`id`,
/// `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Event {
    /// SHA-256 of the canonical serialization.
    pub id: EventId,
    /// Author's BIP-340 x-only public key.
    pub pubkey: PublicKey,
    /// Author-supplied creation timestamp.
    pub created_at: Timestamp,
    /// Event kind.
    pub kind: Kind,
    /// Event tags.
    pub tags: Tags,
    /// Event content.
    pub content: String,
    /// 64-byte Schnorr signature.
    pub sig: Signature,
}

impl Event {
    /// Build an [`Event`] directly from each field.
    ///
    /// This is the constructor used by [`super::UnsignedEvent::sign_with_keys`].
    /// External callers should prefer constructing through the unsigned
    /// pipeline so the `id` is always derived from the other fields.
    #[must_use]
    pub const fn from_parts(
        id: EventId,
        pubkey: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: Tags,
        content: String,
        sig: Signature,
    ) -> Self {
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        }
    }

    /// True when the stored `id` matches the SHA-256 of the canonical
    /// serialization.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        let expected = compute_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        expected == self.id
    }

    /// True when the Schnorr signature verifies against `id` and `pubkey`.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        SECP256K1
            .verify_schnorr(&self.sig, self.id.as_bytes(), self.pubkey.as_inner())
            .is_ok()
    }

    /// Verify both the [`EventId`] and the Schnorr signature.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::InvalidId`] when the canonical hash does not
    /// match the stored id, or [`EventError::InvalidSignature`] when the
    /// Schnorr signature is not valid.
    pub fn verify(&self) -> Result<(), EventError> {
        if !self.verify_id() {
            return Err(EventError::InvalidId);
        }
        if !self.verify_signature() {
            return Err(EventError::InvalidSignature);
        }
        Ok(())
    }

    /// True when the event carries the NIP-70 `["-"]` protected marker.
    ///
    /// Convenience wrapper around [`crate::nip70::is_protected`].
    #[must_use]
    pub fn is_protected(&self) -> bool {
        crate::nip70::is_protected(self)
    }

    /// Read the NIP-40 deadline carried by this event, if any.
    ///
    /// Convenience wrapper around [`crate::nip40::parse_expiration`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::nip40::ExpirationError`] if the `expiration` tag
    /// is present but malformed.
    pub fn expiration(&self) -> Result<Option<Timestamp>, crate::nip40::ExpirationError> {
        crate::nip40::parse_expiration(self)
    }

    /// Whether this event's NIP-40 deadline (if any) has passed at `now`.
    ///
    /// Convenience wrapper around [`crate::nip40::is_expired`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::nip40::ExpirationError`] if the `expiration` tag
    /// is malformed.
    pub fn is_expired(&self, now: Timestamp) -> Result<bool, crate::nip40::ExpirationError> {
        crate::nip40::is_expired(self, now)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.try_to_json()
            .map_or(Err(fmt::Error), |json| f.write_str(&json))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tag::Tag;
    use super::super::unsigned::UnsignedEvent;
    use super::*;
    use crate::Keys;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn signed_event(content: &str) -> Event {
        let keys = fixture_keys();
        UnsignedEvent::new(
            *keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::from_vec(vec![Tag::new(["alt", "test"]).unwrap()]),
            content,
        )
        .sign_with_keys(&keys)
        .unwrap()
    }

    #[test]
    fn verify_round_trip() {
        let event = signed_event("hello");
        event.verify().unwrap();
    }

    #[test]
    fn tampered_id_fails_verify() {
        let mut event = signed_event("hello");
        // Mutate the id so the canonical hash no longer matches.
        let mut bytes = event.id.to_byte_array();
        bytes[0] ^= 0xff;
        event.id = EventId::from_byte_array(bytes);
        assert_eq!(event.verify().unwrap_err(), EventError::InvalidId);
    }

    #[test]
    fn tampered_content_fails_verify() {
        let mut event = signed_event("hello");
        event.content.push('!');
        // The id is now stale, so we should fail with InvalidId before the
        // signature check.
        assert_eq!(event.verify().unwrap_err(), EventError::InvalidId);
    }

    #[test]
    fn forged_signature_fails_verify() {
        let mut event = signed_event("hello");
        // Build a valid-shape signature for a different message under the
        // same keys; verification against the original id must reject it.
        let keys = fixture_keys();
        let other_message = [0xaa_u8; 32];
        event.sig = keys.sign_schnorr(&other_message);
        assert_eq!(event.verify().unwrap_err(), EventError::InvalidSignature);
    }

    #[test]
    fn json_round_trip_preserves_signature() {
        let event = signed_event("hello");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""kind":1"#));
        assert!(json.contains(r#""content":"hello""#));
        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
        parsed.verify().unwrap();
    }

    #[test]
    fn inherent_is_protected_matches_free_function() {
        // Bare event: not protected
        let event = signed_event("public");
        assert!(!event.is_protected());

        // Build a protected event via the NIP-70 builder helper.
        let keys = fixture_keys();
        let protected = super::super::EventBuilder::text_note("private")
            .created_at(Timestamp::from_secs(1))
            .protected()
            .sign_with_keys(&keys)
            .unwrap();
        assert!(protected.is_protected());
    }

    #[test]
    fn inherent_expiration_matches_free_function() {
        let keys = fixture_keys();
        let event = super::super::EventBuilder::text_note("with-deadline")
            .created_at(Timestamp::from_secs(1))
            .expiration(Timestamp::from_secs(2_000))
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(
            event.expiration().unwrap(),
            Some(Timestamp::from_secs(2_000))
        );
        assert!(!event.is_expired(Timestamp::from_secs(1_999)).unwrap());
        assert!(event.is_expired(Timestamp::from_secs(2_000)).unwrap());
    }
}
