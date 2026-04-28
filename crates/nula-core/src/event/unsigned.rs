// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Event before its signature has been attached.
//!
//! [`UnsignedEvent`] is the value handed to a signer (local [`Keys`], NIP-46
//! remote signer, NIP-07 browser extension, …). The cryptographic identifier
//! is computed eagerly so the signer only needs to produce a 64-byte Schnorr
//! signature over `id`.
//!
//! [`Keys`]: crate::Keys

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::compute_event_id;
use super::event::Event;
use super::id::EventId;
use super::kind::Kind;
use super::tag::Tags;
use crate::key::{Keys, PublicKey};
use crate::types::Timestamp;

/// Errors raised when signing an [`UnsignedEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UnsignedEventError {
    /// The signer's public key did not match the event author.
    #[error("signer public key does not match event pubkey")]
    SignerMismatch,
}

/// An event whose `id` has been computed but no signature attached.
///
/// `Display`, `serde` and equality compare every field. Two unsigned events
/// produced from identical inputs are guaranteed to compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnsignedEvent {
    /// SHA-256 of the canonical serialization (NIP-01).
    pub id: EventId,
    /// Author's BIP-340 x-only public key.
    pub pubkey: PublicKey,
    /// Author-supplied creation timestamp.
    pub created_at: Timestamp,
    /// Event kind (NIP-01).
    pub kind: Kind,
    /// Event tags.
    pub tags: Tags,
    /// Event content.
    pub content: String,
}

impl UnsignedEvent {
    /// Build an [`UnsignedEvent`] by computing the [`EventId`] from `pubkey`
    /// and the other fields.
    #[must_use]
    pub fn new(
        pubkey: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: Tags,
        content: impl Into<String>,
    ) -> Self {
        let content = content.into();
        let id = compute_event_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        }
    }

    /// Recompute the [`EventId`] from the current fields and return it.
    ///
    /// Useful when fields were mutated through the public struct API.
    #[must_use]
    pub fn compute_id(&self) -> EventId {
        compute_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )
    }

    /// Sign this event with `keys`.
    ///
    /// The signer's public key must match `self.pubkey`; this protects against
    /// silently mis-signing on behalf of another author.
    ///
    /// # Errors
    ///
    /// Returns [`UnsignedEventError::SignerMismatch`] if the signer's
    /// public key does not match `self.pubkey`.
    pub fn sign_with_keys(self, keys: &Keys) -> Result<Event, UnsignedEventError> {
        if keys.public_key() != &self.pubkey {
            return Err(UnsignedEventError::SignerMismatch);
        }

        // Recompute the id from the current fields rather than trusting the
        // `id` already on the struct: callers can mutate fields between
        // construction and signing.
        let canonical_id = self.compute_id();
        let signature = keys.sign_schnorr(&canonical_id.to_byte_array());

        Ok(Event::from_parts(
            canonical_id,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
            signature,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn new_computes_id() {
        let keys = fixture_keys();
        let unsigned = UnsignedEvent::new(
            *keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "hello",
        );
        assert_eq!(unsigned.id, unsigned.compute_id());
    }

    #[test]
    fn sign_with_keys_produces_event() {
        let keys = fixture_keys();
        let unsigned = UnsignedEvent::new(
            *keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "hello",
        );
        let event = unsigned.clone().sign_with_keys(&keys).unwrap();
        assert_eq!(event.id, unsigned.id);
        assert_eq!(event.pubkey, unsigned.pubkey);
        assert_eq!(event.content, unsigned.content);
        event.verify().unwrap();
    }

    #[test]
    fn sign_with_keys_rejects_mismatch() {
        let alice = fixture_keys();
        let bob = Keys::parse("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap();
        let unsigned = UnsignedEvent::new(
            *alice.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "hello",
        );
        let err = unsigned.sign_with_keys(&bob).unwrap_err();
        assert_eq!(err, UnsignedEventError::SignerMismatch);
    }

    #[test]
    fn serde_round_trip() {
        let keys = fixture_keys();
        let unsigned = UnsignedEvent::new(
            *keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TEXT_NOTE,
            Tags::new(),
            "hi",
        );
        let json = serde_json::to_string(&unsigned).unwrap();
        let parsed: UnsignedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, unsigned);
    }
}
