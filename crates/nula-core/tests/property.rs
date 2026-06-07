// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Property-based invariants for `nula-core`.
//!
//! These complement the example-based unit tests and the official
//! NIP-44 vectors with randomised coverage of the round-trip and
//! self-consistency contracts the whole stack relies on. Each property
//! is an invariant that must hold for *every* input, not just the
//! hand-picked cases:
//!
//! - a freshly signed event always self-verifies (id + Schnorr sig),
//! - keys and ids survive a hex / bech32 (NIP-19) round trip byte-for-byte,
//! - NIP-44 `decrypt(encrypt(m)) == m` for any sender/recipient/message.
//!
//! `[u8; 32]` seeds that do not land on a valid secp256k1 scalar are
//! skipped (`return Ok(())`); such seeds are astronomically rare, so the
//! shrinker still explores the valid space thoroughly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "integration tests inherit the crate's full dev-dep set and \
              proptest expands test fns at module scope; test code may also \
              panic for brevity."
)]

use nula_core::event::{EventBuilder, EventId};
use nula_core::key::{Keys, PublicKey, SecretKey};
use nula_core::{FromBech32, ToBech32};
use proptest::prelude::*;

/// Build a [`Keys`] from a random 32-byte seed, skipping the rare seeds
/// that do not encode a valid secp256k1 scalar.
fn keys_from_seed(seed: [u8; 32]) -> Option<Keys> {
    SecretKey::from_byte_array(seed)
        .ok()
        .map(Keys::from_secret_key)
}

proptest! {
    /// Every event produced by the builder + local-keys signer must pass
    /// [`nula_core::Event::verify`] — the canonical id matches the
    /// SHA-256 of the NIP-01 serialization and the Schnorr signature
    /// verifies against (id, pubkey).
    #[test]
    fn signed_event_self_verifies(seed in any::<[u8; 32]>(), content in ".{0,256}") {
        let Some(keys) = keys_from_seed(seed) else { return Ok(()); };
        let event = EventBuilder::text_note(content)
            .sign_with_keys(&keys)
            .expect("local-keys signing is infallible");
        prop_assert!(event.verify().is_ok(), "freshly signed event failed verify()");
    }

    /// A 32-byte event id round-trips through both its 64-char hex form
    /// and its NIP-19 `note1…` bech32 form.
    #[test]
    fn event_id_round_trips(bytes in any::<[u8; 32]>()) {
        let id = EventId::from_byte_array(bytes);

        let hex = id.to_hex();
        prop_assert_eq!(id, EventId::parse(&hex).expect("hex must re-parse"));

        let b32 = id.to_bech32().expect("note bech32 must encode");
        prop_assert_eq!(id, EventId::from_bech32(&b32).expect("note bech32 must decode"));
    }

    /// A public key survives a raw-byte round trip and an `npub` bech32
    /// round trip.
    #[test]
    fn public_key_round_trips(seed in any::<[u8; 32]>()) {
        let Some(keys) = keys_from_seed(seed) else { return Ok(()); };
        let pk: PublicKey = *keys.public_key();

        prop_assert_eq!(
            pk,
            PublicKey::from_byte_array(pk.to_byte_array()).expect("x-only bytes re-parse"),
        );

        let npub = pk.to_bech32().expect("npub must encode");
        prop_assert_eq!(pk, PublicKey::from_bech32(&npub).expect("npub must decode"));
    }

    /// A secret key survives a raw-byte round trip and an `nsec` bech32
    /// round trip (compared by bytes — `SecretKey` does not expose its
    /// scalar except through `to_byte_array`).
    #[test]
    fn secret_key_round_trips(seed in any::<[u8; 32]>()) {
        let Ok(secret) = SecretKey::from_byte_array(seed) else { return Ok(()); };
        let bytes = secret.to_byte_array();

        prop_assert_eq!(
            bytes,
            SecretKey::from_byte_array(bytes).expect("scalar re-parse").to_byte_array(),
        );

        let nsec = secret.to_bech32().expect("nsec must encode");
        let back = SecretKey::from_bech32(&nsec).expect("nsec must decode");
        prop_assert_eq!(bytes, back.to_byte_array());
    }
}

#[cfg(feature = "nip44")]
proptest! {
    /// NIP-44 v2 is a symmetric channel keyed by ECDH: decrypting with
    /// the recipient secret + sender pubkey recovers exactly what was
    /// encrypted with the sender secret + recipient pubkey, for any
    /// non-empty plaintext within the spec bound.
    #[test]
    fn nip44_decrypt_inverts_encrypt(
        sender_seed in any::<[u8; 32]>(),
        recipient_seed in any::<[u8; 32]>(),
        plaintext in ".{1,256}",
    ) {
        use nula_core::nips::nip44;

        let (Ok(sender), Ok(recipient)) = (
            SecretKey::from_byte_array(sender_seed),
            SecretKey::from_byte_array(recipient_seed),
        ) else {
            return Ok(());
        };

        let sender_pub = *Keys::from_secret_key(sender.clone()).public_key();
        let recipient_pub = *Keys::from_secret_key(recipient.clone()).public_key();

        let payload = nip44::encrypt(&sender, &recipient_pub, &plaintext)
            .expect("encrypt of a bounded plaintext must succeed");
        let decrypted = nip44::decrypt(&recipient, &sender_pub, &payload)
            .expect("decrypt with the matching keypair must succeed");

        prop_assert_eq!(plaintext, decrypted, "NIP-44 round trip lost the plaintext");
    }
}
