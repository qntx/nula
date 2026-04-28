// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Cryptographic identity for the Nostr protocol.
//!
//! Nostr uses BIP-340 Schnorr signatures over secp256k1. Each user is
//! identified by a 32-byte x-only public key; events carry a 64-byte Schnorr
//! signature over the SHA-256 of the event's serialized form (NIP-01).
//!
//! This module exposes three primary types:
//!
//! - [`SecretKey`] — a 32-byte secret scalar. Constructed from random bytes
//!   or hex; never serialised to logs in plaintext.
//! - [`PublicKey`] — a 32-byte BIP-340 x-only public key. This is the value
//!   you'll see on the wire as `pubkey` and `p` tags.
//! - [`Keys`] — a keypair convenient for signing.
//!
//! All three implement `serde` as lowercase 64-char hex strings, matching
//! NIP-01.

pub mod keys;
pub mod public_key;
pub mod secret_key;

pub use self::keys::Keys;
pub use self::public_key::{PublicKey, PublicKeyError};
pub use self::secret_key::{SecretKey, SecretKeyError};
