//! Hard limits enforced by the Nostr protocol primitives.
//!
//! Centralising every spec-mandated byte length, length cap, and
//! tunable cost ceiling in a single namespace makes it easy to:
//!
//! - bound caller-side validation against the same numbers the
//!   parsers and validators use internally;
//! - audit the surface for drift relative to the cited NIPs;
//! - cite the value in user-facing documentation without chasing the
//!   constant down through nested modules.
//!
//! Each entry below is either a re-export of the canonical constant
//! that lives next to its consumer, or a `pub const` defined here when
//! the source value is currently `pub(crate)` / private but still
//! protocol-binding.
//!
//! # Stability
//!
//! Removing a constant from this module is a breaking change. Adding
//! new constants is additive. Renaming requires a deprecation cycle.

/// Length, in bytes, of the SHA-256 event id mandated by NIP-01.
pub use crate::event::id::EVENT_ID_SIZE as EVENT_ID_BYTES;
/// Length, in bytes, of a serialised BIP-340 Schnorr signature.
pub use crate::key::keys::SIGNATURE_SIZE as SIGNATURE_BYTES;
/// Length, in bytes, of an x-only BIP-340 public key.
pub use crate::key::public_key::PUBLIC_KEY_SIZE as PUBLIC_KEY_BYTES;
/// Length, in bytes, of a BIP-340 secret key.
pub use crate::key::secret_key::SECRET_KEY_SIZE as SECRET_KEY_BYTES;
/// Maximum length of a [`crate::message::SubscriptionId`], measured
/// in Unicode scalar values.
pub use crate::message::subscription_id::MAX_LENGTH as SUBSCRIPTION_ID_MAX_CHARS;
/// Maximum length, in characters, of a NIP-19 bech32 string the
/// decoder will accept before rejecting the input outright.
pub use crate::nips::nip19::MAX_NIP19_LENGTH as NIP19_MAX_LENGTH;

/// Smallest plaintext length the NIP-44 v2 encryptor accepts.
///
/// Spec: <https://github.com/nostr-protocol/nips/blob/master/44.md#encryption>.
pub const NIP44_MIN_PLAINTEXT_BYTES: usize = 1;

/// Largest plaintext length the NIP-44 v2 encryptor accepts.
///
/// Spec: <https://github.com/nostr-protocol/nips/blob/master/44.md#encryption>.
pub const NIP44_MAX_PLAINTEXT_BYTES: usize = 65_535;

/// Largest *raw* payload length (header + nonce + ciphertext + MAC)
/// the NIP-44 v2 decoder will accept before base64 encoding.
///
/// Spec: <https://github.com/nostr-protocol/nips/blob/master/44.md#decoding>.
pub const NIP44_MAX_PAYLOAD_BYTES: usize = 65_603;

/// Largest `log_n` (scrypt cost factor) the encoder will accept.
///
/// `log_n = 30` corresponds to ~1 GiB of working memory and many
/// minutes of CPU on commodity hardware — far above any sane
/// production setting. The cap exists to keep accidentally-pathological
/// values from wedging a decryptor.
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub use crate::nips::nip49::MAX_LOG_N as NIP49_MAX_LOG_N;
/// Length, in bytes, of the XChaCha20-Poly1305 nonce embedded in
/// an `ncryptsec`.
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub use crate::nips::nip49::NONCE_BYTES as NIP49_NONCE_BYTES;
/// Length, in bytes, of the scrypt salt embedded in an `ncryptsec`.
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub use crate::nips::nip49::SALT_BYTES as NIP49_SALT_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift detector: every spec value is repeated here so a future
    /// refactor that silently changes a constant (e.g. through a
    /// rebase mishap) trips this test before it reaches a release.
    #[test]
    fn pinned_values_match_spec() {
        assert_eq!(EVENT_ID_BYTES, 32);
        assert_eq!(SIGNATURE_BYTES, 64);
        assert_eq!(PUBLIC_KEY_BYTES, 32);
        assert_eq!(SECRET_KEY_BYTES, 32);
        assert_eq!(SUBSCRIPTION_ID_MAX_CHARS, 64);
        assert_eq!(NIP19_MAX_LENGTH, 5_000);
        assert_eq!(NIP44_MIN_PLAINTEXT_BYTES, 1);
        assert_eq!(NIP44_MAX_PLAINTEXT_BYTES, 65_535);
        assert_eq!(NIP44_MAX_PAYLOAD_BYTES, 65_603);
        #[cfg(feature = "nip49")]
        {
            assert_eq!(NIP49_SALT_BYTES, 16);
            assert_eq!(NIP49_NONCE_BYTES, 24);
            assert_eq!(NIP49_MAX_LOG_N, 30);
        }
    }
}
