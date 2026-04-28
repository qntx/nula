//! BIP-340 secp256k1 keypair convenient for signing.
//!
//! [`Keys`] holds a [`SecretKey`] alongside a cached
//! [`secp256k1::Keypair`]. The cache lets us sign Schnorr messages without
//! recomputing the public key on every call — important on the hot path of
//! event creation.

use core::fmt;

use secp256k1::SECP256K1;
use secp256k1::schnorr::Signature;

use super::{PublicKey, SecretKey, SecretKeyError};

/// Length of a Schnorr signature in bytes (BIP-340).
pub const SIGNATURE_SIZE: usize = 64;

/// secp256k1 BIP-340 keypair.
///
/// Construct from a [`SecretKey`] (`Keys::from_secret_key`) or generate a fresh
/// pair (`Keys::generate`). The public key is computed eagerly so signing has
/// O(1) overhead.
///
/// # Example
///
/// ```
/// use nula_core::Keys;
///
/// let keys = Keys::generate().unwrap();
/// let pk_hex = keys.public_key().to_hex();
/// assert_eq!(pk_hex.len(), 64);
/// ```
#[derive(Clone)]
pub struct Keys {
    secret_key: SecretKey,
    public_key: PublicKey,
    keypair: secp256k1::Keypair,
}

impl Keys {
    /// Construct a [`Keys`] from a [`SecretKey`].
    #[must_use]
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let keypair = secp256k1::Keypair::from_secret_key(SECP256K1, secret_key.as_inner());
        let (xonly, _parity) = keypair.x_only_public_key();
        Self {
            secret_key,
            public_key: PublicKey::from(xonly),
            keypair,
        }
    }

    /// Generate a fresh [`Keys`] pair using the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Returns [`SecretKeyError::Rng`] if the OS RNG fails.
    pub fn generate() -> Result<Self, SecretKeyError> {
        let secret_key = SecretKey::generate()?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Parse [`Keys`] from a 64-char lowercase hex secret key.
    ///
    /// # Errors
    ///
    /// See [`SecretKeyError`].
    pub fn parse<S>(input: S) -> Result<Self, SecretKeyError>
    where
        S: AsRef<str>,
    {
        let secret_key = SecretKey::parse(input)?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Borrow the secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Borrow the public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Borrow the inner [`secp256k1::Keypair`].
    ///
    /// Use this only at the boundary with the cryptography backend.
    #[must_use]
    pub const fn as_inner(&self) -> &secp256k1::Keypair {
        &self.keypair
    }

    /// Sign an arbitrary message digest with BIP-340 Schnorr.
    ///
    /// Callers are responsible for hashing application data — for Nostr
    /// events, the digest is the SHA-256 of the canonical serialization
    /// described in NIP-01.
    #[must_use]
    pub fn sign_schnorr(&self, message: &[u8; 32]) -> Signature {
        self.keypair.sign_schnorr(message)
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        // Erase the cached keypair's private half. The wrapped `SecretKey`
        // is erased independently by its own `Drop` impl, so both copies of
        // the secret material are best-effort zeroized when `Keys` falls
        // out of scope.
        self.keypair.non_secure_erase();
    }
}

impl PartialEq for Keys {
    fn eq(&self, other: &Self) -> bool {
        self.secret_key == other.secret_key
    }
}

impl Eq for Keys {}

impl From<SecretKey> for Keys {
    fn from(secret_key: SecretKey) -> Self {
        Self::from_secret_key(secret_key)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    /// BIP-340 test vector 0.
    const SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const EXPECTED_PUBKEY: [u8; 32] =
        hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");

    #[test]
    fn derives_expected_public_key() {
        let keys = Keys::parse(SECRET_HEX).unwrap();
        assert_eq!(keys.public_key().to_byte_array(), EXPECTED_PUBKEY);
    }

    #[test]
    fn generate_distinct() {
        let lhs = Keys::generate().unwrap();
        let rhs = Keys::generate().unwrap();
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn signs_and_verifies() {
        let keys = Keys::parse(SECRET_HEX).unwrap();
        let message = hex!("0202020202020202020202020202020202020202020202020202020202020202");
        let sig = keys.sign_schnorr(&message);
        assert!(
            SECP256K1
                .verify_schnorr(&sig, &message, keys.public_key().as_inner())
                .is_ok()
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let keys = Keys::parse(SECRET_HEX).unwrap();
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(SECRET_HEX));
    }

    #[test]
    fn equality_compares_secret_only() {
        let lhs = Keys::parse(SECRET_HEX).unwrap();
        let rhs = Keys::parse(SECRET_HEX).unwrap();
        assert_eq!(lhs, rhs);
    }
}
