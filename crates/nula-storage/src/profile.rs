//! User-facing profile aggregate.
//!
//! [`Profile`] pairs a [`PublicKey`] with the most recent [`Metadata`]
//! the store has observed for that key. The pair shows up wherever
//! upper-layer code wants "user info" without committing to a NIP — it
//! is the result of [`crate::NostrDatabaseExt::profile`] and of the
//! per-author profile lookups used by relay-pool and gossip.

use nula_core::key::PublicKey;
use nula_core::metadata::Metadata;

/// A `(public_key, metadata)` pair.
///
/// `metadata` is `None` when the store has never observed a kind-0
/// event for `public_key`. Callers should fall back to displaying the
/// bech32-encoded npub in that case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The user's identity key.
    pub public_key: PublicKey,
    /// The most recent kind-0 metadata payload observed, if any.
    pub metadata: Option<Metadata>,
}

impl Profile {
    /// Construct a profile from a key and metadata payload.
    #[must_use]
    #[inline]
    pub const fn new(public_key: PublicKey, metadata: Metadata) -> Self {
        Self {
            public_key,
            metadata: Some(metadata),
        }
    }

    /// Construct a profile that only carries a public key.
    ///
    /// Used as a fallback when the database has not yet seen a kind-0
    /// event for the key.
    #[must_use]
    #[inline]
    pub const fn anonymous(public_key: PublicKey) -> Self {
        Self {
            public_key,
            metadata: None,
        }
    }
}

impl From<PublicKey> for Profile {
    fn from(public_key: PublicKey) -> Self {
        Self::anonymous(public_key)
    }
}
