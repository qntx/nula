// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! `nprofile` — TLV-encoded `(pubkey, [relays])`.

use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Author profile recommendation: a public key plus optional relay hints
/// where the author is reachable.
///
/// Wire form is `bech32("nprofile", TLV[(0, pubkey), (1, relay)*])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nip19Profile {
    /// Author's public key.
    pub public_key: PublicKey,
    /// Hint of relays where the author publishes (NIP-19 §nprofile).
    pub relays: Vec<RelayUrl>,
}

impl Nip19Profile {
    /// Construct a profile pointer.
    #[must_use]
    pub fn new(public_key: PublicKey, relays: impl IntoIterator<Item = RelayUrl>) -> Self {
        Self {
            public_key,
            relays: relays.into_iter().collect(),
        }
    }
}
