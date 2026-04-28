// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Human-readable prefixes used by NIP-19.
//!
//! Each constant lists the canonical lowercase HRP. The helpers wrap them in
//! a [`bech32::Hrp`] which the encoder/decoder require, panicking only on
//! buggy callers (the values we feed in are statically valid).

use bech32::Hrp;

/// `npub` — bare 32-byte public key.
pub const NPUB: &str = "npub";
/// `nsec` — bare 32-byte secret key.
pub const NSEC: &str = "nsec";
/// `note` — bare 32-byte event id.
pub const NOTE: &str = "note";
/// `nprofile` — TLV-encoded `(pubkey, [relays])`.
pub const NPROFILE: &str = "nprofile";
/// `nevent` — TLV-encoded `(event_id, [relays], author?, kind?)`.
pub const NEVENT: &str = "nevent";
/// `naddr` — TLV-encoded `(identifier, [relays], author, kind)`.
pub const NADDR: &str = "naddr";

/// Build a [`bech32::Hrp`] from a known constant.
///
/// The four lowercase HRPs above are statically valid; this helper exists so
/// the rest of the module never has to handle the impossible parse error.
#[must_use]
pub fn hrp_unchecked(value: &'static str) -> Hrp {
    debug_assert!(
        Hrp::parse(value).is_ok(),
        "internal NIP-19 HRP must be valid"
    );
    Hrp::parse_unchecked(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hrps_are_valid() {
        for value in [NPUB, NSEC, NOTE, NPROFILE, NEVENT, NADDR] {
            let hrp = Hrp::parse(value).unwrap();
            assert_eq!(hrp.as_str(), value);
        }
    }

    #[test]
    fn hrp_unchecked_round_trip() {
        let hrp = hrp_unchecked(NPUB);
        assert_eq!(hrp.as_str(), NPUB);
    }
}
