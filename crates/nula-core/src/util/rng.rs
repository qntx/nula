// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Random byte generation helpers.
//!
//! The Nostr protocol needs cryptographically random bytes for fresh secret
//! keys and unique subscription IDs. This module wraps [`getrandom`] and
//! exposes a tiny stable API: it returns errors instead of panicking when the
//! operating system fails to provide entropy, which is critical for relays
//! and signers running in constrained environments (containers, jails, kernel
//! lockdown, …).

use thiserror::Error;

/// Error returned when the operating system fails to provide entropy.
#[derive(Debug, Clone, Copy, Error)]
#[error("operating system failed to provide entropy: {0}")]
#[non_exhaustive]
pub struct RngError(#[from] pub(crate) getrandom::Error);

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// # Errors
///
/// Propagates errors from the OS entropy source.
pub fn fill_bytes(buf: &mut [u8]) -> Result<(), RngError> {
    getrandom::fill(buf)?;
    Ok(())
}

/// Return `N` cryptographically secure random bytes from the OS RNG.
///
/// # Errors
///
/// Propagates errors from the OS entropy source.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RngError> {
    let mut out = [0_u8; N];
    fill_bytes(&mut out)?;
    Ok(out)
}

/// Generate a lowercase hex string built from `N` random bytes.
///
/// The output is always `2 * N` characters long. This is the canonical format
/// used by Nostr subscription IDs and other opaque identifiers carried over
/// the wire.
///
/// # Errors
///
/// Propagates errors from the OS entropy source.
pub fn random_hex_string<const N: usize>() -> Result<String, RngError> {
    let bytes = random_bytes::<N>()?;
    Ok(crate::util::hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_distinct() {
        let lhs: [u8; 32] = random_bytes().unwrap();
        let rhs: [u8; 32] = random_bytes().unwrap();
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn random_hex_string_length() {
        let value = random_hex_string::<16>().unwrap();
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
