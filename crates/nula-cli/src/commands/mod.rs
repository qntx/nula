//! Subcommand implementations. Each module exposes one async (or
//! sync) function per leaf subcommand; argument parsing happens
//! upstream in `crate::cli`.

pub(crate) mod dm;
pub(crate) mod event;
pub(crate) mod keys;
pub(crate) mod relay;
pub(crate) mod relays;

use anyhow::{Result, anyhow};
use nula_core::nips::nip19::FromBech32;
use nula_core::{Keys, PublicKey, SecretKey};

/// Accept `nsec1...` or 64-char hex for a secret key and build a
/// full [`Keys`] pair.
///
/// # Errors
///
/// Returns an error if `raw` is neither a valid bech32 `nsec` nor a
/// 64-char hex secret.
pub(crate) fn parse_secret(raw: &str) -> Result<Keys> {
    if let Ok(sk) = SecretKey::from_bech32(raw) {
        return Ok(Keys::from_secret_key(sk));
    }
    if let Ok(sk) = SecretKey::parse(raw) {
        return Ok(Keys::from_secret_key(sk));
    }
    Err(anyhow!("secret must be nsec1... or 64-char hex"))
}

/// Accept `npub1...` or 64-char hex for a public key.
///
/// # Errors
///
/// Returns an error if `raw` is neither a valid bech32 `npub` nor a
/// 64-char hex public key.
pub(crate) fn parse_public_key(raw: &str) -> Result<PublicKey> {
    if let Ok(pk) = PublicKey::from_bech32(raw) {
        return Ok(pk);
    }
    PublicKey::parse(raw).map_err(Into::into)
}
