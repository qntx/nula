//! `nula keys generate` / `nula keys parse <INPUT>` implementations.
//!
//! Both subcommands emit a JSON object describing the key in every
//! useful form (`nsec` / `npub` / hex). The shape is stable so
//! downstream `jq` pipelines can rely on it.

use anyhow::{Result, anyhow};
use nula_core::nips::nip19::{FromBech32, ToBech32};
use nula_core::{Keys, PublicKey, SecretKey};
use serde_json::json;

use crate::output::write_json;

/// `nula keys generate` — fresh keypair via the OS RNG.
///
/// # Errors
///
/// Propagates [`nula_core::key::SecretKeyError::Rng`] when the OS
/// RNG is exhausted (effectively unreachable on any supported
/// platform).
pub(crate) fn generate() -> Result<()> {
    let keys = Keys::generate()?;
    let value = describe_key(&keys)?;
    write_json(&value)
}

/// `nula keys parse <INPUT>` — accepts any of `nsec1...`,
/// `npub1...`, or a 64-char hex secret key, prints every form.
///
/// # Errors
///
/// Returns `anyhow!("…")` when the input does not look like any of
/// the supported encodings. Concrete error messages bubble up from
/// the underlying parsers.
pub(crate) fn parse(input: &str) -> Result<()> {
    if let Ok(sk) = SecretKey::from_bech32(input) {
        let keys = Keys::from_secret_key(sk);
        return write_json(&describe_key(&keys)?);
    }
    if let Ok(pk) = PublicKey::from_bech32(input) {
        return write_json(&describe_public_key(&pk)?);
    }
    if let Ok(sk) = SecretKey::parse(input) {
        let keys = Keys::from_secret_key(sk);
        return write_json(&describe_key(&keys)?);
    }
    if let Ok(pk) = PublicKey::parse(input) {
        return write_json(&describe_public_key(&pk)?);
    }
    Err(anyhow!(
        "input is neither a valid nsec1.../npub1.../hex key: {input}"
    ))
}

/// Build the full JSON description for a keypair.
fn describe_key(keys: &Keys) -> Result<serde_json::Value> {
    let secret = keys.secret_key();
    let public = keys.public_key();
    let secret_bech32 = secret.to_bech32()?;
    let public_bech32 = public.to_bech32()?;
    Ok(json!({
        "kind": "keypair",
        "secret_key": {
            "bech32": secret_bech32,
            "hex": secret.to_hex(),
        },
        "public_key": {
            "bech32": public_bech32,
            "hex": public.to_hex(),
        },
    }))
}

/// Build the JSON description for a public-key-only input.
fn describe_public_key(public: &PublicKey) -> Result<serde_json::Value> {
    let bech32 = public.to_bech32()?;
    Ok(json!({
        "kind": "public_key",
        "public_key": {
            "bech32": bech32,
            "hex": public.to_hex(),
        },
    }))
}
