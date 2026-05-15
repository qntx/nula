//! Encode and decode every NIP-19 entity (`npub`, `nsec`, `note`,
//! `nprofile`, `nevent`, `naddr`) and verify the round-trip is
//! lossless.
//!
//! NIP-19 specifies the human-readable bech32 representation for every
//! Nostr identifier. This example demonstrates each variant and asserts
//! that the encoded → decoded pipeline preserves the original payload.
//!
//! ```bash
//! cargo run --example 19_bech32_round_trip
//! ```

#![allow(
    clippy::print_stdout,
    clippy::missing_assert_message,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::uninlined_format_args,
    clippy::useless_vec,
    unused_crate_dependencies,
    reason = "runnable demo: stdout output is the whole point, panic-on-failure is acceptable in a script-like context, and the binary inherits the lib's dep set"
)]

use nula_core::event::{Coordinate, EventId, Kind};
use nula_core::nips::nip19::{FromBech32, Nip19Coordinate, Nip19Event, Nip19Profile, ToBech32};
use nula_core::types::RelayUrl;
use nula_core::{Keys, PublicKey, SecretKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = Keys::generate()?;

    // npub — bare public key.
    let npub = keys.public_key().to_bech32()?;
    let pk_back = PublicKey::from_bech32(&npub)?;
    assert_eq!(pk_back, *keys.public_key());
    println!("npub      : {npub}");

    // nsec — bare secret key. PRINTED here only for the demo; real
    // code SHOULD never log secrets.
    let nsec = keys.secret_key().to_bech32()?;
    let sk_back = SecretKey::from_bech32(&nsec)?;
    assert_eq!(&sk_back, keys.secret_key());
    println!("nsec      : {} (truncated)", &nsec[..16]);

    // note — bare event id (no relay hint, no author hint).
    let id = EventId::from_byte_array([0xab; 32]);
    let note = id.to_bech32()?;
    let id_back = EventId::from_bech32(&note)?;
    assert_eq!(id_back, id);
    println!("note      : {note}");

    // nprofile — pubkey + relay hints.
    let relays = vec![
        RelayUrl::parse("wss://relay.one/")?,
        RelayUrl::parse("wss://relay.two/")?,
    ];
    let profile = Nip19Profile::new(*keys.public_key(), relays.iter().cloned());
    let nprofile = profile.to_bech32()?;
    let profile_back = Nip19Profile::from_bech32(&nprofile)?;
    assert_eq!(profile_back, profile);
    println!("nprofile  : {nprofile}");

    // nevent — event id + optional author + optional kind + relay hints.
    let nevent_payload = Nip19Event::new(id)
        .with_author(*keys.public_key())
        .with_kind(Kind::TEXT_NOTE)
        .with_relays(relays.iter().cloned());
    let nevent = nevent_payload.to_bech32()?;
    let nevent_back = Nip19Event::from_bech32(&nevent)?;
    assert_eq!(nevent_back, nevent_payload);
    println!("nevent    : {nevent}");

    // naddr — addressable coordinate (kind:author:identifier).
    let coord = Coordinate::new(Kind::new(30023), *keys.public_key(), "post-1");
    let nip19_coord = Nip19Coordinate::from_coordinate(coord.clone(), relays.iter().cloned());
    let naddr = nip19_coord.to_bech32()?;
    let naddr_back = Nip19Coordinate::from_bech32(&naddr)?;
    assert_eq!(naddr_back.coordinate, coord);
    println!("naddr     : {naddr}");

    println!("---\nall 6 NIP-19 entities round-trip OK");
    Ok(())
}
