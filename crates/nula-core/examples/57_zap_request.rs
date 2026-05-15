//! Build a NIP-57 zap request and validate it round-trips through
//! [`ZapRequest::from_event`].
//!
//! NIP-57 ("Lightning Zaps") layers a typed kind-9734 zap-request
//! event on top of LNURL-pay. This example demonstrates the typed
//! builder, the canonical `description` JSON the LNURL provider
//! receives, and the symmetric parse from a signed event.
//!
//! ```bash
//! cargo run --example 57_zap_request
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

use nula_core::event::{Coordinate, EventBuilder, EventId, Kind};
use nula_core::nips::nip57::ZapRequest;
use nula_core::types::RelayUrl;
use nula_core::{JsonUtil, Keys};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let zapper = Keys::generate()?;
    let recipient = Keys::generate()?;

    // Build a zap request that targets a kind-1 note authored by
    // the recipient and stored on two relays.
    let request = ZapRequest::new(
        *recipient.public_key(),
        vec![
            RelayUrl::parse("wss://relay.one/")?,
            RelayUrl::parse("wss://relay.two/")?,
        ],
    )
    .amount_msats(21_000) // 21 sats
    .lnurl("LNURL1...EXAMPLE")
    .event_target(EventId::from_byte_array([0xab; 32]))
    .kind_target(Kind::TEXT_NOTE)
    .message("Great post! ⚡");

    println!("recipient        : {}", recipient.public_key().to_hex());
    println!("amount (msat)    : {:?}", request.amount_msats);
    println!("relays           : {}", request.relays.len());

    // The LNURL provider expects the zap request to be a SIGNED
    // kind-9734 event whose JSON forms the `description` field of
    // the BOLT-11 invoice.
    let signed = EventBuilder::zap_request(&request).sign_with_keys(&zapper)?;
    println!("event id         : {}", signed.id.to_hex());
    println!("event kind       : {}", signed.kind.as_u16());
    println!("tag count        : {}", signed.tags.len());

    // Round-trip: parse the typed bundle back from the signed event.
    let parsed = ZapRequest::from_event(&signed)?;
    assert_eq!(parsed, request, "ZapRequest round-trip MUST be lossless");
    println!("round-trip       : OK");

    // The canonical `description` value is exactly the signed
    // event's JSON.
    let description = signed.try_to_json()?;
    println!("description bytes: {}", description.len());

    // Optional: build the addressable variant for a long-form post.
    let addr_request = ZapRequest::new(
        *recipient.public_key(),
        vec![RelayUrl::parse("wss://relay.example/")?],
    )
    .address_target(Coordinate::new(
        Kind::new(30023),
        *recipient.public_key(),
        "great-article",
    ))
    .amount_msats(100_000);
    let addr_signed = EventBuilder::zap_request(&addr_request).sign_with_keys(&zapper)?;
    let addr_parsed = ZapRequest::from_event(&addr_signed)?;
    assert_eq!(addr_parsed, addr_request);
    println!("addr round-trip  : OK");

    Ok(())
}
