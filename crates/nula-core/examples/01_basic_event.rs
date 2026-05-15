//! Build, sign, verify, and serialize a kind-1 text note.
//!
//! This is the smallest end-to-end exercise of the `nula-core` event
//! pipeline — the same primitives every higher-level helper composes
//! on top of.
//!
//! ```bash
//! cargo run --example 01_basic_event
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

use nula_core::event::{Event, EventBuilder};
use nula_core::{JsonUtil, Keys};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a fresh BIP-340 keypair. Production code would
    // typically load the secret from disk / a hardware wallet
    // instead.
    let keys = Keys::generate()?;
    println!("public key  : {}", keys.public_key().to_hex());

    // `EventBuilder::text_note` pins `kind = 1` and lets us layer
    // tags on top before signing.
    let signed: Event = EventBuilder::text_note("Hello from nula-core!")
        .tag(nula_core::Tag::new(["t", "intro"])?)
        .sign_with_keys(&keys)?;

    println!("event id    : {}", signed.id.to_hex());
    println!("kind        : {}", signed.kind.as_u16());
    println!("created_at  : {}", signed.created_at.as_secs());
    println!("tag count   : {}", signed.tags.len());

    // The signature must verify against the canonical bytes.
    signed.verify()?;
    println!("signature   : OK");

    // The wire form is the JSON shape NIP-01 specifies.
    let json = signed.try_to_json()?;
    println!("---\nwire JSON ({} bytes):\n{}", json.len(), json);

    // Round-trip the JSON to confirm the canonical form is stable.
    let reparsed = Event::from_json(&json)?;
    assert_eq!(reparsed, signed, "round-trip must preserve the event");
    println!("---\nround-trip  : OK");

    Ok(())
}
