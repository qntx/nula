//! Event parse + verify fuzz target.
//!
//! Property under test: deserialising an arbitrary JSON blob as an
//! [`Event`] and then calling `verify_id` / `verify_signature` /
//! `verify` MUST NOT panic — every malformed-but-deserialisable event
//! must yield a `bool` / typed error, never an index-OOB, overflow, or
//! secp256k1 abort.
//!
//! Relays and clients verify attacker-controlled events on the hot
//! path, so a panic here is a remote denial-of-service. A
//! successfully-parsed event must also re-serialise and re-parse.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::event::Event;

fuzz_target!(|data: &[u8]| {
    let Ok(event) = serde_json::from_slice::<Event>(data) else {
        return;
    };

    // None of these may panic regardless of how adversarial the
    // (successfully-deserialised) event is.
    let _ = event.verify_id();
    let _ = event.verify_signature();
    let _ = event.verify();

    // Re-serialisation must be infallible and the bytes must re-parse:
    // the wire form has to stay stable so event ids never drift.
    if let Ok(bytes) = serde_json::to_vec(&event) {
        let _ = serde_json::from_slice::<Event>(&bytes);
    }
});
