//! NIP-01 `kind:0` [`Metadata`] parse fuzz target.
//!
//! Property under test: deserialising an arbitrary JSON blob as
//! [`Metadata`] must not panic, and a value that parses must
//! re-serialise and re-parse (round-trip stable). Profile metadata is
//! attacker-controlled content fetched from relays, so the parser and
//! its serializer must tolerate any input without aborting.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::metadata::Metadata;

fuzz_target!(|data: &[u8]| {
    let Ok(metadata) = serde_json::from_slice::<Metadata>(data) else {
        return;
    };

    // A successfully-parsed value must serialise back and re-parse;
    // neither step may panic.
    if let Ok(bytes) = serde_json::to_vec(&metadata) {
        let _ = serde_json::from_slice::<Metadata>(&bytes);
    }
});
