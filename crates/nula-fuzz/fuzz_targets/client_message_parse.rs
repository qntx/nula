//! `ClientMessage` JSON parser fuzz target.
//!
//! Treats arbitrary bytes as a UTF-8 NIP-01 wire string and feeds
//! them into `serde_json::from_str::<ClientMessage>`. The harness
//! enforces that:
//!
//! * The deserialiser never panics.
//! * Any successfully deserialised message round-trips through
//!   `serde_json::to_string` + re-parse without value loss.
//!
//! Round-trip property is what catches silent enum-variant
//! reshapes (e.g. a future `NegOpen` field that the serializer
//! forgets to write while the deserialiser still reads).

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::ClientMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = serde_json::from_str::<ClientMessage>(text) else {
        return;
    };
    let re_serialised =
        serde_json::to_string(&parsed).expect("ClientMessage Serialize is infallible");
    let re_parsed: ClientMessage = serde_json::from_str(&re_serialised)
        .expect("canonical Serialize output must re-parse");
    assert_eq!(parsed, re_parsed);
});
