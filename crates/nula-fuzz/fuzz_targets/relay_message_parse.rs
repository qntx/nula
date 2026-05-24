//! `RelayMessage` JSON parser fuzz target. Mirror of
//! `client_message_parse` for the relay → client direction.
//!
//! Same enforcement: never panic; every successful parse must
//! round-trip through `serde_json::to_string` + re-parse without
//! value loss.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::RelayMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = serde_json::from_str::<RelayMessage>(text) else {
        return;
    };
    let re_serialised =
        serde_json::to_string(&parsed).expect("RelayMessage Serialize is infallible");
    let re_parsed: RelayMessage = serde_json::from_str(&re_serialised)
        .expect("canonical Serialize output must re-parse");
    assert_eq!(parsed, re_parsed);
});
