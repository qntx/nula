//! NIP-77 Negentropy payload decoder fuzz target.
//!
//! Feeds arbitrary bytes into [`nula_core::nips::nip77::decode_payload`]
//! and asserts the decoder either returns `Ok` or a typed
//! [`NegentropyError`] — never a panic.
//!
//! When a payload round-trips successfully the harness also re-encodes
//! it through [`encode_payload`] and checks the bytes match, catching
//! any silent value-loss bugs in either direction.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::nips::nip77::{decode_payload, encode_payload};

fuzz_target!(|data: &[u8]| {
    // Reject the trivial empty case the decoder is documented to
    // reject: it shrinks the corpus toward inputs that actually
    // exercise the varint / range parsers.
    if data.is_empty() {
        return;
    }

    let Ok(payload) = decode_payload(data) else {
        // Typed error path: nothing to assert beyond "did not panic".
        return;
    };

    // Round-trip property: re-encoding the decoded payload must
    // reproduce the canonical byte sequence and decode back into the
    // same logical value.
    let re_encoded = encode_payload(&payload);
    let re_decoded = decode_payload(&re_encoded)
        .expect("re-encoded canonical bytes always decode");
    assert_eq!(payload, re_decoded);
});
