//! NIP-46 (Nostr Connect) remote-signer protocol walkthrough.
//!
//! NIP-46 lets a *client* delegate signing to a remote *signer* over
//! Nostr-encrypted JSON-RPC. The example walks through the spec's
//! happy path:
//!
//! 1. the signer publishes a `bunker://` URI;
//! 2. the client parses it and crafts a `connect` request;
//! 3. the client envelopes the request as a [`Message`];
//! 4. the signer answers with the canonical `"ack"`.
//!
//! The cryptographic transport (NIP-44 wrapping of the JSON-RPC body)
//! is intentionally elided — the focus here is the typed handshake.
//!
//! ```bash
//! cargo run --example 46_remote_signer --features nip46
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

use nula_core::nips::nip46::{Message, Method, Request, Response, ResponseResult, Uri};
use nula_core::types::RelayUrl;
use nula_core::{JsonUtil, Keys};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Signer side: produce the `bunker://` URI
    let signer_keys = Keys::generate()?;
    let relay = RelayUrl::parse("wss://relay.example/")?;
    let bunker = format!(
        "bunker://{}?relay={}&secret=12345",
        signer_keys.public_key().to_hex(),
        relay.as_str(),
    );
    println!("bunker URI         : {bunker}");

    // 2. Client side: parse the URI and build a `connect`
    let parsed = Uri::parse(&bunker)?;
    let Uri::Bunker {
        remote_signer_public_key,
        relays,
        secret,
    } = &parsed
    else {
        unreachable!("we constructed a bunker URI above");
    };
    println!("client sees relays : {}", relays.len());
    println!("client sees secret : {:?}", secret);

    let connect = Request::Connect {
        remote_signer_public_key: *remote_signer_public_key,
        secret: secret.clone(),
        // An empty `Vec` means "no permissions requested" while
        // `None` means "field omitted".
        perms: None,
    };
    let request = Message::request("req-1", &connect);
    let request_json = request.try_to_json()?;
    println!("---");
    println!("request envelope JSON ({} bytes):", request_json.len());
    println!("{request_json}");

    // 3. Signer side: roundtrip params via the typed wire codec
    let params = connect.params();
    let recovered = Request::from_wire(Method::Connect, &params)?;
    assert_eq!(recovered, connect, "wire codec must be lossless");
    println!("---\nwire round-trip    : OK");

    // 4. Signer answers with the canonical `ack`
    let response = Response::with_result(ResponseResult::Ack);
    let response_envelope = Message::response("req-1", response);
    let response_json = response_envelope.try_to_json()?;
    println!("---");
    println!("response envelope JSON:");
    println!("{response_json}");

    Ok(())
}
