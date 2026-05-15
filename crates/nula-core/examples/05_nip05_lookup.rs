//! NIP-05 DNS identifier verification with a hand-supplied
//! well-known document.
//!
//! NIP-05 maps a `<local>@<domain>` handle to a BIP-340 pubkey via
//! `https://<domain>/.well-known/nostr.json?name=<local>`. The
//! example parses the address, computes the canonical URL, and runs
//! the offline verification path against an in-memory document so
//! the snippet stays runnable without a network round-trip.
//!
//! ```bash
//! cargo run --example 05_nip05_lookup
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

use nula_core::PublicKey;
use nula_core::nips::nip05::{Nip05Address, verify_document};

const FIXTURE_DOC: &str = r#"{
    "names": {
        "bob": "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"
    },
    "relays": {
        "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4":
            ["wss://relay.example/"]
    }
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Parse the user-typed handle. The parser lowercases the
    //    domain, validates the local-part charset, and recognises
    //    the `_@<domain>` "root" form clients render as just
    //    `<domain>`.
    let address = Nip05Address::parse("Bob@Example.COM")?;
    println!("local       : {}", address.local);
    println!("domain      : {}", address.domain);
    println!("display     : {}", address.display());
    println!("well-known  : {}", address.well_known_url());

    // 2) Verify the in-memory well-known document. Production code
    //    would fetch this over HTTPS via the `Nip05Fetcher` trait
    //    (gated behind the `nip05` feature for the reqwest impl);
    //    keeping the example offline keeps it executable from any
    //    box without reaching the network.
    let expected =
        PublicKey::parse("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")?;
    let ok = verify_document(&address, FIXTURE_DOC, &expected)?;
    println!("verified    : {ok}");
    assert!(ok, "fixture document MUST verify against the expected key");

    // 3) A different pubkey simply returns `false` — not an error.
    //    This mirrors the spec semantics: the document is well-formed
    //    but the operator has chosen a different binding.
    let stranger =
        PublicKey::parse("0000000000000000000000000000000000000000000000000000000000000003")?;
    let mismatch = verify_document(&address, FIXTURE_DOC, &stranger)?;
    println!("mismatch ok : {mismatch}");
    assert!(!mismatch);

    Ok(())
}
