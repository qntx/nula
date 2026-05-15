//! Walk a kind-1 note's content with the unified [`NostrParser`].
//!
//! The parser yields a single token stream covering NIP-21 references,
//! URLs, hashtags, line breaks, and plain text — the four affordances
//! a UI layer needs to render a note. This example demonstrates the
//! full flow on a small sample document.
//!
//! ```bash
//! cargo run --example 99_parser
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

use nula_core::Keys;
use nula_core::nips::nip19::ToBech32;
use nula_core::parser::{NostrParser, NostrParserOptions, Token};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")?;

    // A typical note touching every affordance.
    let note = format!(
        "🚀 Welcome to Nostr!\nFollow nostr:{} and visit https://nostr.com.\n#nostr #rust",
        alice.public_key().to_bech32()?,
    );
    println!("---\nsource:\n{note}\n---\ntokens:");

    let parser = NostrParser::new();
    for token in parser.parse(&note, NostrParserOptions::default()) {
        match token {
            Token::Text(s) => println!("text     : {s:?}"),
            Token::Nostr(uri) => println!("nostr    : {uri:?}"),
            Token::Url(url) => println!("url      : {url}"),
            Token::Hashtag(tag) => println!("hashtag  : #{tag}"),
            Token::LineBreak => println!("linebreak"),
            other => println!("unknown  : {other:?}"),
        }
    }

    // Disable hashtag detection to demonstrate granular control.
    println!("---\nsame content with hashtags disabled:");
    for token in parser.parse(&note, NostrParserOptions::default().hashtags(false)) {
        if let Token::Text(s) = token
            && s.trim().is_empty()
        {
            continue;
        }
        println!("{token:?}");
    }

    Ok(())
}
