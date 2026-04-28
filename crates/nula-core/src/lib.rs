//! Protocol primitives for the [Nostr] protocol used across the `nula` workspace.
//!
//! `nula-core` is the lowest layer of the workspace. It defines the on-the-wire
//! data model (events, filters, tags, messages), the cryptographic identity
//! (keys, signatures), and a small set of shared value types. It performs no
//! I/O, has no async runtime dependency, and is safe to reuse from tests,
//! relays, signers, and offline tooling.
//!
//! Higher-level crates layer pool management, transports, databases, gossip,
//! signers, and relay servers on top of these primitives.
//!
//! [Nostr]: https://github.com/nostr-protocol/nostr

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-core")]
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_assert_message,
        clippy::missing_errors_doc,
        clippy::tests_outside_test_module,
        reason = "test code may use panicking and indexing idioms for brevity"
    )
)]

pub mod event;
pub mod filter;
pub mod key;
pub mod message;
pub mod metadata;
pub mod nip02;
pub mod nip09;
pub mod nip10;
pub mod nip11;
pub mod nip13;
#[cfg(feature = "nip17")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip17")))]
pub mod nip17;
pub mod nip19;
pub mod nip22;
pub mod nip40;
pub mod nip42;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip44;
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub mod nip49;
#[cfg(feature = "nip59")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip59")))]
pub mod nip59;
pub mod nip65;
pub mod nip70;
pub mod prelude;
pub mod signer;
pub mod types;
pub mod util;

// Phase-0 placeholder dependencies. These crates ship with the v0.2 base
// dependency set so we can land NIP-04 / NIP-05 / NIP-06 / NIP-49 in the
// next phases without touching `Cargo.toml` again. Each `use … as _;`
// silences the `unused_crate_dependencies` lint until the corresponding
// `nipNN` module lights it up. Remove the matching line as each NIP is
// implemented.
#[cfg(feature = "nip04")]
use aes as _;
#[cfg(feature = "nip04")]
use cbc as _;
#[cfg(feature = "nip06")]
use bip39 as _;
#[cfg(feature = "nip05")]
use reqwest as _;
// `zeroize` is consumed by NIP-44 today; an unconditional placeholder
// keeps `--no-default-features` warning-clean and is harmless when the
// crate is also pulled in through a real `use zeroize::...;` elsewhere.
use zeroize as _;

// Crate-root re-exports: only the small set of types that callers reach
// for *by name* on every interaction with Nostr (events, keys, filters,
// messages, the JSON helper, the signer trait). Everything else lives one
// explicit `use` away inside its module — in particular, every `*Error`
// stays under its module path (`nula_core::nip02::Error`, etc.) so error
// names cannot collide and so adding a new error variant is not a breaking
// change. See `prelude` for the curated import-everything view.
pub use self::event::{
    Coordinate, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind, Tags,
    UnsignedEvent, compute_event_id,
};
pub use self::filter::Filter;
pub use self::key::{Keys, PublicKey, SecretKey};
pub use self::message::{ClientMessage, RelayMessage, SubscriptionId};
pub use self::metadata::Metadata;
pub use self::nip19::{FromBech32, Nip19Entity, ToBech32};
pub use self::signer::NostrSigner;
pub use self::types::{ImageDimensions, RelayUrl, Timestamp, Url};
pub use self::util::JsonUtil;
