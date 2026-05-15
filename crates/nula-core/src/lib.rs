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
//! # Hard limits
//!
//! Every byte size, length cap, and tunable bound the protocol mandates lives
//! in [`limits`]. The table below summarises the most common values; consult
//! the cited NIPs for the binding spec text.
//!
//! | Constant | Value | Spec |
//! |---|---|---|
//! | [`limits::EVENT_ID_BYTES`] | `32` | [NIP-01] §`id` |
//! | [`limits::SIGNATURE_BYTES`] | `64` | [NIP-01] §`sig` |
//! | [`limits::PUBLIC_KEY_BYTES`] | `32` | [BIP-340] |
//! | [`limits::SECRET_KEY_BYTES`] | `32` | [BIP-340] |
//! | [`limits::SUBSCRIPTION_ID_MAX_CHARS`] | `64` | [NIP-01] §`<subscription_id>` |
//! | [`limits::NIP19_MAX_LENGTH`] | `5_000` | [NIP-19] §guards |
//! | [`limits::NIP44_MIN_PLAINTEXT_BYTES`] | `1` | [NIP-44] §plaintext |
//! | [`limits::NIP44_MAX_PLAINTEXT_BYTES`] | `65_535` | [NIP-44] §plaintext |
//! | [`limits::NIP44_MAX_PAYLOAD_BYTES`] | `65_603` | [NIP-44] §payload |
//! | [`limits::NIP49_SALT_BYTES`] | `16` | [NIP-49] §scrypt |
//! | [`limits::NIP49_NONCE_BYTES`] | `24` | [NIP-49] §XChaCha20 |
//! | [`limits::NIP49_MAX_LOG_N`] | `30` | [NIP-49] §scrypt cost cap |
//!
//! [Nostr]: https://github.com/nostr-protocol/nostr
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md
//! [NIP-19]: https://github.com/nostr-protocol/nips/blob/master/19.md
//! [NIP-44]: https://github.com/nostr-protocol/nips/blob/master/44.md
//! [NIP-49]: https://github.com/nostr-protocol/nips/blob/master/49.md
//! [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

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
pub mod limits;
pub mod message;
pub mod metadata;
pub mod nips;
pub mod observe;
pub mod prelude;
pub mod signer;
pub mod types;
pub mod util;

// `zeroize` is consumed across NIP-44, NIP-49 and the `Keys` Drop
// impls; the unconditional placeholder keeps `--no-default-features`
// warning-clean even when only [`SecretKey`]'s zeroize call site is
// active.
// `criterion` is wired in `dev-dependencies` for the `benches/`
// targets only; lib unit tests never reach for it. The placeholder
// keeps `cargo build --tests` warning-clean under
// `unused-crate-dependencies`.
#[cfg(test)]
use criterion as _;
use zeroize as _;

// Crate-root re-exports: only the small set of types that callers reach
// for *by name* on every interaction with Nostr (events, keys, filters,
// messages, the JSON helper, the signer trait). Everything else lives one
// explicit `use` away inside its module — in particular, every `*Error`
// stays under its module path with a descriptive prefix
// (`nula_core::nip02::ContactListError`, `nula_core::signer::SignerError`,
// …). The prefix matches the v0.1 convention and avoids the
// `clippy::error_impl_error` warning while keeping the error names
// disambiguated when callers `use nula_core::*Error`.
// See `prelude` for the curated import-everything view.
pub use self::event::{
    Coordinate, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind, Tags,
    UnsignedEvent, compute_event_id,
};
pub use self::filter::Filter;
pub use self::key::{Keys, PublicKey, SecretKey};
pub use self::message::{ClientMessage, RelayMessage, SubscriptionId};
pub use self::metadata::Metadata;
pub use self::nips::nip19::{FromBech32, Nip19Entity, ToBech32};
pub use self::signer::NostrSigner;
pub use self::types::{ImageDimensions, RelayUrl, Timestamp, Url};
pub use self::util::JsonUtil;
