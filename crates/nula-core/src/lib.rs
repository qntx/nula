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
pub mod nips;
pub mod prelude;
pub mod signer;
pub mod types;
pub mod util;

// Placeholder import for crates that are declared in `Cargo.toml` but
// not yet pulled in by any `nipNN` module: silences
// `unused-crate-dependencies` so we can stage the dep graph ahead of
// the implementation. Remove the corresponding line as each NIP lights
// up its own real `use … ::*;`.
#[cfg(feature = "nip05")]
use reqwest as _;
// `zeroize` is consumed across NIP-44, NIP-49 and the `Keys` Drop
// impls; the unconditional placeholder keeps `--no-default-features`
// warning-clean even when only [`SecretKey`]'s zeroize call site is
// active.
use zeroize as _;

// `criterion` is wired in `dev-dependencies` for the `benches/`
// targets only; lib unit tests never reach for it. `base64` is a
// dev-dependency for the `nip44_vectors` integration test (and an
// optional production dependency behind the `nip04` / `nip44`
// features); when both features are off, the lib's own unit-test build
// has no use for it. Both placeholders keep `cargo build --tests`
// warning-clean under `unused-crate-dependencies` regardless of which
// feature subset is active.
#[cfg(test)]
use {base64 as _, criterion as _};

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
