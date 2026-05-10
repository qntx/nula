//! [NIP-01] Basic protocol flow description.
//!
//! NIP-01 is the bedrock of Nostr: it defines the event object, the
//! signature scheme, the JSON wire encoding, the relay/client message
//! grammar, and the subscription filter. Every other NIP layers on top.
//!
//! Unlike the rest of the [`crate::nips`] modules, NIP-01 does not own
//! its own types — those live where the protocol uses them:
//!
//! - **Events** are in [`crate::event`].
//! - **Filters** are in [`crate::filter`].
//! - **Wire messages** are in [`crate::message`].
//! - **Keys & signatures** are in [`crate::key`].
//! - **Tags** are in [`crate::event::tag`].
//! - **Bech32 entities** are in [`crate::nips::nip19`].
//!
//! This module is therefore an *index* rather than a fresh implementation:
//! it re-exports the canonical NIP-01 surface, documents the spec
//! mapping, and pins the wire-format guarantees that the rest of the
//! crate must uphold. Treat it as the entry point when reading the spec
//! alongside the source.
//!
//! # Spec ↔ source map
//!
//! | Spec section                       | Module / type                              |
//! |------------------------------------|--------------------------------------------|
//! | §Events and signatures             | [`Event`], [`UnsignedEvent`], [`compute_event_id`] |
//! | §Tags (§32)                        | [`Tag`], [`Tags`], [`TagKind`], [`SingleLetterTag`] |
//! | §Kinds                             | [`Kind`]                                   |
//! | §Communication between clients and relays | [`ClientMessage`], [`RelayMessage`] |
//! | §Filters                           | [`Filter`]                                 |
//! | §Replaceable / Addressable events  | [`Coordinate`], [`Kind::is_replaceable`], [`Kind::is_addressable`] |
//! | §Canonical event id                | [`compute_event_id`], [`canonical_form_overview`] |
//!
//! # Canonical id invariant
//!
//! NIP-01 §Events and signatures pins the event id to
//! `SHA-256` of the *compact* JSON serialization of
//! `[0, pubkey, created_at, kind, tags, content]`. The function
//! [`compute_event_id`] is the only sanctioned way to produce one inside
//! `nula-core`; if a refactor ever introduces a second canonicalisation
//! path, the regression test
//! `event::tests::canonical_serialization_is_infallible` will fail before
//! the divergent path can ship. The shared invariants are documented at
//! length in [`canonical_form_overview`] below.
//!
//! # Wire-level guarantees
//!
//! - **Compact JSON.** No whitespace, lowercase hex pubkeys/ids, integer
//!   timestamps in seconds since the Unix epoch.
//! - **Control-character escapes.** Exactly the seven NIP-01 §32 short
//!   escapes (`\b \t \n \f \r \" \\`); every other control byte uses
//!   `\u00XX`.
//! - **Tag value order is preserved.** Both [`Tags`] and the
//!   single-letter buckets in [`Filter::generic_tags`] keep insertion
//!   order so byte-level interop with `nostr-tools`, `rust-nostr`, and
//!   `go-nostr` is exact.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

pub use crate::event::{
    Coordinate, CoordinateError, Event, EventBuilder, EventBuilderError, EventError, EventId,
    EventIdError, Kind, SingleLetterTag, SingleLetterTagError, Tag, TagError, TagKind, Tags,
    UnsignedEvent, UnsignedEventError, compute_event_id,
};
pub use crate::filter::Filter;
pub use crate::key::{Keys, PublicKey, PublicKeyError, SecretKey, SecretKeyError};
pub use crate::message::{
    ClientMessage, ClientMessageError, MachineReadablePrefix, MachineReadablePrefixError,
    RelayMessage, RelayMessageError, SubscriptionId, SubscriptionIdError,
};

/// Canonical event-id form (documentation-only).
///
/// NIP-01 hashes the JSON array `[0, pubkey, created_at, kind, tags,
/// content]` exactly as serialised by [`crate::event::compute_event_id`].
/// The function is the single source of truth; this item exists purely
/// so the rustdoc index of NIP-01 has a heading-level anchor that
/// callers can link to from spec citations and migration guides.
///
/// # Inputs
///
/// 1. `pubkey` — lowercase hex of the 32-byte x-only key.
/// 2. `created_at` — integer Unix seconds.
/// 3. `kind` — integer kind, 0..=65535.
/// 4. `tags` — array of arrays of strings, in insertion order.
/// 5. `content` — UTF-8 string with NIP-01 §32 control-character escapes.
///
/// # Output
///
/// 32-byte SHA-256 digest, surfaced as a 64-char lowercase hex
/// [`crate::EventId`].
///
/// # Stability
///
/// The serialization is byte-identical with `nostr-tools`,
/// `rust-nostr`, and `go-nostr`. This crate's
/// `event::tests::canonical_serialization_is_infallible` and
/// `nip01_control_character_escapes_are_canonical` regression tests
/// pin the contract; any drift fails CI.
#[doc(hidden)]
pub const fn canonical_form_overview() {}
