//! [NIP-24] Extra metadata fields and tags.
//!
//! NIP-24 is the spec's landing zone for *de facto* conventions that do
//! not belong anywhere else:
//!
//! - Extended `kind: 0` user-metadata fields (`display_name`, `website`,
//!   `banner`, `bot`, `birthday`).
//! - Deprecated aliases (`displayName`, `username`) that clients must
//!   still accept on read but not produce on write.
//! - Tag conventions with stable meanings across kinds (`r`, `i`,
//!   `title`, `t`).
//!
//! This module is an **index**: it re-exports the canonical Rust types
//! — [`Metadata`] and [`Birthday`] — and documents the one-to-one
//! mapping between NIP-24 prescriptions and the source files. The
//! actual serde and builder code lives in [`crate::metadata`] so there
//! is a single implementation for the `kind: 0` content payload.
//!
//! # Spec ↔ source map
//!
//! ## `kind: 0` extra fields
//!
//! | NIP-24 key         | Rust field                | Notes                                    |
//! |--------------------|---------------------------|------------------------------------------|
//! | `display_name`     | [`Metadata::display_name`]| Alternative, bigger display name.        |
//! | `website`          | [`Metadata::website`]     | Typed as [`crate::types::Url`].          |
//! | `banner`           | [`Metadata::banner`]      | Wide background picture URL.             |
//! | `bot`              | [`Metadata::bot`]         | `true` for automated profiles.           |
//! | `birthday`         | [`Metadata::birthday`]    | Wraps [`Birthday`]; every part optional. |
//!
//! ## Deprecated `kind: 0` aliases
//!
//! These keys survive round-trips via [`Metadata::custom`] and are
//! reachable through the dedicated helpers so callers can migrate older
//! profiles without dropping bytes:
//!
//! - `displayName` → [`Metadata::legacy_display_name`]
//! - `username`    → [`Metadata::legacy_username`]
//!
//! ## Tag conventions
//!
//! NIP-24 fixes these short-name tags' meanings whenever a more
//! specific NIP does not override them. Each one has a typed
//! constructor on [`crate::Tag`] that pins the wire shape and
//! enforces the spec's invariants at the type level:
//!
//! | Tag key | Meaning                                                       | Constructor                                  |
//! |---------|---------------------------------------------------------------|----------------------------------------------|
//! | `r`     | A web URL the event refers to.                                | [`crate::Tag::r`]                            |
//! | `i`     | An external identifier (NIP-73 specifies concrete schemes).   | [`crate::Tag::i`] / [`crate::Tag::i_with_context`] |
//! | `title` | Name of a NIP-51/52/53/99 listing / calendar / live / set.    | [`crate::Tag::title`]                        |
//! | `t`     | A hashtag. The value MUST be a lowercase string.              | [`crate::Tag::t`] (auto-lowercases)          |
//!
//! The `t` constructor folds the input through [`str::to_lowercase`]
//! before storing it, so `Tag::t("RustLang")` and `Tag::t("rustlang")`
//! both produce the byte-identical canonical form `["t", "rustlang"]`.
//!
//! # Usage
//!
//! ```
//! use nula_core::metadata::{Birthday, Metadata};
//!
//! let profile = Metadata::new()
//!     .with_name("alice")
//!     .with_display_name("Alice the Cypherpunk")
//!     .with_bot(false)
//!     .with_birthday(Birthday::month_day(4, 1));
//!
//! let json = profile.to_event_content().unwrap();
//! assert!(json.contains(r#""bot":false"#));
//! assert!(json.contains(r#""birthday":{"month":4,"day":1}"#));
//! ```
//!
//! [NIP-24]: https://github.com/nostr-protocol/nips/blob/master/24.md

pub use crate::metadata::{Birthday, Metadata};
