//! Observability field conventions for `tracing` spans.
//!
//! This module is documentation-only: it does not export any Rust
//! items beyond the constants below. Its job is to be the single
//! place every `#[tracing::instrument(...)]` annotation in the crate
//! refers to when naming fields, so that downstream subscribers (a
//! Loki / Tempo / OTEL pipeline, or a local `tracing-subscriber`) see
//! a consistent schema regardless of which NIP a span came from.
//!
//! # Why fixed names
//!
//! Ad-hoc field names (`kind`, `event_kind`, `nostr_kind`, …) break
//! dashboard reuse across builds. Pinning the names here lets a
//! single Grafana query (`{nostr_event_kind=…}`) work for every span
//! emitted by `nula-core`.
//!
//! # Names in use
//!
//! The canonical shape is `nostr.<subject>.<attribute>`. The dot is
//! rendered as `.` by `tracing`'s JSON layers and as `_` by the
//! default `fmt` layer; both are fine because the subject/attribute
//! split disambiguates either way.
//!
//! | Constant                    | Field name                    | Meaning                                                     |
//! |-----------------------------|-------------------------------|-------------------------------------------------------------|
//! | [`FIELD_EVENT_KIND`]        | `nostr.event.kind`            | Event kind as a `u16`.                                      |
//! | [`FIELD_EVENT_CONTENT_SIZE`]| `nostr.event.content_size`    | Byte length of the event `content` (post-encoding).         |
//! | [`FIELD_EVENT_TAG_COUNT`]   | `nostr.event.tag_count`       | Number of top-level tags on the event.                      |
//! | [`FIELD_EVENT_ID`]          | `nostr.event.id`              | 64-char lowercase hex event id (only when already computed).|
//! | [`FIELD_PUBKEY_SHORT`]      | `nostr.pubkey.short`          | First 8 hex chars of the involved public key; never secret. |
//! | [`FIELD_NIP`]               | `nostr.nip`                   | Spec number most directly exercised by the span, e.g. `44`. |
//! | [`FIELD_PLAINTEXT_SIZE`]    | `nostr.encryption.plaintext_size` | Byte length of the plaintext (never the bytes themselves).|
//! | [`FIELD_CIPHERTEXT_SIZE`]   | `nostr.encryption.ciphertext_size`| Byte length of the ciphertext.                          |
//! | [`FIELD_BECH32_HRP`]        | `nostr.bech32.hrp`            | Human-readable prefix of the bech32 string being processed. |
//!
//! # Redaction rule
//!
//! **Never** attach any of the following to a span:
//!
//! - [`crate::SecretKey`] bytes or hex.
//! - NIP-44 / NIP-04 plaintexts.
//! - `ConversationKey` contents.
//! - NIP-49 password bytes.
//!
//! All of these MUST be passed to `#[tracing::instrument(skip(...))]`
//! so a subscriber that mirrors spans to, say, Sentry never records
//! secrets on the wire. When the caller needs a correlation tag for a
//! pubkey, use [`FIELD_PUBKEY_SHORT`] (first 8 chars) — the 32-byte
//! x-only public key is itself public information, but we still only
//! log a prefix to keep log volumes reasonable.

/// `nostr.event.kind`
pub const FIELD_EVENT_KIND: &str = "nostr.event.kind";
/// `nostr.event.content_size`
pub const FIELD_EVENT_CONTENT_SIZE: &str = "nostr.event.content_size";
/// `nostr.event.tag_count`
pub const FIELD_EVENT_TAG_COUNT: &str = "nostr.event.tag_count";
/// `nostr.event.id`
pub const FIELD_EVENT_ID: &str = "nostr.event.id";
/// `nostr.pubkey.short`
pub const FIELD_PUBKEY_SHORT: &str = "nostr.pubkey.short";
/// `nostr.nip`
pub const FIELD_NIP: &str = "nostr.nip";
/// `nostr.encryption.plaintext_size`
pub const FIELD_PLAINTEXT_SIZE: &str = "nostr.encryption.plaintext_size";
/// `nostr.encryption.ciphertext_size`
pub const FIELD_CIPHERTEXT_SIZE: &str = "nostr.encryption.ciphertext_size";
/// `nostr.bech32.hrp`
pub const FIELD_BECH32_HRP: &str = "nostr.bech32.hrp";
