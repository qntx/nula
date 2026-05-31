//! NIP modules — one Rust module per [Nostr Implementation Possibility].
//!
//! Each submodule mirrors the `nostr-protocol/nips` numbering exactly so
//! that grepping for `nipXX` either in this crate or in the spec
//! repository points at the same artefact. The common surface across
//! all of them:
//!
//! - `pub fn` helpers (typed accessors, parsers, builders) that read
//!   from or attach to an [`Event`](crate::Event) or
//!   [`UnsignedEvent`](crate::UnsignedEvent).
//! - A module-local error enum prefixed with the NIP topic
//!   (`ContactListError`, `PowError`, …) so importing several at once
//!   stays unambiguous and side-steps the `clippy::error_impl_error`
//!   lint.
//! - For NIPs that ride on top of other NIPs (NIP-17 on NIP-59, NIP-59
//!   on NIP-44, NIP-46 on NIP-44), the dependency chain is encoded in
//!   the Cargo `[features]` graph so disabling the leaf disables
//!   everything above it.
//!
//! # Topical groups
//!
//! ## Protocol foundation
//!
//! - [`nip01`] — Spec-to-source index for the NIP-01 core (events,
//!   filters, wire messages); re-exports the canonical surface that
//!   lives in [`crate::event`], [`crate::filter`], [`crate::message`].
//!
//! ## Social events
//!
//! - [`nip02`] — Follow list (`kind 3`).
//! - [`nip09`] — Event deletion requests (`kind 5`).
//! - [`nip10`] — `e` / `p` tags inside text notes (threading).
//! - [`nip14`] — `subject` tag for `kind: 1` text notes (threaded views).
//! - [`nip18`] — Reposts (`kind 6`), generic reposts (`kind 16`), and
//!   quote-repost `q` tags.
//! - [`nip22`] — Comments (`kind 1111`).
//! - [`nip23`] — Long-form articles (`kind 30023` / draft `30024`).
//! - [`nip25`] — Reactions (`kind 7`): like / dislike / emoji /
//!   custom-emoji content with the prescribed `e` / `p` / `k` / `a`
//!   tag set.
//! - [`nip27`] — Text note references: `nostr:` URI scanner with
//!   byte-range spans and NIP-18 `q` / NIP-01 `p` implicit tag
//!   synthesis.
//! - [`nip38`] — User statuses (`kind 30315`, addressable by status
//!   type such as `general` / `music`).
//!
//! ## DNS-bound identity
//!
//! - [`nip05`] *(feature `nip05`)* — DNS-based internet identifiers
//!   `<local>@<domain>` resolved through
//!   `/.well-known/nostr.json`. The fetch surface is abstracted as
//!   the [`nip05::Nip05Fetcher`] trait; a redirect-disabled `reqwest`
//!   implementation lives behind the same feature flag.
//!
//! ## Relay-side semantics
//!
//! - [`nip11`] — Relay information document (HTTP `application/nostr+json`).
//! - [`nip42`] — Client-to-relay AUTH (`kind 22242`).
//! - [`nip65`] — Relay list metadata (`kind 10002`).
//! - [`nip70`] — Protected events (`["-"]` tag).
//!
//! ## Time, work, and lifecycle
//!
//! - [`nip13`] — Proof of work (`nonce` tag, leading-zero target).
//! - [`nip40`] — Expiration timestamp.
//!
//! ## Identifier encodings
//!
//! - [`nip19`] — bech32 entities (`npub`, `nsec`, `note`, `nprofile`,
//!   `nevent`, `naddr`).
//! - [`nip21`] — `nostr:` URI scheme wrapping every NIP-19 entity that is
//!   safe to expose in a URL (secret keys are refused).
//!
//! ## Metadata and generic conventions
//!
//! - [`nip24`] — Extra `kind: 0` fields and cross-kind tag conventions
//!   (`display_name`, `bot`, `birthday`, `r` / `i` / `title` / `t`).
//! - [`nip31`] — Human-readable `alt` fallback for unknown event kinds
//!   so `kind: 1`-centric clients still render something sensible.
//! - [`nip30`] — Custom emoji: `:shortcode:` tokens resolved through
//!   `emoji` tags. Ships both a builder ([`Tag::emoji`](crate::event::Tag::emoji))
//!   and a content scanner ([`nip30::shortcodes_in`]).
//! - [`nip39`] — External identities (`github`, `twitter`, `mastodon`,
//!   `telegram`, …) declared via `i` tags with platform-specific
//!   proofs. Forward-compatible: unknown platform names round-trip.
//!
//! ## Key derivation and delegation
//!
//! - [`nip06`] *(feature `nip06`)* — BIP-39 mnemonic + BIP-32 path
//!   `m/44'/1237'/account'/chain_type/index` → Nostr [`Keys`](crate::Keys).
//! - [`nip26`] — Delegated event signing (cold-key → hot-key
//!   authority via the `delegation` tag). Spec marks NIP-26 as
//!   `unrecommended`; we ship a complete implementation so existing
//!   on-relay corpora remain decodable.
//!
//! ## Encryption
//!
//! - [`nip04`] *(feature `nip04`)* — **Deprecated** legacy DM
//!   (AES-256-CBC over raw ECDH `X`); kept for compatibility with the
//!   existing on-relay corpus and NIP-46 backends.
//! - [`nip44`] *(feature `nip44`)* — Versioned payload encryption
//!   (`ChaCha20` + HMAC-SHA256), the modern direct-message primitive.
//! - [`nip49`] *(feature `nip49`)* — `ncryptsec`, password-protected
//!   private keys (scrypt + XChaCha20-Poly1305).
//! - [`nip59`] *(feature `nip59`)* — Gift-wrap envelope (kind 13/1059).
//! - [`nip17`] *(feature `nip17`)* — Private direct messages built on
//!   gift wraps.
//!
//! ## Remote signing
//!
//! - [`nip46`] *(feature `nip46`)* — Nostr Connect protocol primitives
//!   (request/response types, `bunker://` and `nostrconnect://` URIs).
//!
//! [Nostr Implementation Possibility]: https://github.com/nostr-protocol/nips

pub mod nip01;
pub mod nip02;
#[cfg(feature = "nip04")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip04")))]
pub mod nip04;
pub mod nip05;
#[cfg(feature = "nip06")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip06")))]
pub mod nip06;
pub mod nip09;
pub mod nip10;
pub mod nip11;
pub mod nip13;
pub mod nip14;
pub mod nip15;
#[cfg(feature = "nip17")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip17")))]
pub mod nip17;
pub mod nip18;
pub mod nip19;
pub mod nip20;
pub mod nip21;
pub mod nip22;
pub mod nip23;
pub mod nip24;
pub mod nip25;
pub mod nip26;
pub mod nip27;
pub mod nip28;
pub mod nip29;
pub mod nip30;
pub mod nip31;
pub mod nip32;
pub mod nip34;
pub mod nip35;
pub mod nip36;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip37;
pub mod nip38;
pub mod nip39;
pub mod nip40;
pub mod nip42;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip44;
pub mod nip45;
#[cfg(feature = "nip46")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip46")))]
pub mod nip46;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip47;
pub mod nip48;
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub mod nip49;
pub mod nip50;
pub mod nip51;
pub mod nip52;
pub mod nip53;
pub mod nip54;
pub mod nip56;
pub mod nip57;
pub mod nip58;
#[cfg(feature = "nip59")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip59")))]
pub mod nip59;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip60;
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub mod nip61;
pub mod nip62;
pub mod nip65;
pub mod nip66;
pub mod nip68;
pub mod nip70;
pub mod nip71;
pub mod nip72;
pub mod nip73;
pub mod nip75;
pub mod nip77;
pub mod nip78;
pub mod nip7d;
pub mod nip84;
pub mod nip86;
pub mod nip88;
pub mod nip89;
pub mod nip90;
pub mod nip92;
pub mod nip94;
pub mod nip96;
pub mod nip98;
pub mod nip99;
pub mod nipa0;
pub mod nipa4;
pub mod nipb0;
pub mod nipb7;
pub mod nipc0;
pub mod nipc7;
