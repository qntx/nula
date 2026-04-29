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
//! - [`nip02`] — Follow / contact lists (`kind 3`).
//! - [`nip09`] — Event deletion requests (`kind 5`).
//! - [`nip10`] — `e` / `p` tags inside text notes (threading).
//! - [`nip22`] — Comments (`kind 1111`).
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
//!
//! ## Key derivation
//!
//! - [`nip06`] *(feature `nip06`)* — BIP-39 mnemonic + BIP-32 path
//!   `m/44'/1237'/account'/chain_type/index` → Nostr [`Keys`](crate::Keys).
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

pub mod nip02;
#[cfg(feature = "nip04")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip04")))]
pub mod nip04;
#[cfg(feature = "nip06")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip06")))]
pub mod nip06;
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
#[cfg(feature = "nip46")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip46")))]
pub mod nip46;
#[cfg(feature = "nip49")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip49")))]
pub mod nip49;
#[cfg(feature = "nip59")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip59")))]
pub mod nip59;
pub mod nip65;
pub mod nip70;
