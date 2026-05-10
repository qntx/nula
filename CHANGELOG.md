# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 1 W2 — protocol root completion** (`nula-core`):
  - `nips::nip21` — `nostr:` URI scheme. 5-variant `Nip21` enum
    (`Pubkey` / `EventId` / `Profile` / `Event` / `Coordinate`), sealed
    `ToNostrUri` / `FromNostrUri` traits, and bidirectional conversions
    with `Nip19Entity`. Secret keys are refused by construction: the
    sealed trait set deliberately excludes `SecretKey` so
    `nostr:nsec…` URIs can never be produced by type-correct code, and
    `Nip21::parse` rejects them at runtime with
    `Nip21Error::SecretKeyRefused`.
  - `nips::nip24` — spec-indexed module for extra `kind: 0` metadata
    fields and cross-kind tag conventions. Promotes NIP-24's `bot` and
    `birthday` keys to first-class `Metadata` fields, introduces the
    `Birthday` struct with independently optional year / month / day
    (for privacy-preserving month-and-day-only publishing), and adds
    `legacy_display_name` / `legacy_username` accessors for the
    deprecated `displayName` / `username` keys (which still
    round-trip via `Metadata::custom`).
  - `nips::nip31` — spec-indexed module for `alt` fallback descriptions
    on unknown event kinds. Exposes `alt_description(&Tags)` for the
    reader side.
  - Typed `Tag` constructors covering every NIP-24 / NIP-31 tag with a
    pinned meaning: `Tag::t` (auto-lowercases per NIP-24), `Tag::r`
    (typed `&Url`), `Tag::i` / `Tag::i_with_context`, `Tag::title`,
    `Tag::alt`.
- **Phase 1 W1 — protocol baseline** (`nula-core`):
  - `nips::nip01` — spec-to-source index re-exporting the canonical
    NIP-01 surface (event, tag, filter, message, key) with the
    wire-format guarantees pinned as module-level documentation.
  - `criterion` benchmarks for every Nostr hot path: `benches/event.rs`
    (canonical hashing, signing, verifying, JSON round-trip),
    `benches/hex.rs` (encoding/decoding with SIMD confirmation),
    `benches/nip19.rs` (bech32 encode/decode across all HRPs and TLV
    bodies), `benches/nip44.rs` (v2 encrypt/decrypt and
    ConversationKey derive). First-run baseline is committed at
    `.bench/baseline-w1.md` for review-friendly week-over-week
    comparison.
- **Phase 0 — Foundation** (`nula-core`):
  - Workspace dependencies for NIP-04/06/17/44/46/49/59 primitives:
    `aes`, `cbc`, `chacha20`, `chacha20poly1305`, `hkdf`, `hmac`, `scrypt`,
    `bip39`, `base64`, `indexmap`, `zeroize`, `reqwest`.
  - Cargo features: `nip04`, `nip05`, `nip06`, `nip11-fetch`, `nip17`,
    `nip44`, `nip46`, `nip49`, `nip59`, `pow-multi-thread`. Default set:
    `["nip04", "nip06", "nip17", "nip44", "nip46", "nip49", "nip59"]`.
  - Official NIP-44 v2 test vectors at
    `crates/nula-core/tests/fixtures/nip44-vectors.json` (sourced from
    `nostr-protocol/nips`).

### Changed

- **Phase 1 W1** (`nula-core`):
  - The `nip44_vectors` integration test now declares
    `required-features = ["nip44"]` in Cargo so `cargo test
    --no-default-features` skips its build entirely instead of
    compiling an empty file that tripped `unused_crate_dependencies`
    against every dev-dependency.
- **Phase 0 — Foundation** (`nula-core`):
  - Removed the legacy `std` feature. The crate is now strictly std-only,
    aligned with the v0.2 design principles. Existing callers should remove
    `default-features = false` + `features = ["std"]` and rely on the
    default feature set instead.

## [0.1.0] — 2026-04-26

Initial preview release. See git history for the audit-driven baseline.
