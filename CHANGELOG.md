# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- **Phase 0 — Foundation** (`nula-core`):
  - Removed the legacy `std` feature. The crate is now strictly std-only,
    aligned with the v0.2 design principles. Existing callers should remove
    `default-features = false` + `features = ["std"]` and rely on the
    default feature set instead.

## [0.1.0] — 2026-04-26

Initial preview release. See git history for the audit-driven baseline.
