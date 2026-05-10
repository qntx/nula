# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 1 W4 — identity & delegation** (`nula-core`):
  - `nips::nip05` — DNS-based internet identifiers `<local>@<domain>`.
    Two-layer architecture: a side-effect-free core (`Nip05Address`,
    `Nip05Document`, `verify_document`) that callers can drive with
    fixture JSON, plus a `Nip05Fetcher` async trait that abstracts
    the `https://<domain>/.well-known/nostr.json?name=<local>` IO.
    The trait returns a `Pin<Box<dyn Future + Send>>` so it stays
    dyn-compatible and FFI-friendly. The core is feature-flag-free —
    only the default `reqwest`-backed fetcher
    (`ReqwestNip05Fetcher`) lives behind the existing `nip05` Cargo
    feature, with `redirect::Policy::none()` enforced per NIP-05
    §"Security Constraints" so a misbehaving server cannot launder a
    different pubkey under the same identifier.
  - `nips::nip26` — Delegated event signing. Provides `Conditions`
    (typed `kind=` / `created_at>` / `created_at<` clause set with
    order-preserving `parse` / `render` so signed strings stay
    byte-identical), `delegation_message` / `delegation_hash` for
    out-of-process signers, and `sign_delegation` /
    `verify_delegation` for in-process flows. End-to-end
    `verify_event_delegation` checks the token signature *and* that
    `(kind, created_at)` matches the conditions. New typed tag
    constructor: `Tag::delegation`.
  - `nips::nip39` — External identities (GitHub / Twitter / Mastodon
    / Telegram, plus arbitrary platform names through
    `ExternalPlatform::Other(String)` for forward compatibility).
    `Identity::parse_tag_values` correctly handles compound
    identities such as Mastodon's `<instance>/@<username>`. Reader
    `identities_from_tags` skips NIP-73 external content `i` tags
    and tolerates future extra columns. New typed tag constructor:
    `Tag::external_identity`.
- **Phase 1 W3 — social core + observability** (`nula-core`):
  - New opt-in `tracing` feature wires the `tracing` crate as a
    dev-grade observability layer. The first wave instruments every
    high-frequency hot path: `Event::verify`,
    `UnsignedEvent::sign_with_keys`, `nip44::encrypt` /
    `encrypt_with_nonce` / `decrypt` / `decrypt_with_conversation_key`,
    and `Nip19Entity::from_bech32`. Every secret argument
    (`Keys`, `SecretKey`, `ConversationKey`, plaintext bytes,
    payloads) is `skip(...)`-ed so subscribers never receive
    sensitive material.
  - New `nula_core::observe` module documents the canonical
    `nostr.<subject>.<attribute>` field schema (`nostr.event.kind`,
    `nostr.encryption.plaintext_size`, `nostr.bech32.hrp`, …) so
    downstream dashboards stay query-stable across crate versions.
  - `nips::nip14` — NIP-14 `subject` tag for `kind: 1` text notes.
    Provides `subject_of(&Tags)` for reads and `reply_subject` that
    prepends a `Re:` prefix once (refusing to stack on an existing
    `Re:`/`RE:`/`re:` prefix even when the conventional space is
    missing).
  - `nips::nip18` — NIP-18 reposts. Models all three flavours: plain
    `kind: 6` reposts (`EventBuilder::repost`), `kind: 16` generic
    reposts (`EventBuilder::generic_repost`, with addressable `a` tag
    handling), and quote-repost authoring via the new `Tag::q` /
    `Tag::q_addressable`. Read helpers
    `reposted_event_{id, pubkey, kind, coordinate}` cover the
    inbound side. Honours NIP-70 protected events (empty `content`).
  - `nips::nip25` — NIP-25 reactions. Full `Reaction` enum
    (`Like` / `Dislike` / `Emoji` / `CustomEmoji`) with
    `is_positive` / `is_negative` polarity flags, `ReactionTarget`
    bundle with `from_event` auto-extracting the addressable
    coordinate, `EventBuilder::reaction` emitting the prescribed
    `e` / `p` / `k` / `a` tag set, and `target_event_id` /
    `target_pubkey` readers that honour NIP-25's "last-tag-wins"
    rule for thread-context tags.
  - Typed `Tag` constructors: `Tag::subject` (NIP-14), `Tag::q` /
    `Tag::q_addressable` (NIP-18 quote reposts).
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
