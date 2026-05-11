# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 1 W6 — lists, search, app data, monetisation & connectivity**
  (`nula-core`):
  - `nips::nip51` — Lists & sets. The `List` bundle pairs public tag
    items with NIP-44-encrypted private items inside `.content`, and
    the `ListItem` enum spans every spec-mentioned target (pubkeys,
    relays, events, coordinates, hashtags, words, threads, emojis,
    Bitcoin/Lightning relays, group references). `EventBuilder::list`
    serialises both halves; `List::from_event` reverses with optional
    signer-driven decryption (NIP-44 preferred, NIP-04 fallback).
    `event::kind` gains the full set of standard list/set kinds
    (`KIND_MUTE_LIST`, `KIND_PINNED_NOTES`, `KIND_BOOKMARKS`,
    `KIND_COMMUNITIES`, `KIND_PUBLIC_CHATS`, `KIND_BLOCKED_RELAYS`,
    `KIND_SEARCH_RELAYS`, `KIND_SIMPLE_GROUPS`,
    `KIND_INTERESTS`, `KIND_EMOJIS`, `KIND_DM_RELAYS`,
    `KIND_GOOD_WIKI_AUTHORS`, `KIND_GOOD_WIKI_RELAYS`,
    `KIND_FOLLOW_SETS`, `KIND_RELAY_SETS`, `KIND_BOOKMARK_SETS`,
    `KIND_CURATION_SETS`, `KIND_VIDEO_SETS`, `KIND_KIND_MUTE_SETS`,
    `KIND_INTEREST_SETS`, `KIND_EMOJI_SETS`,
    `KIND_RELEASE_ARTIFACT_SETS`, `KIND_APP_CURATION_SETS`,
    `KIND_CALENDAR`, `KIND_STARTER_PACKS`).
  - `nips::nip50` — Search capability. `SearchQuery` carries a
    free-text head plus a typed `Vec<SearchExtension>` covering every
    extension the spec calls out (`include:spam`, `domain:`,
    `language:`, `sentiment:`, `nsfw:`) with a forward-compatible
    `Other { key, value }` variant. `parse_token` is strict on the
    documented extensions but tolerant of unknown ones, and the
    `Filter` integration mirrors NIP-01's wire shape so search and
    classic filtering compose without copy-pasted glue.
  - `nips::nip78` — Application-specific data. The `ApplicationData`
    bundle binds `kind: 30078` to its `d`-identifier, free-form
    `.content`, and a preserved `extra_tags` vector so
    `from_event` → `to_event` round-trips never lose bespoke columns
    apps stamp on their own events. `EventBuilder::application_data`
    is the canonical builder.
  - `nips::nip94` — File metadata. `FileMetadata` covers every
    optional column from the spec (`url`, `m`, `x`, `ox`, `size`,
    `dim`, `magnet`, `i`, `blurhash`, `summary`, `alt`, `fallback`,
    `service`) plus the nested `FileVariant` shared by `thumb` and
    `image` so a hosting service can attach typed previews. The
    builder defends NIP-94's "url + x are mandatory" invariant and
    preserves unknown columns through `extra_tags`.
  - `nips::nip28` — Public chat. Typed `ChannelMetadata` (used by
    `kind: 40`/`41`) and `HideReason` (`kind: 43`) JSON content
    bundles, plus dedicated `EventBuilder` methods
    (`channel_create`, `channel_metadata`, `channel_message_root`,
    `channel_message_reply`, `hide_message`, `mute_user`) that stamp
    the `e`/`p`/`relays` tag triple the spec requires. Forward
    compatibility: unknown JSON keys round-trip through
    `extra_metadata`.
  - `nips::nip72` — Moderated communities. `CommunityDefinition`
    (`kind: 34550`) groups identifier, name, description, image,
    relay markers (`author`, `requests`, `approvals`), and moderator
    list with optional relay hints. `PostApproval` (`kind: 4550`)
    models both nested-event and address-only approvals, supports
    inline JSON copies of the approved post, and exposes
    `EventBuilder::community_post_approval`,
    `community_top_level_post`, and `community_post_reply` for the
    full posting flow.
  - `nips::nip58` — Badges. `BadgeDefinition` (`kind: 30009`),
    `BadgeAward` (`kind: 8`), and `ProfileBadges` (`kind: 30008`)
    bundles model the full triplet: definitions carry a typed
    `BadgeImage` (with optional `WxH` parsing) plus an unbounded
    thumbnail list; awards bind a coordinate + recipient pubkeys; the
    profile list pairs `(a, e)` definition/award columns into
    `ProfileBadgeEntry` records, dropping orphaned `e` columns per
    spec.
  - `nips::nip57` — Lightning Zaps. `ZapRequest` (`kind: 9734`)
    captures the spec's Appendix A invariants (`recipient`,
    `relays`, optional `amount`/`lnurl`, optional `e`/`a`/`k`
    targets) and `ZapReceipt` (`kind: 9735`) carries the LNURL
    server's `bolt11`, embedded zap-request JSON, optional
    `preimage`, and resolved `sender`. `parse_zap_split_targets`
    surfaces NIP-57.2 split tags as a typed
    `Vec<ZapSplitTarget>` with relay hint and weight. Validation
    helpers (`ZapRequest::ensure_valid`,
    `ZapReceipt::description_request`) enforce the cross-tag
    invariants the spec hands to relays/wallets.
  - `nips::nip98` — HTTP authentication. `HttpAuthRequest` models
    the ephemeral `kind: 27235` event, `HttpMethod` enum covers all
    RFC 9110 verbs plus a forward-compatible `Other`,
    `validate_against` enforces URL canonicalisation, method match,
    timestamp skew (default ±60 s), and optional
    `payload`-hash verification, and `to_authorization_header` /
    `parse_authorization_header` round-trip the spec's
    `Nostr <base64(event_json)>` representation.
  - `nips::nip47` — Nostr Wallet Connect. `ConnectionUri` parses
    `nostr+walletconnect://…` URIs (wallet pubkey, relays, secret,
    optional lud16); `InfoEvent` enumerates the wallet's advertised
    methods, notifications, and supported encryption schemes;
    `Encryption` (with `negotiate` helper) implements NIP-47.2's
    encryption negotiation (NIP-44 v2 preferred, NIP-04 fallback).
    `EventBuilder` gains `nwc_info`, `nwc_request`, `nwc_response`,
    and `nwc_notification`, and matching decrypt helpers
    (`decrypt_request`, `decrypt_response`, `decrypt_notification`)
    expose the typed JSON-RPC payloads. `ErrorCode` covers every
    spec-listed wallet error plus a forward-compatible
    `Custom(String)`.

- **Phase 1 W5 — content pipeline & long-form** (`nula-core`):
  - `nips::nip23` — Long-form content. Models the published article
    (`kind: 30023`) and its draft sibling (`kind: 30024`) through the
    `Article` bundle, which groups the spec-pinned metadata
    (`title`, `image`, `summary`, `published_at`) and the addressable
    `d`-identifier in one place. `EventBuilder::long_form_article` /
    `EventBuilder::long_form_draft` author both kinds; the reader
    `Article::from_event` reverses the mapping, refuses wrong kinds,
    and validates `published_at` parses as stringified unix
    seconds.
  - `nips::nip27` — Text note references. Differentiation vs upstream
    (which ships nothing for NIP-27): byte-range scanner
    `references_in` yielding `(Range<usize>, Nip21)` tuples in
    content order, plus `tags_from_content` synthesising the
    NIP-27 + NIP-18 implicit `p` / `q` tag bundle with
    deduplication. The scanner refuses `nostr:nsec…` bodies via the
    existing `Nip21::SecretKeyRefused` gate, so secret keys cannot
    leak through a quoted note.
  - `nips::nip30` — Custom emoji. New `Emoji` bundle plus
    `Tag::emoji` builder, `validate_shortcode` charset gate
    (`[A-Za-z0-9_-]`), `emojis_from_tags` forward-compatible reader
    that tolerates unknown extra tag columns, and `shortcodes_in`
    content scanner producing byte-offset `Range<usize>` spans for
    in-place rendering substitution.
  - `nips::nip38` — User statuses. `kind: 30315` addressable event
    modelled through the `UserStatus` bundle, `StatusType` enum
    (with forward-compatible `Custom(String)`), and `StatusLink`
    enum that surfaces the `r` / `p` / `e` / `a` tag variants the
    spec mentions. `EventBuilder::user_status` consolidates the `d`,
    link, and NIP-40 `expiration` tags into a single chained call;
    `UserStatus::from_event` reverses the mapping and surfaces the
    spec's "empty content clears the status" signal via
    `is_clear()`.
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
