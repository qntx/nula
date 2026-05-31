# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Workspace crate consolidation (17 → 9 crates).** The
  rust-nostr-style fan-out of single-purpose crates is collapsed into
  cohesive, feature-gated crates following Rust 2024 conventions:
  - **Storage (5 → 1):** `nula-storage-memory`, `nula-storage-lmdb`,
    `nula-storage-sqlite`, and `nula-storage-test-suite` are folded
    into `nula-storage` as the feature-gated modules
    `nula_storage::{memory, lmdb, sqlite, test_suite}` (default
    `memory`; the persistent backends pull their C deps only when
    enabled).
  - **Relay (4 → 1):** `nula-net`, `nula-relay-pool`, and
    `nula-relay-builder` are folded into `nula-relay` as
    `nula_relay::{transport, pool, server}` (transport always on;
    `pool` default; `server` opt-in).
  - **Signer:** `nula-signer-connect` is renamed to `nula-signer`.
  - **Core:** the `BoxFuture` / `BoxStream` async aliases move to
    `nula_core::boxed` (re-exported at the crate root) as the single
    canonical home for the workspace's async seams.

  **BREAKING CHANGE:** the removed crates no longer exist. Migrate
  imports to the new module paths
  (`nula_storage::memory::MemoryDatabase`,
  `nula_relay::pool::RelayPool`, `nula_relay::server::MockRelayBuilder`,
  `nula_relay::transport::WebSocketTransport`, `nula_signer::*`,
  `nula_core::BoxFuture`) and depend on the parent crate with the
  matching feature.

### Added

- **`nula-nwc` — NIP-47 Nostr Wallet Connect client (new crate).** Drives
  a remote Lightning wallet service over encrypted DMs on top of
  `nula_relay::pool::RelayPool`. A single dispatcher actor subscribes to
  `kind:23195` responses / `kind:23197`/`23196` notifications, decrypts
  each body, and correlates responses to requests through the response's
  `e` tag. Ships typed helpers (`pay_invoice`, `pay_keysend`,
  `get_balance`, `get_info`, `make_invoice`, `lookup_invoice`,
  `list_transactions`), a generic `send_request`, a notification
  broadcast stream, `get_info_event` capability discovery, and an
  embedded/external pool mode. Now covers the full upstream `nwc` typed
  method surface. End-to-end tested against an in-process mock wallet
  over `MockRelay`.
- **`nula-blossom` — Blossom blob-transport client (new crate).**
  Implements the BUD-01/02 HTTP surface (`upload`, `download`, `has`,
  `delete`, `list`) with NIP-24242 (`kind:24242`) authorization events
  signed by any `nula_core::NostrSigner` (local `Keys` or a remote
  bunker). `download` verifies blob integrity against the requested
  sha256. `upload_to_all` / `download_any` bridge the NIP-B7 discovery
  side (`BlossomServerList`) with the transport side — closing the
  "two halves" gap where `nula-core` had NIP-B7 and upstream had the
  HTTP transport. HTTP paths are tested against a `wiremock` mock server.
- **NIP-46 bunker side in `nula-signer`** (`nula_signer::bunker`). The
  new `NostrConnectRemoteSigner` listens on a relay set, decrypts
  `kind:24133` requests, dispatches them against `NostrConnectKeys`
  (separate transport vs signing keys), and publishes encrypted
  responses; `bunker_uri()` advertises the session and a `BunkerPolicy`
  hook gates every non-`connect` request. Closes the bunker reverse gap
  (`nula-signer` was previously client-only). Verified by a real
  `NostrConnect` ↔ `NostrConnectRemoteSigner` round trip over `MockRelay`.
- **NIP-15 Marketplace types** (`nula_core::nips::nip15`): typed
  `StallData` / `ProductData` / `AuctionData` (auction support is absent
  upstream) with `to_event_builder` + `from_event`, plus the order /
  payment-request / payment-verification DM payloads. The product event
  is addressed by the **product** id per the spec (fixing the upstream
  `stall_id` deviation), and order items use the spec field `product_id`.
- **NIP-35 Torrents types** (`nula_core::nips::nip35`): a validated
  `TorrentInfoHash`, `TorrentFile`, and `Torrent` with both
  `to_event_builder` and a `from_event` parser (upstream ships only the
  builder), an `EventBuilder::torrent_comment` helper, and lossless
  preservation of non-`tcat:` external references.
- **Typed `Tags` extractors + `dedup`** (`nula_core`): `public_keys`,
  `event_ids`, `coordinates`, `hashtags`, `expiration`, and `challenge`
  accessors, plus a `Tags::dedup` mirroring the upstream longest-wins
  policy.
- **`Filter::fingerprint` → `FilterKey`** (`nula_core`): an
  order-independent, hashable/orderable identity key for a `Filter`
  (which deliberately stays insertion-ordered on the wire and therefore
  implements neither `Hash` nor `Ord`), for deduplicating subscriptions
  or keying a cache.
- **Lazy single-letter `Tags` index** (`nula_core`): `Tags` builds and
  caches a `TagsIndexes` (`BTreeMap<SingleLetterTag, BTreeSet<String>>`)
  on first `Tags::indexes()` call, mirroring rust-nostr.
  `Filter::match_event` now matches `#<letter>` constraints through the
  index, so checking one event against many filters costs a single index
  build instead of a full tag scan per filter. The cache is invalidated
  by every mutator and excluded from equality, hashing, `Debug` and
  serialization (the wire form stays byte-identical, preserving event
  IDs); it is boxed behind a `OnceLock` to keep `Event`'s footprint
  minimal while staying `Send + Sync`. Adds a `Tag::single_letter_tag()`
  accessor.
- **`NostrSigner` is now `wasm32`-ready** (`nula_core::signer`):
  `SignerFuture` and `boxed_signer_future` drop the `Send` bound on
  `wasm32` (mirroring `nula_core::boxed::BoxFuture`), since NIP-07
  browser signers return `!Send` `JsFuture`s. Non-wasm targets are
  unchanged (`Send` retained). This unblocks an out-of-tree NIP-07
  `window.nostr` signer crate without touching the trait's `Send + Sync`
  bound (a stateless browser signer stays `Send + Sync`).

- **Phase 8 — `nula-cli` private messages + relay lists.** The
  `nula` binary gains two subcommand groups wrapping the Phase
  7.4 / 7.5 SDK facades:
  - **`nula dm send`** — gift-wrap (NIP-17) a private message to
    one or more `--to` recipients and publish every wrap. Emits
    `{ "kind": "dm_sent", "wrap_ids": [...], "success": [...],
    "failed": [...] }`.
  - **`nula dm recv`** — fetch kind-1059 wraps addressed to the
    caller, decrypt the inner rumors, and emit
    `{ "kind": "dm_received", "count": N, "messages": [...] }`
    with each message's `sender`, `created_at`, `rumor_kind`, and
    `content`. Honours `--since`.
  - **`nula relays set`** — compose a NIP-65 relay list from
    `--read` / `--write` / `--both` flags, sign the kind-10002
    event, and publish it.
  - **`nula relays get`** — fetch + parse a peer's relay list by
    `--pubkey`, emitting the read / write / full breakdown.
  - **Shared key parsing** — `parse_secret` / `parse_public_key`
    hoisted into `commands/mod.rs` and reused by `event`, `dm`,
    and `relays`.
  - **4 new e2e CLI tests** (`dm_send_then_recv_round_trip`,
    `relays_set_then_get_round_trip`, `dm_send_requires_to_flag`,
    `relays_set_requires_at_least_one_relay_entry`) bring the CLI
    suite to 11.

### Fixed

- **`nula-relay` pool `translate()` tripped `unreachable_pattern` /
  `unnecessary_wraps` under partial feature sets** (e.g. when built as a
  dependency with `nip42` off). The `RelayNotification` match now handles
  `AuthChallenge` explicitly under `#[cfg(feature = "nip42")]` (instead of
  a wildcard) and scopes an `unnecessary_wraps` allow to the
  `nip42`-disabled config, so per-crate `clippy -D warnings` passes in
  every feature combination.
- **`nula-sdk` failed to compile without the `sync` feature.**
  `Client::try_connect_relay` mapped connect timeouts to the
  `sync`-gated `Error::SyncStreamClosed` variant, so any build
  that did not enable `sync` (e.g. `nula-cli`, which only turns
  on `memory-fallback` + `default-transport`) failed to compile.
  The timeout now maps to a new, non-gated
  `Error::ConnectTimeout { url }`, which is also the semantically
  correct error (the previous variant claimed a NIP-77 stream had
  closed). Regression-tested via
  `try_connect_relay_times_out_with_connect_timeout_error` and the
  no-default-features build.
- **`nula-sdk` relied on incidental feature unification for
  `nula-core/nip17`.** The `nips::nip17` / `nips::nip65` facades
  reference `nula-core`'s gift-wrap helpers unconditionally, but
  the dependency only enabled them by accident through other
  crates in the default build graph. `nula-sdk` now declares
  `nula-core = { features = ["nip17"] }` explicitly (which pulls
  `nip44` + `nip59`), so every feature combination builds.

- **Phase 7.5 — NIP-65 relay-list helpers + gossip refresh on
  `Client`.** New `nula_sdk::nips::nip65` module wires
  `nula_core::nips::nip65` (kind-10002 `RELAY_LIST` codec,
  `RelayList` / `RelayMarker` types) to the SDK facade:
  - **`Client::set_relay_list(list: &RelayList) -> Output<EventId>`**
    signs the kind-10002 event, broadcasts it, and -- when the
    `gossip` feature is on and a `Gossip` is wired -- feeds the
    freshly-built event into `Gossip::process` so the routing
    graph reflects the new list immediately, without a refetch.
  - **`Client::get_relay_list(pubkey, timeout) -> Option<RelayList>`**
    fetches the latest kind-10002 for `pubkey` and parses it.
    `Ok(None)` when nothing was published; `Error::Nip65` on a
    malformed event (wrong kind, bad url, unknown marker).
  - **`Client::refresh_relay_metadata(pubkeys, timeout) -> usize`**
    (`gossip`-only) re-fetches every relay-routing-relevant list
    (kind 10002 NIP-65 + kind 10050 NIP-17) for the supplied
    pubkeys and pushes every result through `Gossip::process`.
    Returns the number of events successfully ingested. Per-event
    fetch failures are silently aggregated -- a partial refresh
    is strictly better than an aborted one.
  - **`RelayList` / `RelayMarker` / `RelayListError`** are
    re-exported from `nula_sdk::nips::nip65`, so callers writing
    `client.set_relay_list(&list)` only need a single use.
  - **New `Error::Nip65(RelayListError)`** variant.
  - **3 new integration tests**
    (`nip65_set_and_get_relay_list_round_trip`,
    `nip65_get_relay_list_returns_none_when_unpublished`,
    `nip65_refresh_relay_metadata_drives_gossip_routing`).

- **Phase 7.4 — NIP-17 private direct messages on `Client`.** New
  `nula_sdk::nips::nip17` module wires the wire-level helpers
  from `nula_core::nips::nip17` (kind-14 rumor + NIP-59 gift wrap
  + kind-10050 DM-relays list) to the SDK facade:
  - **`Client::send_private_msg(sender_keys, recipients, message,
    reply_to)`** — builds the unsigned chat-message rumor,
    delegates to `wrap_for_many` to produce one gift wrap per
    recipient + one self-wrap, and ships every wrap through the
    pool. Returns `Output<Vec<EventId>>` -- the outer wrap ids in
    emission order plus the merged per-relay accept / reject
    aggregates.
  - **`Client::send_private_msg_to(urls, …)`** — same pipeline
    restricted to a caller-chosen relay subset.
  - **`Client::receive_private_msgs(receiver_keys, since,
    timeout) -> Vec<ReceivedPrivateMsg>`** — pulls every kind-1059
    gift wrap addressed to `receiver_keys`'s public key, drops
    unreadable wraps silently per NIP-17, and surfaces the
    decrypted unsigned rumor plus the outer envelope coordinates
    (`wrap_id`, `wrap_pubkey`, `wrap_created_at`).
  - **`Client::set_dm_relays(relays)` /
    `Client::get_dm_relays(pubkey, timeout) -> Option<Vec<RelayUrl>>`**
    — publish / fetch the kind-10050 DM-relays advertisement.
    `set_dm_relays` reuses the existing
    `Client::sign_event_builder` + `send_event` chain; the getter
    queries by author + kind + limit 1.
  - **`ReceivedPrivateMsg`** struct re-exported at the crate
    root.
  - **New `Error::Nip17(Nip17Error)`** variant for forwarded
    NIP-17 / NIP-59 / NIP-44 failures.
  - **Design decision on signers**: the helpers take `&Keys`
    explicitly rather than going through the configured signer.
    NIP-59 sealing needs both Schnorr signing *and* NIP-44 ECDH
    secret access, which the dyn-safe `NostrSigner` trait does
    not surface as a single sync handle. Local-keypair callers
    pay no extra cost (they already have the `Keys`); NIP-46 /
    hardware signers cannot perform NIP-17 today, period -- the
    spec gap is upstream.
  - **3 new integration tests** (`nip17_round_trip_alice_to_bob_via_mock_relay`,
    `nip17_send_private_msg_rejects_empty_recipients`,
    `nip17_set_and_get_dm_relays_round_trip`).

- **Phase 7.3.7 — Client-side `AdmitPolicy` middleware.** New
  `nula_sdk::policy` module + crate-root re-exports
  (`AdmitPolicy`, `AdmitStatus`, `PolicyError`):
  - **Trait surface mirrors upstream `nostr-sdk::AdmitPolicy`** —
    `admit_relay`, `admit_connection`, `admit_event`. Every method
    has a `Success` default; users override only the gates they
    care about. Futures are boxed via `nula_net::BoxFuture` for
    object safety.
  - **`ClientBuilder::admit_policy(impl Into<Arc<dyn AdmitPolicy>>)`**
    installs the policy. When a policy is configured the SDK
    automatically forces `auto_save_events = false` on the
    underlying pool so the persistence fast-path can no longer
    bypass `admit_event`.
  - **Wired gates**:
    - `Client::add_relay_with_capabilities` (and every
      capability-specific `add_*_relay` helper that delegates to
      it) runs `admit_relay`.
    - `Client::connect_relay` / `try_connect_relay` runs
      `admit_connection`.
    - `Client::sync_to_relay` download phase runs `admit_event`
      *before* `database.save_event`. Rejected events are
      surfaced on `SyncSummary::rejected_by_policy`
      (`HashMap<EventId, Option<String>>`) and never persist.
  - **Read accessors** — `Client::admit_policy()` returns the
    installed `Arc<dyn AdmitPolicy>` (or `None`); the public
    `Client::check_admit_event` helper lets callers consuming raw
    subscription / fetch streams reuse the same gate.
  - **New `Error` variants** — `Error::PolicyRejected { stage,
    reason }` (where `stage` is `"relay"` / `"connection"` /
    `"event"`) and `Error::Policy(PolicyError)` for backend
    errors.

- **Phase 7.3 — SDK API ergonomics + monitor + subscription
  registry.** New `Client` surface for parity with upstream
  `nostr-sdk::Client`:
  - **`Monitor` + `MonitorNotification::StatusChanged`** —
    opt-in (`ClientBuilder::monitor()` /
    `monitor_with_capacity(n)`) broadcast of every relay's
    `RelayStatus` transition. Backed by a `tokio::broadcast`
    channel; multiple subscribers see the same frames.
  - **`Client::subscriptions()` / `subscription(id)` /
    `unsubscribe_all()`** — read the registry of every active
    subscription (id → relay set + filters) maintained by the
    SDK layer. `subscribe*` paths now insert; `unsubscribe`
    removes; `unsubscribe_all` fans out + drains.
  - **`Client::wait_for_connection(timeout)`** — block until
    every registered relay reaches `RelayStatus::Connected` or
    `timeout` elapses. Listens on the pool's notification
    channel for prompt wake-ups.
  - **`Client::send_msg(ClientMessage)`** — pool-level fan-out
    of an arbitrary `ClientMessage`; mirrors the per-relay
    `Relay::send_msg`.
  - **Capability convenience methods** —
    `add_discovery_relay`, `add_read_relay`,
    `add_write_relay`, `add_gossip_relay`. New
    `RelayCapabilities::GOSSIP` bit distinguishes user-pinned
    NIP-65 routing relays from peer-listed ones (`DISCOVERY`).
  - **Per-relay control** — `connect_relay(url)`,
    `try_connect_relay(url, timeout)`,
    `disconnect_relay(url)`. Typed `Error::UnknownRelay` when
    `url` is not in the pool.
  - **Bulk removal** — `remove_all_relays()`,
    `force_remove_all_relays()`.
- **Phase 7.2.3 — gossip persistence delegated to storage
  backends.** `nula-gossip` already wrote every ingested
  NIP-65 / NIP-17 event back through its configured
  `NostrDatabase`; this phase made that contract first-class:
  - Crate-level "Persistence" doc section documents the design
    decision (no dedicated `nula-gossip-sqlite` crate -- pick the
    backend you use for events and gossip inherits its durability
    story).
  - New integration test
    `crates/nula-gossip/tests/persistence.rs`:
    `warm_up_rehydrates_routes_from_sqlite_after_restart` --
    ingest an NIP-65 list against a `SqliteDatabase`-backed
    gossip, drop the whole handle stack, reopen the same SQLite
    file, build a fresh gossip handle, call `warm_up`, and assert
    the outbox / inbox come back from disk.
- **Phase 7.2.2 — `nula-keyring` crate.** New
  publish-on-crates.io crate persisting `nula-core::Keys` in the
  operating system's native secret store:
  - macOS Keychain (via `keyring` `apple-native`)
  - Linux Secret Service over D-Bus (via `linux-native` with
    `linux-native-sync-persistent` headless fallback)
  - Windows Credential Manager (via `windows-native`)

  Public surface:
  - **`Keyring::new(service)`** — scope every entry to a single
    reverse-domain service identifier.
  - **`Keyring::{set, get, delete}`** — async APIs, running the
    blocking native calls on tokio's blocking pool.
  - **`Keyring::{set_blocking, get_blocking, delete_blocking}`**
    — sync siblings for CLI / system tray call sites.
  - `delete` is idempotent (`NoEntry` normalised to `Ok`).
  - Typed errors: `Keyring(keyring::Error)`,
    `InvalidSecret(SecretKeyError)`, `Join(JoinError)`.
- **Phase 7.2.1 — `nula-storage-sqlite` crate.** New
  publish-on-crates.io backend implementing
  `nula_storage::NostrDatabase` on top of a vendored SQLite file
  (durable append-only event log) paired with an in-process
  `nula_storage_memory::MemoryDatabase` for the hot read path. On
  startup the backend replays every stored record through the
  memory replica, so every NIP-09 / NIP-40 / NIP-62 / replaceable
  / addressable rule the memory crate already enforces also
  governs the SQLite store.
  - **`SqliteDatabase::open(path)`** — open / create a SQLite
    file. The parent directory is `mkdir -p`'d on demand.
  - **`SqliteDatabase::open_in_memory()`** — `:memory:` database
    for tests; data vanishes with the handle.
  - **`Backend::Sqlite`** added to the storage feature enum.
  - Vendored SQLite via `rusqlite/bundled` by default (toggle off
    via `default-features = false` to link against the system
    SQLite).
  - Conformance: passes the full `nula-storage-test-suite` and
    adds three SQLite-specific durability tests
    (`events_survive_a_reopen`, `wipe_persists_across_reopen`,
    `in_memory_database_does_not_persist`).
- **Phase 7.1 — full Up/Down/Both NIP-77 sync semantics.** The
  `Client::sync_to_relay` reconciliation driver now also performs
  the actual event exchange the protocol's `(have, need)` split
  implies:
  - **`SyncDirection { Up, Down, Both }`** — direction of the
    desired exchange. Default is `Down` (pull relay-only events
    into the local database).
  - **`SyncSummary { local, remote, sent, received,
    send_failures }`** — observable side effects per call. `local`
    / `remote` survive even on `dry_run`; `sent` /
    `received` / `send_failures` populate during the upload /
    download phases.
  - **`SyncProgress { total, current }` + `SyncOptions::with_progress(watch::Sender)`**
    — streaming progress watch channel. The reconciliation loop
    bumps `total` each round; the upload / download loops bump
    `current` per processed event.
  - **`SyncOptions::dry_run(true)`** — skip the upload + download
    phases entirely; only the reconciliation summary survives.
  - **`Client::sync_with(urls, filter, opts)`** — pool-level
    fan-out that runs `sync_to_relay` against each url and merges
    the per-relay summaries.
- **Phase 6.6 — NIP-77 client driver and fuzz workspace upgrade.**
  - **`Relay::send_msg(ClientMessage)`** — actor command + public
    API on `nula-relay::Relay` for shipping arbitrary
    `ClientMessage` variants over the live socket. Used by the new
    NIP-77 driver to emit `NegMsg` / `NegClose` frames.
  - **`Relay::subscribe_neg(id, filter, initial_message_hex)`**
    — opens a NIP-77 reconciliation session as a regular
    subscription whose outbound frame is `["NEG-OPEN", id, filter,
    initial_hex]` instead of `["REQ", …]`. The returned
    `SubscriptionHandle` yields the new
    `SubscriptionItem::NegMsg` / `SubscriptionItem::NegErr`
    variants. Sessions are not re-issued on reconnect (the
    Negentropy state machine cannot resume across a fresh socket).
  - **`Client::sync_to_relay(relay_url, filter, timeout)`** —
    Layer-5 NIP-77 driver in `nula-sdk` that:
    1. sources local `(EventId, Timestamp)` pairs from the
       configured database,
    2. opens a session via `Relay::subscribe_neg`,
    3. folds each `NegMsg` reply through
       `nula_sync::Reconciliation::reconcile_hex` and ships the
       next `NegMsg` via `Relay::send_msg`,
    4. returns a typed `SyncOutput { have, need }` describing the
       per-side delta.
    Adds `Error::UnknownRelay`, `Error::SyncFailed`, and
    `Error::SyncStreamClosed` variants.
  - **`ClientBuilder::database_arc(Arc<dyn NostrDatabase>)`** —
    sibling of `signer_arc` for sharing the database between the
    client and external callers (test seeders, background
    workers).
  - **`MockRelayBuilder` learned NIP-77.** `nula-relay-builder`
    now drives a per-subscription `nula_sync::Responder`,
    handling `NegOpen` / `NegMsg` / `NegClose` frames and
    emitting structured `NegErr` reasons (NIP-20 prefixed) for
    every failure path. Pulls `nula-sync = { features =
    ["storage"] }` as a runtime dep.
  - **`nula-fuzz` moved to `crates/nula-fuzz`** — explicit
    `[workspace] exclude = ["crates/nula-fuzz"]` keeps the
    cargo-fuzz nightly RUSTFLAGS isolated, but the source now
    lives alongside every other workspace crate. New harnesses:
    `nip77_payload_decode` (decoder is total + round-trip
    property), `client_message_parse` /
    `relay_message_parse` (Serialize/Deserialize symmetry).
- **Phase 6.5 — `nula-cli` binary crate.** New publish-on-crates.io
  crate that ships a single `nula` binary wrapping `nula-sdk` and
  `nula-relay-builder`. Subcommands:
  - **`nula keys generate`** — OS-RNG keypair, prints `nsec` /
    `npub` / hex as a stable-shape JSON object.
  - **`nula keys parse <INPUT>`** — accepts `nsec1...` /
    `npub1...` / 64-char hex; dumps every other form.
  - **`nula relay run [--bind ADDR]`** — start an in-process mock
    relay via `nula-relay-builder::MockRelayBuilder`; emits the
    listening URL and blocks until `Ctrl-C`.
  - **`nula event publish --relay URL [--relay URL ...] --secret
    NSEC|HEX --content TEXT [--content-file PATH | -] [--kind N]
    [--timeout SECS]`** — signs a kind-N event and ships it to
    every relay; exits non-zero when every relay rejected the
    publish. The `--secret` flag also reads `$NULA_SECRET`
    (hidden from `--help` output to avoid leaking secrets into
    process listings).
  - **`nula event fetch --relay URL [--relay URL ...] [--author
    NPUB|HEX]... [--kind N]... [--limit N] [--since UNIX]
    [--until UNIX] [--timeout SECS]`** — one-shot `REQ` against
    the relay set, prints the deduplicated `Events` array.
  - Every subcommand emits exactly one JSON object on `stdout`
    (pretty-printed; `jq -c .` for compact); tracing logs go to
    `stderr` under `RUST_LOG` (default `info`).
- **CLI integration tests (`tests/cli.rs`, 7 cases)** — driven via
  `assert_cmd`: `keys generate` JSON shape, `keys parse` round
  trip (nsec / npub variants + garbage-input failure), `event
  publish` / `event fetch` flag requirements, and a full
  publish + fetch round-trip against an in-process
  `MockRelayBuilder`-spawned relay.
- **Workspace dependency additions** — `clap = "4.6"` (derive +
  env + wrap_help), `anyhow = "1.0"`, `tracing-subscriber = "0.3"`,
  plus `assert_cmd = "2.0"` / `predicates = "3.1"` for CLI tests.
- **Phase 6.4 — Layer-5 SDK facade (`nula-sdk` crate).** New
  publish-on-crates.io crate that composes Layer 1-4 into a single
  `Client` + `ClientBuilder` modelled on the upstream
  `nostr_sdk::Client`. Surface:
  - **Lifecycle & getters** — `new`, `builder`, `pool`, `signer`,
    `database`, `gossip` (feature `gossip`), `is_shutdown`,
    `shutdown`, `notifications`, `automatic_authentication`.
  - **Relay management** — `add_relay`,
    `add_relay_with_capabilities`, `remove_relay`,
    `force_remove_relay`, `relay`, `relays`, `connect`,
    `try_connect`, `disconnect`. All `add_*` variants accept any
    `impl IntoRelayUrl` (`&str`, `String`, `&RelayUrl`,
    `RelayUrl`).
  - **Publishing & signing** — `sign_event_builder`, `send_event`,
    `send_event_to`, `send_event_builder`,
    `send_event_builder_to`. `send_*_to` accept any
    `IntoIterator<Item = impl IntoRelayUrl>`.
  - **Fetching & streaming** — `fetch_events`,
    `fetch_events_from`, `stream_events`, `stream_events_from`
    (`close_on_eose` baked in; multi-relay dedup via
    `RelayPoolOptions::dedup_cache_size`).
  - **Subscriptions** — `subscribe`, `subscribe_with_id`,
    `subscribe_to`, `unsubscribe`.
  - **`ClientBuilder` setters (10)** — `signer`, `signer_arc`,
    `database`, `gossip` (feature `gossip`),
    `websocket_transport`, `pool_options`,
    `automatic_authentication`, `build()`.
  - **Feature flags (defaults on the right)** — `gossip` ✅,
    `sync` ✅, `memory-fallback` ✅, `default-transport` ✅,
    `nip46` ❌, `tracing` ❌.
  - **Error surface** — typed `#[non_exhaustive]` enum wrapping
    `nula_relay_pool::Error`, `nula_relay::Error`,
    `nula_core::event::EventBuilderError`,
    `nula_core::signer::SignerError`,
    `nula_core::message::SubscriptionIdError`,
    `nula_core::types::RelayUrlError`, `nula_gossip::Error`
    (feature `gossip`), `nula_sync::Error` /
    `nula_storage::Error` (feature `sync`), and a typed
    `SignerNotConfigured` variant.
  - **Tests** — 5 unit (`IntoRelayUrl` + `collect_relay_urls`
    cases) + 5 integration (`add_relay` parse path, signer-not-
    configured, end-to-end publish + fetch against
    `MockRelayBuilder`, subscribe + unsubscribe round trip,
    unparseable url error path) + 1 quickstart doctest. Workspace
    total: 1121 → 1128.
- **ADR-0011** records the public-surface decisions, the
  deliberate departures from `nostr_sdk::Client` (no fluent
  builder return types, no deprecated `add_*_relay` shorthands, no
  `wait_for_connection`), and the deferred surface (`Client::sync`
  waits on a future `Relay::send_msg` API; NIP-17 DM helpers and
  NIP-65 outbox helpers ship in a later phase as additive
  `nula-sdk::nips::*` modules).
- **Phase 6.2 — NIP-77 Negentropy sync (`nula-sync` crate).** New
  Layer-3 crate that wraps the upstream
  [`negentropy = "0.5"`](https://crates.io/crates/negentropy) state
  machine in two role-specific session types plus a storage adapter:
  - `Reconciliation` — initiator session. `with_defaults(storage)` /
    `initiate(storage, frame_size_limit)` produce the opening
    message; `reconcile(query)` / `reconcile_hex(query_hex)` fold
    each peer reply into a `ReconcileOutcome { have, need,
    next_message }`.
  - `Responder` — non-initiator session, symmetric API for the
    relay / mock side.
  - `prepare_storage(items)` — sealed `NegentropyStorageVector`
    builder for `impl IntoIterator<Item = (EventId, Timestamp)>`.
  - `storage` feature: `from_database(&dyn NostrDatabase, filter)`
    bridges `nula_storage::NostrDatabase::negentropy_items` into a
    session-ready storage.
  - `tracing` feature placeholder reserved for the upcoming
    span-instrumented SDK loop.
  - 10 tests total (9 unit + 1 doctest), including a two-replica
    `MemoryDatabase` convergence end-to-end test.
- **NIP-77 wire messages in `nula-core`.** Three new
  `ClientMessage` variants (`NegOpen`, `NegMsg`, `NegClose`) and two
  new `RelayMessage` variants (`NegMsg`, `NegErr`) with full
  `serde` codec + 9 round-trip tests. Both enums are
  `#[non_exhaustive]` so this is **additive only** for downstream
  pattern matches that follow the workspace convention.
- **ADR-0010** records why Negentropy lives in its own crate rather
  than inside `nula-core` or `nula-relay-pool`.
- **Phase 6.3 — `nula-storage-test-suite` (publish = false).** New
  workspace crate that ships a reusable conformance suite any
  `NostrDatabase` backend can run against itself:
  - `DatabaseFactory` trait with an `async fn build()` returning
    `(Arc<dyn NostrDatabase>, Self::Guard)`. Backends that hold
    out-of-process state (LMDB's `TempDir`) hand the guard back; the
    suite drops it between cases.
  - 23 cases across five modules — `save_event`, `query_filters`,
    `nip09_deletion`, `replaceable`, `concurrency` — covering
    duplicate / ephemeral / expired / replaced semantics, every
    `QueryPattern` shape, NIP-09 tombstone semantics, and concurrent
    multi-writer safety (8 writers × 16 events).
  - Per-category helpers (`run_save_path`, `run_query_path`,
    `run_nip09`, `run_replaceable`, `run_concurrency`) for backends
    that want partial coverage.
  - `nula-storage-memory` and `nula-storage-lmdb` now declare
    `nula-storage-test-suite` as a dev-dependency and replace ~1 KLOC
    of duplicated integration tests with a single `tests/suite.rs`
    that runs the full suite. Backend-specific edge cases
    (`memory/tests/capacity.rs`, `lmdb/tests/persistence.rs`) stay
    where they belong.

### Changed

- **Phase 6.1 — Layer 4 builder API convergence (breaking).** Every
  Layer 3-4 `*Builder::build()` that previously `panic!`-ed on a
  missing required input now returns `Result<_, Error>` with a typed
  `MissingFoo` variant. Callers must add `?` or `.expect(...)` at the
  call site; the panics they were silently relying on are gone. The
  exact shape:
  - `nula_relay::RelayBuilder::build` → `Result<Relay, Error>` with a
    new `Error::MissingTransport` variant. `nula_relay::Relay::new`
    (gated on `default-transport`) keeps its infallible signature by
    bypassing the builder and constructing
    `nula_net::default::DefaultTransport` directly.
  - `nula_relay_pool::RelayPoolBuilder::build` →
    `Result<RelayPool, Error>` with two new variants
    `Error::MissingDatabase` and `Error::MissingTransport`.
  - `nula_gossip::GossipBuilder::build` → `Result<Gossip, Error>`
    with a new `Error::MissingDatabase` variant.
  - `nula_signer_connect::NostrConnectBuilder::build` keeps its
    existing `Result` return shape but the two `panic!`-ed
    branches now surface as `Error::MissingUri` and
    `Error::MissingPool`.
  - Four new regression tests cover each of the new error paths
    (`crates/{nula-relay-pool,nula-gossip,nula-signer-connect}/tests/builder.rs`).

### Added

- **Phase 5 — multi-relay routing & remote signer (Layer 4 completion).**
  Two new workspace crates plus a Phase-4 relay-builder follow-up
  bring the workspace to feature parity with the upstream
  `rust-nostr` Layer-4 stack.
  - `nula-gossip` (new crate, Layer 4): NIP-65 outbox/inbox routing,
    NIP-17 DM-relay tracking, hint and most-received histograms,
    `BrokenDownFilters` tri-state filter break-down (`PerRelay` /
    `Orphan` / `Generic`), `AllowedRelays` policy gate (onion /
    local / no-tls toggles), `GossipLimits` per-bucket caps,
    `GossipBuilder` fluent constructor, `Gossip::warm_up` for cache
    rehydration from `NostrDatabase`, and a `RefresherHandle`-driven
    background tokio task that re-pulls outdated NIP-65 / NIP-17
    lists on a configurable cadence.
  - `nula-signer-connect` (new crate, Layer 4): NIP-46 (Nostr
    Connect) remote signer client. Supports both `bunker://` and
    `nostrconnect://` URIs (with mandatory secret-echo verification
    on the latter), all nine NIP-46 RPCs (`connect`,
    `get_public_key`, `sign_event`, `nip04_*`, `nip44_*`, `ping`,
    `switch_relays`), pluggable `AuthUrlHandler` trait + default
    `RejectAuthUrl`, dual `PoolMode` (external `Arc<RelayPool>` or
    embedded mini-pool), and an object-safe
    `nula_core::NostrSigner` impl so the client drops straight into
    any `Arc<dyn NostrSigner>` slot.
  - `nula-relay-builder` (Phase 4 follow-up): every connection
    actor now consumes a relay-wide `tokio::sync::broadcast<Event>`
    and forwards each accepted event to every active subscription
    whose filter matches via `Filter::match_event`. Ephemeral kinds
    (NIP-01 20000–<30000, including `kind:24133` / NIP-46) ACK with
    `OK true` and broadcast to live subscribers without
    persisting — matching the spec's broadcast-but-do-not-store
    semantics.
- **ADR-0009**: documents the routing / remote-signer architecture
  (concrete `Gossip` struct vs. trait, dual pool mode, dispatcher
  actor, secret-echo gate, NIP-46 RPC error mapping).

### Fixed

- **Feature gating** (`nula-core`):
  - `limits.rs` unconditionally re-exported `nips::nip49::{MAX_LOG_N,
    NONCE_BYTES, SALT_BYTES}` even though the `nip49` module is
    feature-gated. Building `nula-core` with any feature subset that
    excluded `nip49` (notably `--no-default-features`) failed.
    Resolution: gate the three re-exports plus the matching drift
    assertions in `tests::pinned_values_match_spec` behind
    `#[cfg(feature = "nip49")]`. This unblocks `nula-net`'s
    trait-only build, which depends on `nula-core` with default
    features off.
  - `nips::nip98` (HTTP Auth) unconditionally referenced `base64::Engine`
    but `base64` was an optional dependency pulled in only via the
    `nip04` / `nip44` features. Any feature subset lacking either
    failed to compile (e.g. `cargo check --features nip49`). Resolution:
    promote `base64` to a non-optional workspace dependency.
  - `nips::nip06` (BIP-39 derivation) uses `hmac::Hmac<Sha512>`
    internally but the `nip06` feature only declared `dep:bip39`,
    omitting `dep:hmac`. Building with `--features nip06` alone
    failed. Resolution: list `dep:hmac` explicitly on the `nip06`
    feature (it stays optional and is also pulled in by `nip44`).
  - `nips::nip51` carried dead-code warnings under feature subsets
    without `nip44` (the `SecretKey` import plus the
    `serialize_items` / `deserialize_items` / `CustomError` items
    are only used by encrypted-list helpers). Resolution: gate them
    with `#[cfg(feature = "nip44")]`.

- **Documentation** (`nula-core`):
  - All 31 rustdoc unresolved-link / redundant-target warnings
    cleared. Categories: stale `Self::xxx` references in module-level
    docs replaced with concrete type paths (`nip78` / `nip94` / `nip98`);
    invented method names corrected to the real items (`nip37`'s
    `crate::util::json::Error` → `serde_json::Error`; `nip47`'s
    `NwcError::UnsupportedEncryption` → `NwcError::UnknownEncryption`
    plus the `EventBuilder::nwc_*` wildcard expanded to the four
    concrete methods; `nip98`'s `Event::try_to_json` →
    `JsonUtil::try_to_json`); redundant `[Type](crate::path::Type)`
    targets dropped where the type is already in scope (`nip71` /
    `nip92`); literal `[<chainId>:]` in `nip73`'s i-tag wire-format
    table escaped so rustdoc stops parsing it as an intra-doc link;
    wildcard `Kind::*` and `CountRequest::to_wire` references in
    `nip45` / `nip51` rewritten as prose. `cargo doc -p nula-core
    --no-deps --all-features` now passes under
    `RUSTDOCFLAGS="-D warnings"`.

### Added

- **`nula-net` Layer-2 transport crate** (`nula-net`):
  - `WebSocketTransport` trait — object-safe, returns
    `BoxFuture<'_, Result<(WebSocketSink, WebSocketStream), Error>>`
    so the transport surface stays runtime-agnostic and works under
    `Arc<dyn …>` erasure in the upper layers.
  - Wire-shaped `Message` / `CloseFrame` variants mirroring RFC 6455
    one-for-one, plus a `#[non_exhaustive]` `ConnectionMode` enum
    (today only `Direct`; `Proxy` / `Tor` reserved for a future
    minor release).
  - `Error` enum following ADR-0004: `#[non_exhaustive]`, every
    boxed source `Send + Sync + 'static`, dedicated variants for
    `Io` / `Tls` / `Handshake { status, message }` /
    `ConnectionClosed` / `ProtocolViolation` / `UnsupportedMode` /
    `Backend`.
  - `BoxFuture` alias with a `cfg(target_arch = "wasm32")` split
    that drops the `Send` bound on browser targets (see ADR-0003).
    `WebSocketSink` / `WebSocketStream` aliases follow the same
    cfg-split.
  - `default-transport` feature (default-on) ships a
    `tokio-tungstenite`-backed `DefaultTransport` plus a
    `DefaultTransportBuilder` exposing `max_frame_size`,
    `max_message_size`, and `accept_unmasked_frames`. rustls +
    webpki-roots are wired in so `wss://…` works on a fresh install.
    The default sink avoids the `SinkMapErr` panic documented at
    rust-nostr#984 by forwarding `Sink` methods explicitly.
  - `mock` feature (default-off) provides `MockTransport` +
    `MockHandle`, an unbounded-channel-backed in-memory transport
    that upper-layer crates use to drive their state machines
    without opening real sockets.
  - `tracing` feature (default-off) wires `Instrument` spans on the
    handshake hot path with `nostr.relay.url` recorded per
    ADR-0005 conventions.
  - `IntoWebSocketTransport` blanket sugar accepting concrete `T:
    WebSocketTransport`, `Arc<T>`, and `Arc<dyn WebSocketTransport>`
    — callers pass any of the three to API boundaries.
  - End-to-end integration tests: text + binary frame round-trip
    against a localhost echo server (`tests/default_transport.rs`)
    and channel round-trip with assertion helpers
    (`tests/mock_transport.rs`).
  - Disable defaults (`default-features = false`) for wasm /
    custom-backend builds; the trait surface alone has zero runtime
    dependencies beyond `nula-core` + `futures` + `thiserror`.

- **`nula-relay` Layer-3 single-relay state machine** (`nula-relay`):
  - `Relay` handle + `RelayBuilder` — `Arc<Inner>` over a detached
    tokio actor task; `Send + Sync + Clone`. The last clone going
    out of scope fires `Command::Shutdown` from `Inner::Drop`, so
    there is no manual `close()` to forget.
  - Connection lifecycle modelled as a 5-state machine
    (`Initialized` → `Connecting` → `Connected` → `Disconnected`
    → `Terminated`), exposed both as `Relay::status()` (lock-free
    `AtomicU8`) and as a lossless `mpsc` notification stream via
    `Relay::notifications()`.
  - `ReconnectPolicy::{Never, Constant, Exponential}` with the
    AWS *full jitter* algorithm
    (`random(0, min(cap, base * 2^attempts))`); reconnect timer is
    armed inside the actor's `select!` so flap recovery costs zero
    extra wakeups.
  - Subscription model: `Relay::subscribe(id, filters, opts)`
    returns a `SubscriptionHandle` that is `Stream<Item =
    SubscriptionItem>` with three terminal forms (`Event`,
    `EndOfStoredEvents`, `Closed { message }`). Dropping the
    handle auto-issues `["CLOSE", id]` to the relay via an RAII
    `CloseGuard`. Active subscriptions are re-issued on every
    successful reconnect.
  - Publish path: `Relay::publish(event, opts)` correlates
    `["EVENT", …]` with the relay's `OK` reply through a deadline-
    keyed map. The actor's `select!` arms a dedicated
    `next_publish_timeout` timer keyed off the earliest pending
    deadline, so an idle actor still expires timed-out publishes
    without depending on external wakeups.
  - NIP-42 AUTH (`feature = "nip42"`, default-on): inbound
    `["AUTH", challenge]` surfaces as
    `RelayNotification::AuthChallenge`; callers reply with
    `Relay::authenticate(event)`.
  - `RelayLimits` — caller-tunable caps on inbound message size,
    in-flight subscriptions, and pending publishes; over-cap calls
    return typed `Error` variants instead of growing the actor's
    maps unbounded.
  - `RelayStats` — per-handle atomic counters (connect attempts /
    successes, bytes sent / received, events published / received,
    last handshake duration). Read-only via `Relay::stats()`.
  - `Error` enum follows ADR-0004 with variants for transport
    failure, malformed messages, publish rejection / timeout,
    subscription closure, shutdown, connect timeout, not-connected,
    duplicate subscription, and the two cap-exceeded conditions.
  - Feature flags: `default-transport` (re-export of
    `nula-net/default-transport` so `Relay::new(url)` works
    out-of-the-box), `nip42`, and `tracing`. The trait surface
    compiles under `--no-default-features` for wasm / custom
    transports.
  - Integration test suite (`tests/{lifecycle,subscribe,publish,
    nip42}.rs`) drives every public method through
    `nula-net::mock::MockTransport`; the suite covers connect /
    disconnect / drop-shutdown, REQ + EVENT + EOSE round-trip,
    `close_on_eose` stream termination, `["CLOSE", id]` on
    handle-drop, CLOSED-frame surfacing, publish OK / reject /
    timeout / NotConnected, and the NIP-42 AUTH challenge round
    trip.

- **ADR amendments** (docs):
  - ADR-0001 — layer table updated: `nula-net` now hosts the default
    `tokio-tungstenite` implementation behind a feature gate, and
    `nula-relay` is recast as the NIP-01 protocol state machine
    (reconnect, subscriptions, AUTH, negentropy) rather than the
    transport client.
  - ADR-0003 — added a "Default-impl gating" section documenting
    the `default-transport` / `mock` / `tracing` feature triplet,
    plus a wasm-aware `BoxFuture` alias listing.
  - ADR-0006 — new record describing the single-relay actor model:
    detached `tokio::spawn` task owning every mutable structure,
    the `select!` wakeup invariants, the channel topology
    (`mpsc` commands + `oneshot` replies + `mpsc` notifications +
    per-subscription `mpsc` event sinks), and the alternatives we
    explicitly rejected (mutex-everywhere, broadcast notifications,
    public `JoinHandle`, manual unsafe `Either<L, R>`).
  - ADR-0007 — new record describing the Layer-3 storage
    architecture: three-crate split, `heed` 0.20 + `postcard`
    selection, the seven-dbi secondary-index schema, the single-
    `unsafe` exemption around `EnvOpenOptions::open`, and the
    ingester / spawn_blocking concurrency model.
  - ADR-0008 — new record describing the Layer-4 multi-relay
    orchestration architecture: the pool-without-second-actor
    coordinator model, the `Output<T>` partial-success contract,
    `RelayCapabilities` bitflags, broadcast vs. mpsc trade-offs
    for pool notifications, the `stream_events` LRU-bounded
    dedup driver (improvement over upstream's unbounded
    `HashSet`), and the deliberate non-scope of admit / monitor /
    NIP-65 / NIP-46 / TLS at this layer.

- **`nula-net::BoxStream` alias** (`nula-net`):
  - The `future` module is renamed to `boxed` and now hosts both
    [`BoxFuture`] and the new [`BoxStream`] type alias. `BoxStream`
    follows the same wasm32 cfg-split as `BoxFuture` (drops the
    `Send` bound on browser targets) and is the canonical return
    shape for object-safe `Stream`-yielding APIs across the
    workspace, starting with `nula-relay-pool::stream_events`.
  - Re-exported as `nula_net::BoxStream`; consumers stay on the
    top-level path so the rename is invisible to callers.

- **`nula-relay-pool` Layer-4 multi-relay coordinator** (`nula-relay-pool`):
  - `RelayPool` — `Arc<Inner>` over `RwLock<HashMap<RelayUrl,
    RelayEntry>>`, **no second actor task**. Each per-relay
    [`nula_relay::Relay`] still runs its own actor; the pool
    coordinates them. Cloning the handle is `Arc`-cheap; the last
    clone going out of scope tears the pool down (drains relays,
    aborts forwarders, broadcasts `PoolNotification::Shutdown`).
  - `RelayPoolBuilder` — fluent builder requiring an
    `Arc<dyn NostrDatabase>`; defaults the transport to
    `nula_net::default::DefaultTransport` when the
    `default-transport` feature is on.
  - `Output<T>` — partial-success contract for every fan-out
    operation (`success: HashSet<RelayUrl>`, `failed:
    HashMap<RelayUrl, String>`, classifiers
    `is_full_success` / `is_partial_success` / `is_total_failure`).
  - `RelayCapabilities` bitflags (`READ` / `WRITE` / `DISCOVERY`)
    plus `AtomicRelayCapabilities` for runtime mutation.
    `add_relay` merges capabilities on the second call; pool
    operations pick relays whose capability set overlaps with
    what they need.
  - `PoolNotification` over `tokio::sync::broadcast` —
    `RelayAdded` / `RelayRemoved` / `Status` / `Notice` /
    `Shutdown`. **Lossy on slow consumers** (documented).
    Subscription events do **not** flow here; they live on
    `stream_events` with cross-relay dedup applied.
  - `stream_events` — single driver task merging per-relay
    `SubscriptionHandle`s with `futures::stream::SelectAll`,
    deduping by `EventId` through an `lru::LruCache` with a
    configurable bound (default 100k entries). Optional auto-save
    hook persists every cache-miss event into the pool's
    `NostrDatabase`. **Improvement over upstream** rust-nostr,
    which uses an unbounded `HashSet` and leaks memory on
    long-lived streams.
  - `RelayPoolOptions` — `max_relays`, `notification_channel_size`
    (default 4096), `dedup_cache_size` (default 100_000),
    `auto_save_events` (default `true`).
  - `Error` enum (#[non_exhaustive]) covering `Shutdown` /
    `RelayNotFound` / `TooManyRelays` / `NoRelaysSpecified`,
    plus `From<nula_relay::Error>` and `From<nula_storage::Error>`
    boundary conversions.
  - 22 integration tests covering add/remove/capacity
    enforcement, send_event partial-success matrix, subscribe
    semantics, cross-relay stream dedup, auto-save persistence,
    `RelayAdded` / `Shutdown` notifications, and shutdown
    idempotency.

- **`nula-relay-builder` Layer-4 in-process Nostr relay** (`nula-relay-builder`):
  - `MockRelay` — an `Arc`-cheap handle wrapping a real
    `tokio::net::TcpListener` accept loop on `127.0.0.1:0`, one
    `tokio::spawn` per accepted connection, full NIP-01 frame
    support (`EVENT` / `REQ` / `CLOSE` / `AUTH` / `COUNT`) speaking
    `tokio_tungstenite` server-side WebSocket. Drop-shutdown
    invariant: dropping the last clone fires the relay-wide
    shutdown broadcast and aborts the accept loop.
  - `MockRelayBuilder` — fluent builder accepting a custom
    `Arc<dyn NostrDatabase>`, custom `WritePolicy` /
    `ReadPolicy`, and a `MockRelayOptions` (bind addr,
    `require_nip42` toggle). Defaults to a fresh
    `MemoryDatabase` when the `memory` feature is on.
  - `WritePolicy` / `ReadPolicy` — object-safe trait surfaces
    using `nula_net::BoxFuture`. Default `AcceptAllWrites` /
    `AcceptAllReads` impls preserve the one-line "spin up a
    relay" ergonomics. `AdmitVerdict::Reject(reason)` surfaces a
    `OK false …` / `CLOSED …` reply with a `MachineReadablePrefix`.
  - **NIP-42 stub**: when `require_nip42` is on, the connection
    actor sends `["AUTH", challenge]` on connect and gates every
    subsequent `EVENT` / `REQ` behind a client `["AUTH", <event>]`
    reply. The signature on the auth event is **not verified** —
    this is a transport-layer fixture, not a real auth gate.
  - `Error` enum (#[non_exhaustive]) covering `Bind` (with
    captured `SocketAddr`), `Storage`, `Shutdown`.
  - Deliberately omitted: TLS, hyper, multi-host routing, rate
    limiting. The crate's role is "test fixture and ad-hoc dev
    relay"; production deployments reach for `nostr-rs-relay`.

- **`nula-storage` Layer-3 trait surface** (`nula-storage`):
  - `NostrDatabase` trait — eight methods (`save_event`,
    `check_id`, `event_by_id`, `count`, `query`, `negentropy_items`,
    `delete`, `wipe`), dyn-safe, returns `nula_net::BoxFuture` so
    the runtime-agnostic cfg-split from ADR-0003 reaches Layer 3
    unchanged.
  - `NostrDatabaseExt` — default-implemented convenience methods
    (`metadata`, `profile`, `relay_list_event`,
    `contact_list_event`); backends inherit them for free.
  - `Events` newtype — sorted, deduplicated `Vec<Event>` with
    canonical "newest first, tie-break by ascending id" iteration
    order matching NIP-01 wire ordering.
  - `SaveEventStatus` / `DatabaseEventStatus` / `RejectedReason`
    status enums with `#[non_exhaustive]` per ADR-0004; reasons
    cover NIP-09 deletion, NIP-40 expiration, NIP-33 replaceable
    conflict, NIP-62 vanish, ephemeral kinds, and duplicates.
  - `Backend` enum + `Features` bitflags (`PERSISTENT`,
    `FULL_TEXT_SEARCH`, `FAST_NEGENTROPY`, `BOUNDED_CAPACITY`).
  - `Profile` aggregate (`PublicKey` + optional `Metadata`) for
    `NostrDatabaseExt::profile`.
  - Zero `unsafe`, zero tokio / tracing pulls — the trait surface
    is wasm-friendly and runtime-agnostic.

- **`nula-storage-memory` in-memory backend** (`nula-storage-memory`):
  - `MemoryDatabase` — `Arc<RwLock<MemoryStore>>` over five
    indexes (`by_id`, `by_time`, `by_author`, `by_kind_author`,
    `by_coordinate`) and three tombstone sets (`deleted_ids`,
    `deleted_coordinates`, `vanished_authors`). Cloning the handle
    is `Arc`-cheap; lock guards never cross an `await`, so every
    returned future is `Send`.
  - `MemoryDatabaseBuilder` — fluent builder with `max_events`
    (LRU eviction), `process_nip09`, and `process_nip62` knobs.
  - `MemoryDatabaseOptions` — public option struct with sensible
    defaults (NIP-09 + NIP-62 on, unbounded capacity).
  - `QueryPattern` — filter classifier picking the most selective
    index for the four common shapes (single author / `(kind,
    author)` / addressable coordinate / generic full scan).
  - 34 integration tests covering save lifecycle, duplicate /
    ephemeral / expired / replaced rejections, every query
    pattern, NIP-09 deletion (event-id + coordinate tombstones,
    cross-author refusal), NIP-40 expiration, addressable
    coordinate replacement, and bounded-capacity LRU eviction.

- **`nula-storage-lmdb` persistent backend** (`nula-storage-lmdb`):
  - `LmdbDatabase` — `Arc<Inner>` over an `heed` LMDB env, a
    dedicated `nula-lmdb-ingester` writer thread, and seven
    secondary index dbis. Drop of the last clone sends
    `IngestCmd::Shutdown` and joins the thread, mirroring the
    `Drop = shutdown` invariant `nula-relay` ships with.
  - `LmdbDatabaseBuilder` — fluent async builder; `mmap` + dbi
    creation runs on `tokio::task::spawn_blocking` so callers
    stay cooperative.
  - On-disk codec: `[version: u8] [postcard(event)]`. Future
    schema changes bump `STORED_EVENT_VERSION`; old binaries
    return `Error::UnsupportedCodecVersion` instead of corrupting
    state silently.
  - Concurrency model: single-writer ingester thread fed via
    `flume::unbounded` MPSC, reads run on `tokio::task::spawn_blocking`
    with their own `heed::RoTxn`.
  - **Single `unsafe` block** around `heed::EnvOpenOptions::open`,
    documented inline with a `// SAFETY:` comment and an
    `#[allow(unsafe_code, reason = …)]` attribute citing ADR-0007.
    The crate uses `#![deny(unsafe_code)]` instead of `forbid`;
    no other `unsafe` lives in `nula-storage-lmdb`.
  - 21 integration tests covering save lifecycle, every query
    index path, NIP-09 deletion, persistence (save → drop →
    reopen round-trip), and `wipe` durability across handle
    cycles.

- **`nip11-fetch` feature implementation** (`nula-core`):
  - `Nip11Fetcher` trait + `Nip11FetchError` enum
    (`Transport` / `Status` / `Decode` variants) + `FetchFuture`
    alias, mirroring the NIP-05 fetcher architecture. The core
    stays side-effect-free so callers can plug in any HTTP
    backend; the `reqwest`-backed `ReqwestNip11Fetcher` default
    implementation lives behind the existing `nip11-fetch` Cargo
    feature.
  - The default fetcher sends `Accept: application/nostr+json`
    per NIP-11 §"Discovering Relay Information" and disables
    HTTP redirects so the relay URL stays the relay's identifier.
    `NIP11_MEDIA_TYPE` is surfaced as a public `const` for
    downstream HTTP servers to advertise the canonical
    `Content-Type`.
  - `MockNip11Fetcher` test fixture inlined in `mod tests`
    matches the `MockFetcher` shape from `nip05` and exercises
    both the happy path and the JSON-decode error path. The
    minimal `block_on` helper is built on `Waker::noop()`
    (stable since Rust 1.85) so the tests do not pull `tokio`
    or `futures-executor` into dev-dependencies.

- **Phase 1 W8 — addressable surfaces & live experiences**
  (`nula-core`):
  - `nips::nip99` — Classified Listings (`kind: 30402` published,
    `kind: 30403` draft). The `Listing` bundle pins the spec-required
    `title` plus optional `summary`, `published_at`, `location`, the
    typed `t` hashtags, multi-`g` geohashes, and the optional
    `status` (`active`/`sold`) closure marker. The `Price`
    sub-bundle parses the four-column `price` row (amount,
    ISO-4217 currency, optional NIP-99 frequency token covering the
    spec's `hour`/`day`/`week`/`month`/`year` plus a forward-compatible
    `Custom`). `Image` carries the optional `WxH` dimensions, and the
    `EventReference` / `AddressReference` rows surface `e` / `a`
    cross-references for catalog-style listings. `EventBuilder::classified_listing`
    enforces "at least one image" per spec invariants.
  - `nips::nip54` — Wiki (`kind: 30818` article, `kind: 30819`
    redirect, `kind: 818` merge request). `WikiArticle` exposes the
    spec's normalized-`d` slug (lowercased, hyphenated,
    punctuation-stripped via the dedicated `normalize_slug` helper),
    typed `RelationRef` with `Relation::{Fork, Defer, NormalizedTo,
    SourceCode}`, and a list of `WikiSource` references covering
    `e`/`a`/`r` source markers. `WikiRedirect` re-uses the typed
    `Coordinate` for the redirect target. `MergeRequest` enforces the
    spec example's tag order (destination `a`, base `e`, destination
    `p`, source `e` with `source` marker) and tracks the source
    revision invariant inside `MergeError::MissingMergeSource`.
  - `nips::nip66` — Relay Discovery (`kind: 30166` discovery,
    `kind: 10166` monitor). `RelayDiscovery` packs every column the
    spec lists: `n` network type, `T` PascalCase relay type, `N`
    supported NIPs, multi-`R` requirements with the `!`-prefix
    boolean convention via `RelayRequirement`, multi-`t` topics,
    `k` accepted kinds with the `!<kind>` rejected convention via
    `AcceptedKind`, geohash, and four `rtt-*` round-trip metrics
    (`open`/`read`/`write`/`auth`) typed through `RoundTripTime`.
    Discovery `d` identifiers go through `DiscoveryTarget`
    (`RelayUrl` or freeform string per spec §"d Tag"). `RelayMonitor`
    bundles the monitor-side declaration with typed
    `MonitorTimeout`, `frequency_seconds`, and the `o`/`g`/`u`
    operator/geohash/URL columns.
  - `nips::nip52` — Calendar Events (`kind: 31922` date-based,
    `kind: 31923` time-based, `kind: 31924` calendar collection,
    `kind: 31925` RSVP). `DateCalendarEvent` validates the `start`
    column as an ISO-8601 date (`YYYY-MM-DD`) through
    `CalendarDate::parse`, while `TimeCalendarEvent` keeps the
    column as a typed `Timestamp` plus optional IANA `start_tzid` /
    `end_tzid` rows. `CalendarEventCommon` shares the
    `title`/`summary`/`image`/`location`/`g` geohash/`p`
    participants (with role marker)/`t` hashtags/`r` references
    surface across both kinds. `CalendarRequest` maps `a` tags onto
    typed `Coordinate`s, `Calendar` aggregates owned event
    coordinates into the addressable `kind: 31924` collection, and
    `Rsvp` surfaces the `status` (`accepted`/`declined`/`tentative`)
    plus the `fb` (`free`/`busy`) tag with the spec's "declined ⇒ no
    fb" invariant enforced by `RsvpStatus::ensure_compatible_with`.
  - `nips::nip71` — Video Events (`kind: 21` normal, `kind: 22`
    short-form, `kind: 31337` normal addressable, `kind: 31338`
    short-form addressable). `Video` bundles every column the spec
    lists: `title`, `published_at`, `alt`, `summary`, `duration`,
    multiple NIP-92 `imeta` variants (one per resolution / language),
    `text-track` rows with optional relay hint via `TextTrack`,
    `content-warning`, multi-`segment` chapter rows via `Segment`,
    multi-`t` hashtags, multi-`p` participants via `VideoParticipant`,
    multi-`r` references, and the optional `origin` row exposing
    third-party platform metadata (`platform`, `external_id`,
    optional URL, optional metadata blob) via `VideoOrigin`.
    `EventBuilder::video` propagates `MediaAttachmentError` from any
    malformed `imeta` variant up through `VideoError`.
  - `nips::nip53` — Live Activities (`kind: 30311` live stream,
    `kind: 30312` meeting space, `kind: 30313` meeting room,
    `kind: 1311` live chat, `kind: 10312` room presence). The
    `LiveStream` / `MeetingSpace` / `MeetingRoom` bundles share
    `LiveStatus` (the spec's `planned`/`live`/`ended` tri-state plus
    forward-compatible `Custom`) and a separate `SpaceStatus`
    (`open`/`private`/`closed` plus `Custom`) for the meeting-space
    extension. `LiveParticipant` surfaces the four-column `p` tag
    shape (pubkey, relay hint, role marker, optional participation
    proof). `MeetingRoom` enforces the parent-space `a` tag invariant
    via `LiveError::MissingAddress`. `LiveChatMessage` and
    `RoomPresence` expose the typed `q`/`e`/`a` cross-references with
    the spec's `root` thread marker preserved across the round trip.

- **Phase 1 W7 — content discovery, moderation & attestations**
  (`nula-core`):
  - `nips::nip32` — Labeling (`kind: 1985`). The `Label` bundle pairs
    `Vec<LabelTerm>` (namespace + value pairs, with the spec's `ugc`
    fallback) with `Vec<LabelTarget>` (typed `e`/`p`/`a`/`r`/`t`
    targets, each carrying an optional relay hint). `labels_from_tags`
    also reads self-reported `L`/`l` tags off any non-1985 event;
    `term_to_tags` is the canonical pair builder.
  - `nips::nip36` — Sensitive Content. `ContentWarning` wraps the
    `content-warning` tag's optional reason column; `Tag::content_warning`
    is the canonical builder, `content_warning_from_tags` the reader.
    Pairs naturally with `nips::nip32` for ontology-scoped warnings.
  - `nips::nip56` — Reporting (`kind: 1984`). `Report` bundles the
    spec's three target shapes (profile / event / blob) plus
    free-form `.content` rationale, with `ReportType` (the spec's
    seven tokens + forward-compatible `Custom(String)`) and the
    Appendix server-URL hints (`server` tag). `EventBuilder::report`
    pins the correct `p`/`e`/`x`/`server` tag ordering per spec
    examples.
  - `nips::nip73` — External Content IDs. `ExternalContentId` and
    `ExternalContentKind` mirror every row of the spec table (URLs,
    ISBN, geohash, ISO 3166, ISAN, DOI, hashtags, podcast feeds /
    episodes / publishers, blockchain transactions and addresses
    with optional chain IDs). `ExternalContentRef` carries an
    optional URL hint, `refs_from_tags` walks any event's `i` tags,
    and `ref_to_tags` builds the canonical `i`+`k` pair.
  - `nips::nip92` — Media Attachments. `MediaAttachment` packs the
    NIP-94 column set into the variadic `imeta` wire form (one
    `url` field plus at least one other), preserves unknown
    `(key, value)` extras for forward compatibility, and
    cross-converts with [`FileMetadata`](crate::nips::nip94) via
    `from_file_metadata` / `to_file_metadata`. `Tag::imeta` builds
    the tag from the typed bundle.
  - `nips::nip89` — Recommended App Handlers. `HandlerRecommendation`
    (`kind: 31989`) bundles a recommended-kind `d` value with one
    or more `a` rows (handler coordinate + relay hint + platform
    marker). `HandlerInformation` (`kind: 31990`) packs the
    handler's identifier, supported kinds (`k` tags), and
    platform-specific entry points (`web` / `ios` / custom) with
    optional NIP-19 entity hints. `ClientTag` models the optional
    `client` tag publishers can attach to advertise the authoring
    application.
  - `nips::nip84` — Highlights (`kind: 9802`). `Highlight` carries
    the highlighted text in `.content`, a typed
    `Vec<HighlightSource>` (events, addressable events, or URLs
    with the spec's `source` / `mention` markers), and a typed
    `Vec<Attribution>` (`p` tags with optional relay hint and role
    keyword). The optional `context` / `comment` tags surface the
    quote-highlight shape from spec §"Quote Highlights"; `roles`
    and `url_markers` modules pin the spec-defined string
    constants.
  - `nips::nip75` — Zap Goals (`kind: 9041`). `ZapGoal` bundles the
    required `amount` (millisats) and `relays` columns, plus the
    optional `closed_at` deadline, `image` / `summary` metadata,
    `r` / `a` references, and reuses NIP-57
    `crate::nips::nip57::ZapSplitTarget` for beneficiary splits.
    `GoalLink` (`Tag::goal`) models the `goal` tag addressable
    events may carry to link back to their funding goal.

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

- **Dependency surface** (`nula-core`):
  - `base64` promoted from an optional dependency (previously gated by
    the `nip04` / `nip44` features) to a non-optional workspace
    dependency. It is consumed by NIP-04 legacy DMs, NIP-44 v2 encrypted
    payloads, and the NIP-98 HTTP-auth `Authorization` header — three
    of the most commonly used NIPs in the workspace — so it is
    effectively a core codec rather than an opt-in extra. The
    `dep:base64` clauses on `nip04` / `nip44` are removed accordingly.
  - **BREAKING**: callers that previously disabled `base64` by
    selecting a feature subset without `nip04` / `nip44` will now
    pull it in unconditionally (~50 KB compiled). Downstream feature
    declarations that named `nula-core/nip04` or `nula-core/nip44`
    purely to surface the `base64` dependency can drop those flags.

- **Code style** (`nula-core`):
  - All `core::*` imports migrated to `std::*` to reflect the Phase 0
    "strictly std-only" stance documented in this changelog. In std
    mode these paths are identical re-exports (`std::fmt == core::fmt`),
    so this is a pure consistency change with zero runtime or codegen
    impact. 42 files updated.

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
