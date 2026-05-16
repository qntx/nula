# ADR-0007: Layer-3 storage architecture

**Status**: Accepted
**Date**: 2026-05-16

## Context

ADR-0001 reserves crates 4–6 of the workspace for the Layer-3 event
store: a `NostrDatabase` trait plus two first-party backends
(in-memory + LMDB-on-disk). With `nula-relay` (Phase 2) landed, the
relay pool / gossip / SDK layers above us need a unified storage seam
to depend on, with two non-overlapping consumer profiles:

1. **Ephemeral / test caller** — wants zero on-disk side effects,
   bounded memory, single-process throughput. The in-memory backend
   is sufficient.
2. **Persistent client / relay** — needs durability, indexes over the
   common NIP-01 filter shapes, and a flush story that survives
   process kill. The on-disk backend lands here.

The upstream `rust-nostr/nostr-database` crate solves the same
problem with thirteen secondary indexes, `flatbuffers`-encoded
records, and a custom `BoxedFuture` alias. We picked a deliberately
smaller surface area so the trait + first backend ship under
ten files per crate; ADR-0001 §Rollback explicitly permits this kind
of pruning.

## Decision

### 1. Three crates, one trait

The split mirrors ADR-0001's layer table verbatim:

| Crate                   | Role                                              |
| ----------------------- | ------------------------------------------------- |
| `nula-storage`          | `NostrDatabase` trait + status enums + `Events`. |
| `nula-storage-memory`   | `MemoryDatabase` (BTreeMap-and-HashMap core).    |
| `nula-storage-lmdb`     | `LmdbDatabase` (heed + postcard).                |

The trait surface reuses `nula_net::BoxFuture<'a, T>` instead of a
crate-local alias, so the runtime-agnostic cfg-split established in
ADR-0003 covers Layer 3 unchanged.

### 2. Backend choice: heed 0.20 (LMDB)

We considered `heed` (LMDB), `redb` (pure-Rust B+ tree), and `fjall`
(Rust-native LSM). LMDB wins on three axes:

- **Maturity** — 5+ years of production deployments at the upstream
  reference scale (`nostr-lmdb` ships in nostr-rs-relay,
  notebroad-rs, and Pocket).
- **Concurrent reads** — multi-reader `RoTxn` scales linearly with
  CPU cores, while writes serialise through a single `RwTxn`. The
  shape maps cleanly onto the single-writer / many-readers profile
  upper layers will hit.
- **Disk footprint** — LMDB's b-tree pages plus our 40-byte index
  keys produce a working set well under the per-event content cost.

The trade-off is **`unsafe_code`**. `heed::EnvOpenOptions::open` is
marked unsafe because the returned `Env` mmaps the database file:
the caller must ensure the file is not concurrently mutated by an
external process, and the configured `map_size` must fit in the
address space. ADR-0001 §Cross-cutting commitments mandates
`#[forbid(unsafe_code)]` workspace-wide; this ADR records the
**single exception**:

- `nula-storage-lmdb` uses `#![deny(unsafe_code)]` (not `forbid`).
- Exactly one `unsafe` block exists, around `EnvOpenOptions::open`
  in `src/store.rs`. It carries an inline `// SAFETY:` comment
  documenting both invariants and an `#[allow(unsafe_code, reason =
  …)]` attribute citing this ADR.
- No other code in the crate uses `unsafe`; the lint catches
  regressions.

### 3. Encoding: `postcard` 1.x

Events on disk are `[u8 version_prefix][postcard(event)]`. The
prefix is a one-byte version tag (`STORED_EVENT_VERSION = 1`); any
future schema change bumps the tag and reads of older payloads
return `Error::UnsupportedCodecVersion(_)` instead of corrupting
state silently. `postcard` is preferred over `bincode`, `flatbuffers`,
and raw JSON because it is:

- **Compact** — ~30 % smaller than `bincode 2.x` for our event shapes.
- **Stable** — semver-stable wire format with documented evolution
  rules (extending structs with `Option<T>` fields stays backward
  compatible).
- **Zero `unsafe`** — fully safe-Rust encoder/decoder, no `alloc`-
  layout assumptions.
- **Embedded-friendly** — already the de-facto serde codec for the
  embedded Rust ecosystem (embassy, embedded-hal), so we inherit
  battle-tested decoders.

### 4. Index schema: seven dbis

`nula-storage-lmdb` opens seven named LMDB databases:

| dbi                   | Key shape                                  | Value         |
| --------------------- | ------------------------------------------ | ------------- |
| `events`              | `event_id (32)`                            | `StoredEvent` |
| `by_created_at`       | `ts_be(8) ‖ id(32)`                        | `()`          |
| `by_author_ts`        | `pubkey(32) ‖ ts_be(8) ‖ id(32)`           | `()`          |
| `by_kind_author_ts`   | `kind_be(2) ‖ pubkey(32) ‖ ts_be(8) ‖ id`  | `()`          |
| `by_coordinate`       | `kind_be(2) ‖ pubkey(32) ‖ d_utf8`         | `event_id`    |
| `deleted_ids`         | `event_id (32)`                            | `ts_be(8)`    |
| `deleted_coordinates` | `kind_be(2) ‖ pubkey(32) ‖ d_utf8`         | `ts_be(8)`    |

Lexicographic byte order matches the natural numeric / canonical
order for every key field: big-endian timestamps and kinds give
ascending byte = ascending numeric, fixed-width id / pubkey segments
make prefix scans straightforward.

We **omit** tag indexes (`tc / atc / ktc`) that the upstream crate
maintains. The current Layer-4 callers (relay pool / gossip) do not
issue tag-only filter shapes; when they do, we add the index then.

### 5. Concurrency: ingester worker

`LmdbDatabase` spawns a dedicated `std::thread` ("nula-lmdb-
ingester") that owns the only `RwTxn`-issuing path. Mutations fan
in through a `flume::unbounded` MPSC channel; each command carries a
`tokio::sync::oneshot` reply, so the async surface stays a normal
`BoxFuture`. Reads bypass the ingester entirely and run on
`tokio::task::spawn_blocking` with their own `RoTxn`.

Cloning the public `LmdbDatabase` handle is `Arc`-cheap; the last
clone going out of scope sends `Shutdown` to the ingester via
`Inner::Drop` and joins the thread, mirroring the
`Drop = shutdown` invariant `nula-relay` ships with (ADR-0006).

### 6. Protocol semantics inside the backend

Both backends honour the same write rules so callers above the trait
never re-implement them:

| NIP / kind range          | Backend behaviour                                                              |
| ------------------------- | ------------------------------------------------------------------------------ |
| **Ephemeral (20000–29999)** | Dropped at write time; returned as `Rejected(Ephemeral)`.                     |
| **NIP-40 expiration**     | Past-expiration events are `Rejected(Expired)`.                               |
| **Duplicate id**          | `Rejected(Duplicate)`. Idempotent re-publishes are not an error.              |
| **NIP-09 deletion**       | Kind-5 events tombstone targets they authored; tombstones refuse re-insertion. |
| **Replaceable (10000–19999)** | Per `(kind, author)`, keep the newest; older or duplicate-by-id loses.       |
| **Addressable (30000–39999)** | Per `(kind, author, d)`, keep the newest; older loses with `Rejected(Replaced)`. |
| **NIP-62 vanish**         | Reserved hook (memory backend honours, LMDB backend stubs for now).            |

### 7. Test strategy: per-backend integration tests

Per the user's Phase-3 decision to skip an independent
`nula-storage-test-suite` crate, each backend ships its own
integration test files under `tests/`. Both backends include
matching `tests/save_event.rs`, `tests/query_filters.rs`,
`tests/nip09_deletion.rs`, etc. The fixtures live in
`tests/helpers/mod.rs` per crate; cross-crate fixture reuse waits
until a real second consumer appears.

## Consequences

### Positive

- Layer-4 consumers (`nula-relay-pool`, `nula-gossip`, future
  `nula-sdk`) get one trait to depend on, with two interchangeable
  backends.
- The on-disk codec is forward-evolvable: bump the version prefix,
  read both shapes in the decoder.
- LMDB's mmap read path lets readers scale to all available cores
  without contention.

### Negative

- We carry one `unsafe` block per ADR-0001 cross-cutting commitment;
  the lint configuration prevents accidental growth.
- LMDB requires a configured `map_size`; the default 1 GiB is enough
  for a per-user client but production relays must tune it via
  `LmdbDatabaseBuilder::map_size_bytes`.
- The two backends duplicate ~150 LOC of protocol-semantics logic.
  We accept the duplication for now; if it grows we will factor it
  into a private `nula-storage::semantics` module.

### Rollback

If `heed` turns out to block compliance on a target (e.g. wasm32,
which has no LMDB), `nula-storage-lmdb` is the only crate that needs
to swap engines. Replacing `heed` with `redb` would let
`nula-storage-lmdb` drop the unsafe exemption entirely; we keep that
path open by keeping all heed-specific types behind crate-private
boundaries.

## References

- ADR-0001 — Workspace architecture (lists `nula-storage*` crates).
- ADR-0003 — Async runtime strategy (BoxFuture reuse).
- ADR-0004 — Error handling via thiserror.
- ADR-0006 — Single-relay actor model (Drop = shutdown precedent).
- [heed](https://github.com/meilisearch/heed) — Rust LMDB binding.
- [postcard](https://github.com/jamesmunns/postcard) — serde codec.
