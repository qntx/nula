# ADR-0010: NIP-77 Negentropy lives in a standalone `nula-sync` crate

**Status**: Accepted
**Date**: 2026-05-17

## Context

[NIP-77](https://github.com/nostr-protocol/nips/blob/master/77.md)
defines a [Negentropy](https://github.com/hoytech/negentropy)
set-reconciliation handshake that lets a client and a relay (or two
clients via a relay) discover their event-set difference with
logarithmic bandwidth and round trips. Phase 6 adds this to the
workspace as the last missing first-class NIP that the upstream
`rust-nostr` stack supports.

Two design questions had to be answered before we wrote a line of
code:

1. **Where do the four wire frames live?**
   `NEG-OPEN` / `NEG-MSG` / `NEG-CLOSE` belong to `ClientMessage`
   and `NEG-MSG` / `NEG-ERR` belong to `RelayMessage`. Both message
   enums already exhaustively model every NIP-01 / NIP-42 / NIP-45
   frame in `nula-core`, and the NIP-77 payloads are nothing more
   than a subscription id, a filter and a hex-encoded byte buffer —
   no extra crates required.
2. **Where does the algorithm itself live?**
   The upstream
   [`negentropy = "0.5"`](https://crates.io/crates/negentropy)
   crate is pure-Rust, `#![no_std]`-by-default, and depends only on
   `alloc`. We do not need to (and should not) re-implement the
   state machine; we only need the workspace glue: a
   `NegentropyStorageVector` adapter for `(EventId, Timestamp)`,
   a `Reconciliation` session for the initiator role, a `Responder`
   session for the non-initiator role, and an optional
   `NostrDatabase` bridge.

We compared two crate layouts:

|     | Layout A: fold algorithm into `nula-relay-pool` | Layout B: standalone `nula-sync` crate |
|-----|-------------------------------------------------|----------------------------------------|
| Dependency surface | `nula-relay-pool` gains `negentropy` (pure-Rust, ~5 KLOC) plus a wire codec | New crate isolates the dependency; pool stays the same |
| Reuse outside the pool | Hard — the algorithm sits inside an actor file | Trivial — Layer 5 (SDK), CLI, fuzz, mock relays all import the same crate |
| Fuzzing / property tests | Have to spin a full `RelayPool` to exercise the codec | Pure functions are fuzz-friendly out of the box |
| `cfg(feature = "nip77")` ergonomics | Boolean flips a chunk of `nula-relay-pool` | Boolean flips a whole crate dependency in `nula-sdk` |
| Coupling to transport | Hard — the algorithm sees the actor mailbox | None — the crate is runtime- and transport-free |

Layout B wins on every axis that matters for the next phase
(Layer 5 facade, CLI, fuzz coverage) and costs us nothing measurable
on the axes that don't.

## Decision

We add a new Layer-3 crate **`nula-sync`** with three public
surfaces and one optional adapter:

- **`Reconciliation`** — initiator session. Holds an owned
  `Negentropy<'static, NegentropyStorageVector>`, exposes
  `initiate(storage, frame_size_limit)` plus the convenience
  `with_defaults(storage)`, and folds responder messages into a
  `ReconcileOutcome { have, need, next_message }`.
- **`Responder`** — non-initiator session. Mirrors the same shape
  but its `reconcile(query) -> Vec<u8>` simply forwards to
  `Negentropy::reconcile`.
- **`prepare_storage`** — sealed-vector constructor that converts
  `impl IntoIterator<Item = (EventId, Timestamp)>` into a
  ready-to-use `NegentropyStorageVector`.
- **`storage::from_database`** — optional, behind the `storage`
  feature, async helper that pulls items from a
  `nula_storage::NostrDatabase` via `negentropy_items(filter)` and
  hands them to `prepare_storage`.

The wire frames live where they belong: we extend
`nula_core::ClientMessage` with `NegOpen`, `NegMsg`, `NegClose` and
extend `nula_core::RelayMessage` with `NegMsg`, `NegErr`. Both enums
are already `#[non_exhaustive]`, so adding variants does not break
downstream code that pattern-matches.

### What `nula-sync` is not responsible for

- **Transport**. The crate touches neither sockets nor relays. The
  caller pushes bytes between `Reconciliation` and `Responder`.
  Phase 6.4 (`nula-sdk`) wires the loop on top of
  `nula_relay_pool::RelayPool`.
- **Event download**. `ReconcileOutcome::need` tells the caller
  which `EventId`s are missing locally; pulling them is a vanilla
  `REQ` subscription, which the pool already supports.
- **Frame budgeting**. `DEFAULT_FRAME_SIZE_LIMIT = 60_000` is a
  baseline; consumers tune it per relay via the constructor.

## Consequences

### Positive

- `nula-core`, `nula-storage`, `nula-relay`, `nula-relay-pool`,
  `nula-gossip`, `nula-signer-connect` all stay completely unaware
  of Negentropy. Builds that disable Phase 6 features pay zero cost.
- Sync becomes a pure-function library: 9 unit tests cover opening
  message generation, two-side convergence (identical and divergent
  sets) and hex round-tripping; the `storage` feature adds one
  end-to-end test against `nula-storage-memory`.
- The crate is the natural home for the future NIP-77 fuzz target
  (`negentropy_message_parse`) listed in the Phase 6 plan.
- Layer 5 (`nula-sdk`) only needs `nula-sync = { workspace = true }`
  to gain a complete sync API — no new actor inside `nula-relay-pool`.

### Negative

- A new crate to publish to crates.io. The Phase 6.9 release
  checklist already accounts for this in the per-Layer publish order
  (`nula-sync` sits in Layer 3, between `nula-storage-lmdb` and
  `nula-gossip`).
- The optional `storage` feature pulls `nula-storage` into the
  dependency graph for callers who want the database adapter; we
  document this in the crate-level rustdoc.

## Status of related crates after this ADR

| Crate                  | Phase 6 status |
|------------------------|---------------|
| `nula-core`            | Adds NIP-77 wire variants. No algorithm or feature flag. |
| `nula-storage`         | `negentropy_items` API was already in place since Phase 4; no change. |
| `nula-storage-memory`  | Default `Features` already include `FAST_NEGENTROPY` via the inherited `negentropy_items` impl; no change. |
| `nula-storage-lmdb`    | Same; future work may add a dedicated secondary index. |
| `nula-relay-pool`      | No change in Phase 6.2. Phase 6.4 will add a high-level `RelayPool::sync(filter)` helper backed by `nula-sync`. |
| `nula-sdk`             | Phase 6.4 will expose `Client::sync(filter)`. |

## References

- [NIP-77 specification](https://github.com/nostr-protocol/nips/blob/master/77.md)
- [Hoyte's reference implementation](https://github.com/hoytech/negentropy)
- ADR-0001: workspace layering (Layer 3 placement)
- ADR-0004: error-handling shape (`thiserror`, `#[non_exhaustive]`)
- ADR-0007: storage layer architecture (`Features::FAST_NEGENTROPY`)
