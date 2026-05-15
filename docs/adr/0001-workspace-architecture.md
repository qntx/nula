# ADR-0001: Workspace architecture (13-crate plan)

**Status**: Accepted
**Date**: 2026-05-14

## Context

The `nula` workspace is a hard fork of [`rust-nostr`](https://github.com/rust-nostr/nostr)
intended to evolve along three axes that the upstream project does
not currently prioritise:

1. **Wider NIP coverage** — every NIP that we use in production gets
   first-party support, including specs (NIP-29, NIP-34, NIP-46,
   NIP-47, NIP-52, NIP-53, NIP-58, NIP-60, NIP-72, NIP-90, NIP-98)
   that are partial or absent upstream.
2. **`no_std` removal** — `nula-core` targets `std`-only platforms
   so we can use `Box<dyn Error + Send + Sync>`, `thiserror`,
   `tracing`, and `std::sync::*` without the `alloc`-only contortions
   the upstream crate maintains for embedded use.
3. **Enterprise-grade plumbing** — strict CI, supply-chain auditing,
   pinned MSRV, observable spans, deterministic builds.

The starting point is a single `nula-core` crate that already covers
events, filters, keys, messages, NIP primitives, and the eight largest
NIP implementations. Everything else (database, transport, gossip,
relay pool, SDK, CLI, signer) currently lives only in the reference
checkout at `3rdparty/nostr/`.

We need a workspace layout that:

- separates concerns sharply enough that downstream consumers can
  pick the exact subset they need (e.g. an embedded relay only wants
  protocol + storage);
- avoids the trap of one crate per NIP — that explodes the build
  graph without adding modularity;
- keeps the public API of each crate small enough that we can ship
  semver-bound breaking changes layer by layer.

## Decision

The workspace is structured as **13 crates** in a strict five-layer
DAG. Each layer may depend only on the layers below it.

```text
              ┌────────────────────────┐
   Layer 5    │ nula-cli   nula-sdk    │   binaries / facade
              └────────────────────────┘
                           ▲
              ┌────────────────────────┐
   Layer 4    │ nula-relay-pool        │   multi-relay orchestration
              │ nula-gossip            │   NIP-65 outbox routing
              │ nula-signer-connect    │   NIP-46 remote signer client
              │ nula-relay-builder     │   in-process test relays
              └────────────────────────┘
                           ▲
              ┌────────────────────────┐
   Layer 3    │ nula-relay             │   NIP-01 state machine
              │ nula-storage           │   NostrDatabase trait
              │ nula-storage-memory    │   in-memory backend
              │ nula-storage-lmdb      │   persistent backend
              └────────────────────────┘
                           ▲
              ┌────────────────────────┐
   Layer 2    │ nula-net                │   WebSocket trait + default
              │                         │   tokio-tungstenite impl
              └────────────────────────┘
                           ▲
              ┌────────────────────────┐
   Layer 1    │ nula-core              │   protocol primitives
              └────────────────────────┘
```

|  # | Crate                 | Layer | Responsibility                                                                 |
| -- | --------------------- | ----- | ------------------------------------------------------------------------------ |
|  1 | `nula-core`           | 1     | Events, filters, keys, messages, NIP primitives. No I/O, no runtime.           |
|  2 | `nula-net`            | 2     | `WebSocketTransport` trait + opt-out `tokio-tungstenite` default + mock impl.  |
|  3 | `nula-relay`          | 3     | Single-relay NIP-01 state machine: reconnect, subscriptions, AUTH, negentropy. |
|  4 | `nula-storage`        | 3     | `NostrDatabase` trait + extension traits.                                      |
|  5 | `nula-storage-memory` | 3     | In-memory backend.                                                             |
|  6 | `nula-storage-lmdb`   | 3     | LMDB-backed persistent storage.                                                |
|  7 | `nula-relay-pool`     | 4     | Multi-relay pool, subscription dedup.                                          |
|  8 | `nula-gossip`         | 4     | NIP-65 outbox/inbox routing graph.                                             |
|  9 | `nula-signer-connect` | 4     | NIP-46 remote signer client.                                                   |
| 10 | `nula-relay-builder`  | 4     | In-process mock relay for integration tests.                                   |
| 11 | `nula-sdk`            | 5     | High-level façade re-exporting the layers above.                               |
| 12 | `nula-cli`            | 5     | Reference CLI binary.                                                          |
| 13 | `nula-fuzz`           | side  | Fuzz harness crate (not shipped, not in dep graph).                            |

### Cross-cutting commitments

- **Edition 2024**, MSRV pinned to **1.94** (see `rust-toolchain.toml`).
- **`#[forbid(unsafe_code)]`** in every crate. The `nula-storage-lmdb`
  crate wraps `unsafe` calls in `heed`, which itself is audited.
- **`thiserror`** for every public error enum. Error variants are
  `#[non_exhaustive]` so we can extend without major bumps.
- **`tracing`** (feature-gated) for spans. Field names live in
  `nula-core::observe` — see ADR-0005.
- **Async runtime layering** — `nula-net`'s _trait surface_
  (`WebSocketTransport`, `BoxFuture<'_, T>`) is runtime-agnostic and
  compiles on `wasm32-unknown-unknown`. The crate's _default
  implementation_ pulls Tokio in behind the `default-transport`
  feature so the common-case install ships a working client; wasm
  consumers and custom-backend authors set `default-features = false`.
  See ADR-0003.

### Build / publish ordering

Crates are released in dependency order. The release script
(`RELEASING.md`) walks layers 1→5; within a layer it follows the
alphabetical order shown in the table.

## Consequences

### Positive

- Downstream consumers can vendor exactly the layers they need
  without paying for the entire stack.
- Breaking changes can be staged: layer 1 absorbs the cost first,
  upper layers absorb only what propagates up.
- The DAG shape is enforced by `cargo` itself — accidentally
  reaching from `nula-storage` back into `nula-relay-pool` won't
  compile.

### Negative

- 13 crates means 13 `Cargo.toml` files to maintain in lockstep
  (workspace dependencies mitigate this).
- The `nula-sdk` façade duplicates re-exports that already live in
  lower crates; we accept the duplication for ergonomic imports.
- CI matrix is wider: every job iterates over the full member list.

### Rollback

If a layer split turns out to be premature (e.g. `nula-relay`'s
NIP-01 state machine collapses into `nula-net`, or `nula-net` ends up
exposing only one trait that `nula-relay` could host directly), we
merge the smaller crate back into its consumer. The pre-merge tag
in git history preserves the API surface for downstream reference.

## References

- `/Users/xu/.windsurf/plans/nula-workspace-bottom-up-plan-7c7373.md` — the
  full bottom-up implementation plan.
- ADR-0002 — `rust-nostr` reference vendoring & sync convention.
- ADR-0003 — Async runtime layering strategy.
- ADR-0004 — Error handling via `thiserror`.
- ADR-0005 — Observability field conventions for `tracing`.
- [rust-nostr workspace layout](https://github.com/rust-nostr/nostr/tree/master/crates).
