# ADR-0008: Multi-relay orchestration architecture

**Status**: Accepted
**Date**: 2026-05-16

## Context

ADR-0001 reserves crates 7–10 of the workspace for Layer 4 — the
multi-relay orchestration layer that turns a set of single-relay
clients into something the SDK / gossip / signer crates can depend
on. With Phase 3 (`nula-storage*`) shipped, the bottom-up plan now
needs the smallest viable Layer 4 to unblock everything above it.

We split Layer 4 into four crates in ADR-0001 because they have
genuinely independent surfaces: pool / NIP-65 routing / NIP-46
remote signer / programmable test relay. They also have very
different shapes — a coordinator, a routing graph, a protocol
state machine, a server. Bundling them all into one crate would
re-create the kind of "everything imports everything" cycle the
13-crate split was designed to avoid.

But shipping all four at once would be a large step that buries
the most important piece (`nula-relay-pool`) under three extra
protocol surfaces. So Phase 4 ships the **two crates that pair**:
`nula-relay-pool` (the coordinator) and `nula-relay-builder` (the
in-process server that lets us write end-to-end tests for the
coordinator without depending on the public relay graph). The
remaining two land in Phase 5 once they have a stable
`nula-relay-pool` underneath.

## Decision

### 1. Scope: pool + builder, not the full Layer 4

| Crate                 | Phase | Reason                                                                      |
| --------------------- | ----- | --------------------------------------------------------------------------- |
| `nula-relay-pool`     | 4     | Required by `nula-gossip`, `nula-sdk`, integration tests of every higher layer. |
| `nula-relay-builder`  | 4     | Required by `nula-relay-pool` integration tests; trivial dependency on Phase-3 storage. |
| `nula-gossip`         | 5     | Independent NIP-65 routing graph. Plugs into the pool but does not change its shape. |
| `nula-signer-connect` | 5     | Independent NIP-46 protocol state machine. Plugs into the pool but does not change its shape. |

### 2. Pool concurrency model

The pool is **not** a second-tier actor. Each
[`nula_relay::Relay`] already runs its own `tokio::spawn`ed actor
(ADR-0006); the pool's job is to coordinate them, not to recreate
that pattern at a coarser grain. The internal layout is a thin
`Arc<Inner>` over a `tokio::sync::RwLock<HashMap<RelayUrl, RelayEntry>>`,
plus a `tokio::sync::broadcast::Sender<PoolNotification>`.

Cloning the public `RelayPool` handle is `Arc`-cheap; every clone
shares the same map. Dropping the **last** clone marks the pool as
shut down (atomic flag), spawns a best-effort drain that
disconnects every relay, and broadcasts
`PoolNotification::Shutdown`. This mirrors the
`Drop = shutdown` invariant the relay layer ships with.

### 3. Partial-success return shape

Every fan-out operation returns `Output<T>`:

```rust
pub struct Output<T> {
    pub value: T,
    pub success: HashSet<RelayUrl>,
    pub failed:  HashMap<RelayUrl, String>,
}
```

The error string is **already rendered** at the boundary so
downstream observability can carry it as plain text without re-
introducing crate-private error types into the type signature.
Callers ask `Output::is_full_success()` / `is_partial_success()` /
`is_total_failure()` — three classifications cover every UI / log /
retry decision branch we have observed in upstream code.

### 4. Per-relay `RelayCapabilities`

Bitflags: `READ`, `WRITE`, `DISCOVERY`. Pool operations pick relays
whose capability set **overlaps** with what the operation needs
(send_event → WRITE, subscribe/stream_events → READ). Mutating
capabilities at runtime works through `AtomicRelayCapabilities`
without touching the relay's actor; a relay added twice with
different capabilities sees its bitflags merged on the second
`add_relay` call.

We deliberately omitted upstream's `GOSSIP` capability: gossip
routing is the job of `nula-gossip` (Phase 5), which keeps its own
relay set rather than co-opting the pool's.

### 5. Notification broadcast channel

`PoolNotification` flows over `tokio::sync::broadcast`. Every
caller of `RelayPool::notifications()` gets its own receiver;
**slow consumers may observe `RecvError::Lagged`**. The trade-off
is intentional: `notifications()` is a fan-out diagnostic / UI
path; back-pressuring the pool's hot path on a stuck UI thread is
worse than dropping a few status transitions.

Subscription events do **not** flow through this channel. They
arrive on the per-relay [`SubscriptionHandle`] returned by the
single-relay `subscribe` API; the pool surfaces them
cross-relay-deduplicated through `stream_events` instead. Keeping
the broadcast channel free of event traffic keeps each lag-drop
cheap (a few hundred bytes of `PoolNotification`, not a 64-KiB
event payload).

### 6. `stream_events` driver task

`RelayPool::stream_events` opens one `SubscriptionHandle` per
selected relay, surrenders them to a single `tokio::spawn`ed
driver task, and returns a `nula_net::BoxStream<'static, (RelayUrl,
Result<Event, …>)>` to the caller.

The driver merges every per-relay stream with `futures::stream::SelectAll`,
runs each event through an `lru::LruCache<EventId, ()>`
(default 100_000 entries), and forwards cache-miss events into a
1024-slot mpsc channel — the consumer end of which becomes the
returned `BoxStream`. When the consumer drops the receiver, the
driver observes `tx.closed()` on its next select poll and exits;
when an optional deadline elapses, it exits the same way. Either
end of the lifecycle is **graceful**, no per-relay
`unsubscribe` is needed (the auto-close-on-drop behaviour of
`SubscriptionHandle` does that for us).

**Improvement over upstream**: the upstream `nostr-sdk` driver
uses a plain `HashSet<EventId>` for dedup, which grows without
bound on long-lived streams. We replace it with an LRU bound;
`RelayPoolOptions::dedup_cache_size` lets callers tune it.

### 7. Auto-save events

`RelayPoolOptions::auto_save_events` (default `true`) hooks into
the `stream_events` driver: every event past the dedup gate also
goes through `Arc<dyn NostrDatabase>::save_event`. Failures are
swallowed — the consumer still observes the event on the returned
stream, and the persistence side-channel is best-effort.

### 8. Builder design (`nula-relay-builder`)

The builder is a real WebSocket server, not a mock. It binds a
`tokio::net::TcpListener` (defaulting to `127.0.0.1:0` so CI can
run multiple in parallel), accepts connections via
`tokio_tungstenite::accept_async`, and per accepted socket spawns
one `handle_connection` future. Each connection actor owns its
split sink/stream halves, an authenticated flag, an in-flight
subscription map, and a clone of the relay-wide shutdown
broadcast.

Every NIP-01 frame surface is implemented on this connection
actor:

- `EVENT` → `WritePolicy::admit_event` → `db.save_event` → `OK`
- `REQ`   → per-filter `ReadPolicy::admit_filter` → `db.query` per filter → stream events → `EOSE`
- `CLOSE` → drop the subscription record
- `AUTH`  → flag the connection as authenticated (signature is **not** verified — see §9)
- `COUNT` → `db.count` → `COUNT` reply

The `WritePolicy` / `ReadPolicy` traits are object-safe and use
`nula_net::BoxFuture` so the runtime cfg-split established in
ADR-0003 reaches the builder unchanged. Their default
implementations (`AcceptAllWrites` / `AcceptAllReads`) preserve
the "spin up a relay in one line" ergonomics.

We **deliberately omitted** TLS, hyper, multi-host routing, and
production-grade rate limiting. The crate is a fixture, not a
shippable relay binary; if anyone needs a real relay in front of
something they should reach for `nostr-rs-relay`.

### 9. NIP-42 challenge stub

`MockRelayOptions::require_nip42 = true` makes the builder send
`["AUTH", challenge]` immediately after the WebSocket handshake
and reject every subsequent `EVENT` / `REQ` until the client
replies with `["AUTH", <event>]`. **The signature on that event is
not verified** — the builder is a transport-layer fixture for
exercising the upper-layer NIP-42 plumbing, not a real auth gate.
End-to-end NIP-42 with signature verification lives in the SDK
layer (Phase 5+).

### 10. Things explicitly out of scope

- `AdmitPolicy` / `Monitor` traits at the **pool** level — the
  pool accepts every relay, and observability runs through the
  notification broadcast plus per-relay `tracing` spans (ADR-0005).
  Spam policies live in the SDK / application layer.
- `gossip_break_down_filter` and other gossip-aware helpers —
  Phase 5's `nula-gossip` keeps its own relay set; the pool stays
  generic.
- `nip42_auto_authentication` at the pool level — that is a
  cross-relay AUTH choreography that depends on a signer trait,
  which is `nula-signer-connect`'s territory.
- TLS in the builder — see §8.

## Consequences

### Positive

- The pool's surface is small enough to maintain by hand in one
  file (`pool.rs`), and the per-call dispatch logic is uniform
  enough to factor into the same `Output<T>` for every fan-out.
- Drop semantics align with the rest of the workspace: a clone
  graph that reaches zero gets cleaned up; nobody has to remember
  to call `shutdown()`.
- The LRU dedup makes long-lived streams safe to use in
  always-on clients without operators having to tune anything.

### Negative

- The pool's `auto_save_events` hook hides side effects from the
  consumer. We accept the convenience trade-off and document it in
  `RelayPoolOptions::auto_save_events`.
- The broadcast notification channel can drop on slow consumers.
  Lossless per-relay feeds remain available; we document the
  trade-off in `PoolNotification`.
- The builder uses one `tokio::spawn` per connection. For a CI
  fixture this is fine; if the builder ever needs to model 10k
  concurrent clients we will revisit (probably by adopting
  `axum` or a connection-pool library).

### Rollback

If the LRU dedup turns out to interact badly with very high event
churn, `RelayPoolOptions::dedup_cache_size` can be tuned per
deployment without changing the public API. If the broadcast
notification model proves too lossy in practice, we can introduce
an mpsc-based variant alongside it without breaking the broadcast
one. If the builder grows beyond the test-fixture role, we can
extract the connection actor into its own crate.

## References

- ADR-0001 — Workspace architecture.
- ADR-0003 — Async runtime layering (BoxFuture / BoxStream).
- ADR-0004 — Error handling via `thiserror`.
- ADR-0005 — Observability conventions for `tracing`.
- ADR-0006 — Single-relay actor model (drop = shutdown).
- [lru](https://github.com/jeromefroe/lru-rs) — LRU cache used for dedup.
- [futures::stream::SelectAll](https://docs.rs/futures/latest/futures/stream/struct.SelectAll.html) — multi-stream merge.
- [tokio_tungstenite](https://github.com/snapview/tokio-tungstenite) — server-side WebSocket binding used by `nula-relay-builder`.
