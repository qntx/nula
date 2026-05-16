# ADR-0009: Layer-4 multi-relay routing & remote signer architecture

**Status**: Accepted
**Date**: 2026-05-16

## Context

Phase 4 (ADR-0008) gave the workspace a multi-relay coordinator
([`nula-relay-pool`]) and an in-process programmable relay
([`nula-relay-builder`]). Two Layer-4 responsibilities were
deliberately deferred:

1. **Routing**: NIP-65 (`kind:10002`) and NIP-17 (`kind:10050`) tell
   us which relays a user reads from / writes to / wants direct
   messages on. Without this, every fan-out picks targets blindly —
   either flooding every known relay or under-delivering to subsets
   that miss the recipient entirely.
2. **Remote signing**: NIP-46 lets an application sign events
   through a hosted bunker without touching the user's secret key.
   The protocol primitives (encoder / decoder / URI parser) already
   live in `nula_core::nips::nip46`; what was missing is the
   transport actor that runs the request/response RPC over a
   subscribed `kind:24133` event stream.

Phase 5 ships both responsibilities under the **full feature parity**
ceiling agreed during planning — the implementation matches the
behaviour of the upstream `rust-nostr` reference for first-class
production use.

## Decision

Two new Layer-4 crates:

|             | Crate                  | Layer | Public surface                                                                |
| ----------: | ---------------------- | ----- | ----------------------------------------------------------------------------- |
|             | `nula-gossip`          | 4     | `Gossip` + `GossipBuilder` + `BrokenDownFilters` + `RefresherHandle`          |
|             | `nula-signer-connect`  | 4     | `NostrConnect` + `NostrConnectBuilder` + `AuthUrlHandler` + `NostrSigner` impl |

Neither introduces new traits at the boundary: routing returns
`HashSet<RelayUrl>` / `BrokenDownFilters`, the signer client
implements the existing `nula_core::NostrSigner`. Higher-level code
(SDK facade, CLI) plugs them into the existing pool and storage
plumbing without any new abstraction.

## `nula-gossip` design

### Concrete struct, not a trait

`Gossip` is a concrete struct backed by `Arc<Inner>`. The cache
lives in memory (`RwLock<HashMap<PublicKey, UserRoutes>>`); long-term
persistence is delegated to the workspace's existing
`Arc<dyn NostrDatabase>` so the routing layer does not introduce a
parallel trait hierarchy.

Rationale: `rust-nostr` ships `nostr-gossip` as a trait + multiple
backends. Our backends already factor through `NostrDatabase`, so
adding a second trait would add no new degrees of freedom and double
the surface area.

### Per-user routing model

Every observed event flows through `Gossip::process()`:

- **`kind:10002`** (NIP-65) updates the user's read/write relay list.
- **`kind:10050`** (NIP-17) updates the user's DM relay list.
- Any other event has its `r` tag values folded into the user's
  *hint* histogram, and (when a `source_relay` is supplied) into the
  *most-received* histogram.

`outbox_relays` / `inbox_relays` / `dm_relays` then take the per-user
NIP-65/17 entries plus the top-K hints and most-received relays per
[`GossipLimits`], applying the [`AllowedRelays`] policy gate (onion /
local / no-tls toggles) at the very end.

### `BrokenDownFilters` tri-state

`Gossip::break_down_filter` returns one of:

- `PerRelay(HashMap<RelayUrl, Filter>)` — the filter targeted
  authors and/or `#p` tags and routing turned that into a per-relay
  filter map. NIP-17 trigger (kinds containing `Kind::GIFT_WRAP`, or
  `#p` set with no kinds) folds DM relays into the result.
- `Orphan(Filter)` — the filter targeted public keys but the cache
  has no routing data for any of them. The caller still owns the
  filter and may run it against a discovery pool.
- `Generic(Filter)` — the filter has neither `authors` nor `#p`
  (e.g. `Filter::new().search("...")`). Routing cannot help; the
  caller picks a generic READ pool.

The three-state name `PerRelay / Orphan / Generic` is more
self-documenting than `rust-nostr`'s two-state `Filters / Other`
output.

### Background refresher

[`RefresherHandle::spawn`] kicks off a tokio task that wakes every
[`GossipOptions::refresher_interval`] (default 60 s), pulls up to
[`GossipOptions::refresher_batch`] outdated keys per kind, and walks
them through `Gossip::refresh` against a caller-supplied discovery
relay set. Every refresh respects [`GossipOptions::min_fetch_interval`]
(default 30 s) so a permanently-missing list cannot starve the queue.

The handle's `Drop` aborts the spawned task; the same handle exposes
`shutdown()` for explicit teardown.

## `nula-signer-connect` design

### Two pool modes

The client lives over a [`nula_relay_pool::RelayPool`] in one of two
shapes:

- **`PoolMode::External`**: the application supplies an
  `Arc<RelayPool>`. The client `add_relay`s its URI relays into it
  and `try_connect`s, but never owns the pool.
- **`PoolMode::Embedded`**: the client builds its own pool from a
  caller-supplied `Arc<dyn NostrDatabase>`. The pool's `Drop` runs
  when the last `NostrConnect` clone goes away.

This sidesteps the upstream's single-mode design which ties every
NIP-46 client to a private `Client` instance. Sharing one `RelayPool`
across many `NostrConnect` clients keeps the connection count flat
in multi-account UIs.

### Dispatcher actor

A single tokio task per client subscribes to
`kind:24133` events targeting the local client pubkey, NIP-44
decrypts the payload, and routes the resulting
`nip46::Message::Response` to its in-flight RPC via a
`Mutex<HashMap<id, Pending>>`.

`Pending` carries the originating method so the dispatcher can decode
the wire payload against the right shape; without that the response
alphabet is ambiguous (`"ack"` is a connect ack, `"pong"` is a ping
reply, both arrive as plain strings).

### `auth_url` flow

NIP-46 lets the bunker reply with the literal `"auth_url"` to ask
the user to complete an out-of-band step. The dispatcher hands the
URL to a pluggable [`AuthUrlHandler`] and **parks the pending entry
back in the map** so the eventual real reply (with the same `id`)
still wakes the original caller.

The default handler [`RejectAuthUrl`] surfaces every prompt as a
backend error. Production apps wire their own handler via
[`NostrConnectBuilder::auth_url_handler`].

### `nostrconnect://` secret-echo gate

For the client-initiated flow the URI carries a mandatory `secret`.
The dispatcher latches `event.pubkey` as the remote signer pubkey
**only when the connect response echoes that secret verbatim**.
Anything else surfaces as `Error::Spoofed` after the configured
timeout, ruling out impersonation.

### `NostrSigner` bridge

`NostrConnect` implements `nula_core::NostrSigner` (object-safe via
`SignerFuture`). Drop-in: every consumer that already accepts an
`Arc<dyn NostrSigner>` works without further glue.

Errors collapse into the trait's surface:

- `Error::Rejected { method, message }` → `SignerError::rejected_with_code`
  carrying `method.as_str()` as the structured code.
- Everything else → `SignerError::backend(err)`.

## Side-effects in the rest of the workspace

- **`nula-relay-builder` live broadcast** (Phase 4 follow-up).
  Connection actors now subscribe to a relay-wide
  `tokio::sync::broadcast<Event>`. Every accepted EVENT publishes to
  the channel; every connection's `select!` pulls from it and runs
  the per-subscription filter matcher (`Filter::match_event`),
  emitting matching `["EVENT", subscription_id, event]` frames.
  Without this the in-process bunker test fixture could not satisfy
  the round-trip — relay clients only saw historical query results,
  never live ones.
- **Ephemeral kinds (NIP-01)**. `kind:24133` (NIP-46) sits in the
  ephemeral 20000–<30000 range. The relay's storage layer rightly
  refuses to persist them; the connection actor now ACKs
  `Rejected(Ephemeral)` as `OK true` (no message) and forwards the
  event to live subscribers anyway, matching the spec's
  broadcast-but-do-not-store semantics.

## Out of scope

- **NIP-46 server / bunker side**. Implementing the signer is its
  own ADR and a security-sensitive piece of work that needs an
  independent UX story.
- **`nula-sdk` Layer-5 facade**. Composes the above into a
  high-level `Client` once Phase 6 lands.
- **Cross-client routing-cache sharing**. Each `Gossip` is private
  to its owning process today.

## Consequences

### Positive

- Routing decisions and remote signing are first-class building
  blocks the rest of the workspace can compose without inheriting
  the upstream's tightly-coupled `Client` god-object.
- The `BrokenDownFilters` shape lets every fan-out caller decide
  what to do with `Orphan` cases — a missing routing entry never
  silently drops the request.
- The pool dual-mode in `nula-signer-connect` avoids forcing the
  caller into a private connection set; multi-account UIs stay
  resource-efficient.
- The `MockRelay` live-broadcast addition turns the in-process
  fixture into a real round-trip transport, which means every NIP
  round-trip test in this and future phases (NIP-46, NIP-17 DM,
  NIP-29 group, …) shares the same harness.

### Negative

- 25+ new public types. Documentation has to land in lockstep with
  every new behaviour to keep the surface discoverable.
- The dispatcher's pending-map is `Mutex<HashMap>` rather than the
  per-relay actor pattern from ADR-0006. We chose the simpler shape
  because every RPC is fan-in (a single source: the bunker) and the
  contention happens only inside this one client; expanding to a
  per-RPC actor adds a tokio task per request without a measurable
  upside.

### Rollback

`nula-gossip` and `nula-signer-connect` are independent crates with
no other workspace member depending on them. If a regression
surfaces post-merge we can revert either crate at HEAD without
touching downstream code; ADR-0008 still covers the relay-pool /
relay-builder pair we ship in Phase 4.

## References

- ADR-0001 — workspace architecture (13-crate plan).
- ADR-0006 — single-relay actor model.
- ADR-0008 — multi-relay orchestration.
- [NIP-17] — private direct messages and DM-relay lists.
- [NIP-46] — Nostr Connect URI scheme + RPC matrix.
- [NIP-65] — relay list metadata.
- `3rdparty/nostr/sdk/src/client/gossip/` — reference filter break-down algorithm.
- `3rdparty/nostr/signer/nostr-connect/` — reference NIP-46 client.

[`nula-relay-builder`]: ../../crates/nula-relay-builder
[`nula-relay-pool`]: ../../crates/nula-relay-pool
[`AllowedRelays`]: ../../crates/nula-gossip/src/options.rs
[`AuthUrlHandler`]: ../../crates/nula-signer-connect/src/auth.rs
[`GossipLimits`]: ../../crates/nula-gossip/src/options.rs
[`GossipOptions::min_fetch_interval`]: ../../crates/nula-gossip/src/options.rs
[`GossipOptions::refresher_batch`]: ../../crates/nula-gossip/src/options.rs
[`GossipOptions::refresher_interval`]: ../../crates/nula-gossip/src/options.rs
[`NostrConnectBuilder::auth_url_handler`]: ../../crates/nula-signer-connect/src/client.rs
[`RefresherHandle::spawn`]: ../../crates/nula-gossip/src/refresher.rs
[`RejectAuthUrl`]: ../../crates/nula-signer-connect/src/auth.rs
[NIP-17]: https://github.com/nostr-protocol/nips/blob/master/17.md
[NIP-46]: https://github.com/nostr-protocol/nips/blob/master/46.md
[NIP-65]: https://github.com/nostr-protocol/nips/blob/master/65.md
