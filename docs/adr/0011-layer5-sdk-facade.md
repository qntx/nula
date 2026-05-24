# ADR-0011: Layer-5 SDK facade lives in `nula-sdk`

**Status**: Accepted
**Date**: 2026-05-24

## Context

Phases 1-5 delivered the workspace as a stack of focused Layer-1/2/3/4
crates: `nula-core` (event / filter / signer types), `nula-net`
(transport), `nula-storage` + memory / LMDB backends, `nula-relay`
(single-relay actor), `nula-relay-pool` (multi-relay coordinator),
`nula-gossip` (NIP-65 outbox routing), `nula-sync` (NIP-77
Negentropy), `nula-signer-connect` (NIP-46 remote signer).

Phase 6 closes the stack with **Layer 5**: a single facade crate
that downstream applications can depend on instead of wiring four to
six lower-layer crates by hand. The upstream `rust-nostr` reference
ships this as `nostr-sdk::Client`; we model the same role with
`nula-sdk::Client` and `nula-sdk::ClientBuilder`.

Two design questions had to be answered before we wrote a line of
code:

1. **Surface parity vs. ergonomic divergence.** The upstream
   `nostr_sdk::Client` exposes ~42 public methods. A subset of those
   are deprecated aliases (`add_discovery_relay`, `add_read_relay`,
   `add_write_relay`, `add_gossip_relay`, `force_remove_*`,
   `wait_for_connection`) and a subset are "fluent builder" return
   types (`AddRelay<'_>`, `SendEvent<'_>`, `Subscribe<'_>`,
   `FetchEvents<'_>`) that encode call options through chained
   methods on the returned value rather than plain function args. We
   chose to **keep the operational set** and **drop the fluent
   builder pattern**: every Layer-5 method takes plain owned /
   borrowed args and returns the final `Result<…, Error>` directly.
2. **`RelayUrlArg`-style polymorphism.** Upstream uses a
   `RelayUrlArg<'_>` trait under the hood to let `add_relay(...)`
   accept `&str` / `String` / `&RelayUrl` / `RelayUrl`. We achieve
   the same shape with a local `IntoRelayUrl` trait
   (`crates/nula-sdk/src/util.rs`) — four `impl`s covering the same
   four input types, one collect helper for `Iterator<Item = U>`
   parameters, no lifetime gymnastics in the call sites.

## Decision

`nula-sdk` is a publish-on-crates.io crate that re-exports the most
common Layer-1/4 types (`Event`, `Filter`, `Keys`, `Kind`,
`SubscriptionId`, `RelayUrl`, `Output`, `RelayCapabilities`,
`Gossip`, `Reconciliation`) and exposes a single `Client`
constructed via `ClientBuilder`.

The crate ships under `Apache-2.0 OR MIT`, follows ADR-0004
(`#[non_exhaustive]` error enums) and ADR-0005 (`tracing` field
names), and is gated behind the workspace lint profile.

### Public API surface (committed)

Lifecycle and getters:

- `Client::new`, `Client::builder`, `Client::shutdown`,
  `Client::is_shutdown`, `Client::pool`, `Client::signer`,
  `Client::database`, `Client::gossip` (feature `gossip`),
  `Client::automatic_authentication`, `Client::notifications`.

Relay management:

- `Client::add_relay`, `Client::add_relay_with_capabilities`,
  `Client::remove_relay`, `Client::force_remove_relay`,
  `Client::relay`, `Client::relays`, `Client::connect`,
  `Client::try_connect`, `Client::disconnect`.

Publishing and signing:

- `Client::sign_event_builder`, `Client::send_event`,
  `Client::send_event_to`, `Client::send_event_builder`,
  `Client::send_event_builder_to`.

Fetching and streaming:

- `Client::fetch_events`, `Client::fetch_events_from`,
  `Client::stream_events`, `Client::stream_events_from`.

Subscriptions:

- `Client::subscribe`, `Client::subscribe_with_id`,
  `Client::subscribe_to`, `Client::unsubscribe`.

ClientBuilder setters (10): `signer`, `signer_arc`, `database`,
`gossip` (feature `gossip`), `websocket_transport`, `pool_options`,
`automatic_authentication`, `build()`.

### Deliberate departures from upstream

| Concern                                                                              | Upstream `nostr-sdk`                                       | `nula-sdk` (ours)                                                                              |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Per-call options                                                                     | Builder returns (`AddRelay<'_>::capabilities(...)`)        | Plain function args (`add_relay_with_capabilities(url, caps)`)                                 |
| `&str` / `String` / `RelayUrl` polymorphism                                          | `RelayUrlArg<'_>` trait                                    | `IntoRelayUrl` trait, four `impl`s                                                             |
| Deprecated capability shorthands (`add_read_relay`, `add_write_relay`, `…`)          | Kept for backward compatibility                            | Dropped; the bitflag-aware `add_relay_with_capabilities` covers the use case in one method     |
| `wait_for_connection`, `force_remove_*`, `force_remove_all_relays`                   | Kept as deprecated forwarders                              | Dropped; `connect`, `remove_relay`, and `force_remove_relay` are the canonical entry points    |
| Memory-database fallback                                                             | None — `MissingDatabase` if you forget to wire one         | Feature `memory-fallback` (default on) substitutes `MemoryDatabase::new()` for first-touch UX  |
| `Client::sync` (NIP-77 driver)                                                       | Implemented inline against `nostr-pool::Relay::sync`       | **Deferred to Phase 6.6** (needs `Relay::send_msg` upstream API; tracked as the only TODO)     |
| `Client::send_private_msg` / `Client::gift_wrap` / NIP-65 outbox helpers             | Implemented as `Client` methods                            | **Deferred to Phase 7** as additive `nula-sdk::nips::*` modules; no surface change needed      |

### Feature flags

| Feature             | Default | Purpose                                                                              |
| ------------------- | :-----: | ------------------------------------------------------------------------------------ |
| `gossip`            |   ✅    | Pull `nula-gossip`; expose `ClientBuilder::gossip` and `Client::gossip`              |
| `sync`              |   ✅    | Pull `nula-sync`; reserves the `Client::sync` slot (impl Phase 6.6)                  |
| `memory-fallback`   |   ✅    | Pull `nula-storage-memory`; default `MemoryDatabase` when `database()` was omitted   |
| `default-transport` |   ✅    | Pull `nula-relay-pool/default-transport` (tokio-tungstenite WebSocket)               |
| `nip46`             |   ❌    | Pull `nula-signer-connect`; for downstream apps using the NIP-46 bunker as a signer  |
| `tracing`           |   ❌    | Emit `tracing` spans on every public `Client` method (ADR-0005 field names)          |

## Consequences

### Positive

- **Single import for downstream applications.** A typical desktop
  client now adds `nula-sdk = "0.2"` and gets a working
  `Client` + `Keys` + `EventBuilder` import path in one line.
- **Surface stays narrow.** Dropping the deprecated shorthands and
  builder-pattern call sites kept the public method count at ~30
  rather than upstream's ~42, without losing functional coverage.
- **Feature gates mirror layer choices.** Turning `gossip` off
  removes the `nula-gossip` dependency from the build entirely;
  same for `sync`, `nip46`, `tracing`, and `default-transport`.
  No Layer-5 method is added that is feature-locked unless the
  feature itself is opt-in.
- **Memory-fallback removes the most common first-touch friction.**
  Quickstart docs no longer have to mention `nula-storage-memory`
  alongside the SDK — the SDK provides one out of the box.

### Negative

- **One more crate to publish.** `nula-sdk` joins the publish-on-
  release list (Phase 6.9). Versioning bumps must include it.
- **`Client::sync` is documented but unimplemented in v0.2.0.**
  The `sync` feature flag stays default-on so the surface gap is
  hidden behind feature gating once Phase 6.6 lands; release notes
  call this out explicitly.
- **Transitive dependency hygiene burden.** Integration tests
  binary linking pulls every Layer 1-4 crate into the test binary's
  closure; we silence the resulting `unused_crate_dependencies`
  lints with explicit `use … as _;` pins in `tests/integration.rs`.
  This is a known Rust 2024 lint quirk, not a real soundness
  issue.

### Neutral

- **Builder pattern divergence.** Some upstream call sites need to
  port from `client.add_relay(url).capabilities(caps).await?` to
  `client.add_relay_with_capabilities(url, caps).await?`. The
  rename table in this ADR covers every divergence; a Phase 7
  migration cookbook will spell them out for downstream readers.
- **Layer-5 has no DM helpers in v0.2.0.** NIP-17 / NIP-65
  outbox / NIP-42 helpers are additive — adding them later is a
  minor-version bump rather than a breaking change.

## Alternatives Considered

### Minimal MVP facade (`new` + 7 methods)

Rejected. The user explicitly chose the full facade option during
Phase 6.4 scoping. The marginal cost of porting the additional ~20
methods after the skeleton was in place was small (~250 LOC in one
commit), and the resulting surface is good enough to claim
"`nostr-sdk` equivalent" in release notes.

### Re-export `nostr-sdk` directly

Rejected at workspace-creation time (ADR-0001). The point of the
fork is to evolve along axes the upstream does not prioritise; the
SDK facade has to be ours so we can tune the call surface (e.g.
plain args vs. builder pattern, no deprecated shorthands).

### Single `nula` umbrella crate

Rejected. The workspace ships every Layer separately so downstream
code can pin only what it uses (e.g. relay servers don't need
Layer 4 / 5). `nula-sdk` is the recommended starting point but not
the only one.

## References

- ADR-0001 — Workspace architecture.
- ADR-0002 — `rust-nostr` reference vendoring.
- ADR-0004 — Error handling via `thiserror`.
- ADR-0005 — Observability field conventions for `tracing`.
- ADR-0008 — Multi-relay orchestration architecture.
- ADR-0009 — Multi-relay routing & remote signer architecture.
- ADR-0010 — NIP-77 Negentropy as a standalone crate.
- [Upstream `nostr-sdk::Client`](https://docs.rs/nostr-sdk/latest/nostr_sdk/client/struct.Client.html).
- Vendored upstream reference: `3rdparty/nostr/sdk/src/client/mod.rs`
  (pinned at ADR-0002's reference SHA).
