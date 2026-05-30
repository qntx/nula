# nula-gossip

> NIP-65 / NIP-17 multi-relay routing graph.

Layer 4 crate that turns a stream of Nostr events into a routing
table: which relays does each user **read** from, **write** to, or
prefer for **direct messages**? `nula-gossip` answers those
questions and breaks every outgoing `Filter` into the per-relay
sub-filters the [`nula-relay`] crate fans out.

## What it covers

- **NIP-65** (`kind:10002`) outbox / inbox lists with `read` / `write`
  markers (parsed by [`nula_core::nips::nip65`]).
- **NIP-17** (`kind:10050`) DM relay lists (parsed by
  [`nula_core::nips::nip17`]).
- **Hints** — relays advertised inline as `r` tag values on regular
  events.
- **Most-received** — per-user histogram of which relay actually
  delivered each event.
- **Background refresher** — optional tokio task that periodically
  re-pulls the NIP-65 / NIP-17 list of every user whose entry has
  expired according to the configured TTL.
- **`AllowedRelays` filter** — onion / local / no-tls toggles.
- **`break_down_filter`** — translate a single user-facing
  [`nula_core::Filter`] into the `HashMap<RelayUrl, Filter>` that the
  relay pool can fan out, plus an explicit `Orphan` / `Generic`
  fallback for the cases where routing is impossible.

## What it does **not** cover

- A relay-pool replacement. `nula-gossip` returns relay sets; the
  pool drives the wire.
- A signer. See [`nula-signer`] for NIP-46 remote signing.
- NIP-46 server / bunker side. Out of scope until a future phase.

See [ADR-0009](../../docs/adr/0009-multi-relay-routing-remote-signer.md)
for the full design record.

[`nula_core::nips::nip17`]: https://docs.rs/nula-core/
[`nula_core::nips::nip65`]: https://docs.rs/nula-core/
[`nula_core::Filter`]: https://docs.rs/nula-core/
[`nula-relay`]: https://docs.rs/nula-relay/
[`nula-signer`]: https://docs.rs/nula-signer/
