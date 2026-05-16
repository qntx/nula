# nula-relay-pool

Multi-relay orchestration on top of [`nula-relay`].

`nula-relay-pool` is Layer 4 of the [`nula`] workspace: it manages a
set of single-relay clients ([`nula_relay::Relay`]), dispatches each
`publish` / `subscribe` operation across the configured fan-out, and
deduplicates events so callers never observe the same `EventId`
twice.

## What it is

- A coordinator over `Arc<dyn nula_storage::NostrDatabase>` and
  `HashMap<RelayUrl, Relay>`.
- A partial-success aware API surface (`Output<T>`).
- A `Stream<(RelayUrl, Result<Event>)>` builder that LRU-deduplicates
  across relays.
- A drop-shutdown handle (clones share state via `Arc`; the last
  drop disconnects every relay).

## What it is not

- It does **not** discover relays itself. Pair it with `nula-gossip`
  for NIP-65 outbox/inbox routing.
- It does **not** manage signing. Pair it with a signer in
  `nula-signer-connect` (NIP-46) or supply your own.
- It does **not** model trust / admission. Spam policies live in the
  SDK / application layer.

## Crate layout

See [`ADR-0008`] for the architecture record.

[`nula`]: https://github.com/qntx/nula
[`nula-relay`]: ../nula-relay
[`nula_relay::Relay`]: ../nula-relay/src/relay.rs
[`ADR-0008`]: ../../docs/adr/0008-multi-relay-orchestration.md
