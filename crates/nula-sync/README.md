# nula-sync

NIP-77 [Negentropy](https://github.com/hoytech/negentropy) reconciliation
sessions and storage adapters for the [`nula`](https://github.com/qntx/nula)
workspace.

## What it does

Negentropy is a set-reconciliation algorithm that lets two peers, each
holding a (potentially huge) set of `(EventId, created_at)` items,
discover which items are missing on each side with logarithmic
bandwidth and round trips. NIP-77 wraps that algorithm in three
wire frames — `NEG-OPEN`, `NEG-MSG`, `NEG-CLOSE` — that we already
model in [`nula_core::ClientMessage`] / [`nula_core::RelayMessage`].

This crate gives you:

- A typed [`Reconciliation`] session that wraps the upstream
  [`negentropy::Negentropy`] state machine.
- A [`prepare_storage`] helper that converts an iterator of
  `(EventId, Timestamp)` pairs into a sealed
  [`negentropy::NegentropyStorageVector`].
- An optional [`storage::from_database`] adapter (behind the
  `storage` feature) that turns a [`nula_storage::NostrDatabase`]
  + [`nula_core::Filter`] into a ready-to-use session.
- Reusable hex encoding / decoding helpers for the NIP-77 wire form.

The actual transport loop (open a subscription, fan messages across
a [`nula_relay_pool::RelayPool`], download missing events,
upload events the relay does not have) is **not** part of this crate
— that lives in [`nula-sdk`](../nula-sdk/) so the algorithm stays
runtime-free and trivially testable.

## Quickstart

```rust,no_run
use nula_core::{EventId, Timestamp};
use nula_sync::{prepare_storage, Reconciliation};

# fn doc() -> Result<(), nula_sync::Error> {
let mine: Vec<(EventId, Timestamp)> = Vec::new(); // load from your DB
let storage = prepare_storage(mine)?;
let mut session = Reconciliation::initiate(&storage)?;

// 1. Send `session.opening_message()` to the relay as the initial
//    `NEG-MSG` payload inside a `NEG-OPEN` frame.
let _wire_hex: &str = session.opening_message_hex();

// 2. Each time the relay replies with `NEG-MSG`, feed the bytes back
//    in. The output tells you what's new on either side and whether
//    the session is complete.
// let outcome = session.reconcile_hex(&relay_message_hex)?;
# Ok(()) }
```

See [the ADR](../../docs/adr/0010-nip77-negentropy-as-standalone-crate.md)
for why this is a standalone crate.

## Workspace ADRs

- [ADR-0010](../../docs/adr/0010-nip77-negentropy-as-standalone-crate.md)
  records the decision to keep Negentropy out of `nula-core` and
  `nula-relay`.
- [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md) shapes
  the [`Error`] surface.
