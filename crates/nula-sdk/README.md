# nula-sdk

Layer-5 Nostr SDK facade for the [`nula`](https://github.com/qntx/nula)
workspace. Composes the lower layers — `nula-core` (events / filters),
`nula-relay` (multi-relay coordinator), `nula-gossip` (NIP-65
outbox routing), `nula-sync` (NIP-77 Negentropy), `nula-signer`
(NIP-46 remote signer) — into a single [`Client`] + [`ClientBuilder`]
mirroring the surface of `nostr-sdk::Client` from the
[`rust-nostr`](https://github.com/rust-nostr/nostr) reference.

The crate is the only one downstream applications should need to depend
on for typical Nostr client work.

## Feature flags

| Feature            | Default | Description                                                                |
| ------------------ | :-----: | -------------------------------------------------------------------------- |
| `gossip`           |   ✅    | NIP-65 outbox routing helpers (re-export [`nula_gossip::Gossip`]).         |
| `sync`             |   ✅    | NIP-77 reconciliation via [`nula_sync`].                                   |
| `nip46`            |   ❌    | NIP-46 remote signer integration via [`nula_signer`].              |
| `default-transport`|   ✅    | Pull a tokio-tungstenite WebSocket transport from `nula-relay`.       |
| `tracing`          |   ❌    | Emit `tracing` spans on every public `Client` method (ADR-0005 fields).    |

## Quickstart

```rust,no_run
use std::time::Duration;
use nula_core::{EventBuilder, Filter, Keys, Kind};
use nula_sdk::Client;

# async fn doc() -> Result<(), nula_sdk::Error> {
let keys = Keys::generate().expect("OS RNG");
let client = Client::builder().signer(keys).build()?;

client.add_relay("wss://relay.example.com").await?;
client.connect().await;

// Publish.
let note = EventBuilder::text_note("Hello, nostr!");
client.send_event_builder(note).await?;

// Subscribe.
let filter = Filter::new().kind(Kind::TEXT_NOTE).limit(10);
let events = client.fetch_events(filter, Duration::from_secs(5)).await?;
for event in events.iter() {
    println!("{}: {}", event.pubkey, event.content);
}

client.shutdown().await;
# Ok(()) }
```

See [ADR-0011](../../docs/adr/0011-layer5-sdk-facade.md) for the
rationale behind the chosen API surface and the deliberate departures
from the upstream `nostr-sdk` shape.
