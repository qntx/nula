# nula

Layer-5 Nostr umbrella facade. Composes `nula-core` (events / filters),
`nula-relay` (multi-relay coordinator), `nula-gossip` (NIP-65 outbox
routing), `nula-sync` (NIP-77 Negentropy), and `nula-signer` (NIP-46
remote signer) into a single [`Client`] + [`ClientBuilder`].

## Feature flags

| Feature             | Default | Description                          |
| ------------------- | :-----: | -----------------------------------  |
| `gossip`            |   ✅    | NIP-65 outbox routing.               |
| `sync`              |   ✅    | NIP-77 reconciliation.               |
| `nip46`             |   ❌    | NIP-46 remote signer.                |
| `default-transport` |   ✅    | Built-in WebSocket transport.        |
| `tracing`           |   ❌    | `tracing` spans on `Client` methods. |

## Example

```rust,no_run
use std::time::Duration;
use nula_core::{EventBuilder, Filter, Keys, Kind};
use nula::Client;

# async fn doc() -> Result<(), nula::Error> {
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
