# nula-relay

Single-relay [NIP-01] state machine: connection lifecycle,
reconnect backoff, REQ/CLOSE subscription tracking, EVENT/EOSE/CLOSED
dispatch, publish ACK correlation, and an optional NIP-42 AUTH
challenge handler.

`nula-relay` sits at Layer 3 of the [`nula`] workspace. It wraps a
`nula_net::WebSocketTransport` with the protocol state machine —
multi-relay orchestration lives one layer higher in
`nula-relay-pool`.

## Quickstart

```rust,no_run
use futures::StreamExt;
use nula_core::{EventBuilder, Filter, Keys, Kind, RelayUrl, SubscriptionId};
use nula_relay::{Relay, SubscribeOptions};

# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
let url = RelayUrl::parse("wss://relay.damus.io")?;
let relay = Relay::new(url);
relay.connect().await?;

let sub = SubscriptionId::generate()?;
let filters = vec![Filter::new().kind(Kind::TEXT_NOTE).limit(10)];
let mut handle = relay
    .subscribe(sub, filters, SubscribeOptions::default())
    .await?;

while let Some(item) = handle.next().await {
    println!("{item:?}");
}
# Ok(()) }
```

## Feature flags

| Feature             | Default | Description                                                                     |
| ------------------- | :-----: | ------------------------------------------------------------------------------- |
| `default-transport` |   ✅    | Pull in `nula-net/default-transport` so `Relay::new(url)` works out of the box. |
| `nip42`             |   ✅    | Expose the `AuthHandler` trait + `Relay::on_auth(...)` hook.                    |
| `tracing`           |   ❌    | Emit `tracing` spans on every state transition / dispatch decision.             |

Disable defaults to plug in a custom transport:

```toml
nula-relay = { version = "0.1", default-features = false }
```

[NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md
[`nula`]: https://github.com/qntx/nula
