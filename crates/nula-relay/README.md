# nula-relay

The Nostr relay layer of the [`nula`] workspace: a runtime-agnostic
WebSocket transport, a single-relay [NIP-01] client, a multi-relay
pool, and an in-process relay server — all in one crate, gated by
features.

| Module                  | Feature             | Purpose                                              |
| ----------------------- | ------------------- | ---------------------------------------------------- |
| `nula_relay::transport` | _always_            | `WebSocketTransport` trait + default / mock impls    |
| `nula_relay` (root)     | _always_            | Single-relay NIP-01 client state machine             |
| `nula_relay::pool`      | `pool` (default)    | Multi-relay orchestration with cross-relay dedup     |
| `nula_relay::server`    | `server`            | In-process programmable relay server (tests / dev)   |

The single-relay client wraps a
`nula_relay::transport::WebSocketTransport` with the protocol state
machine — connection lifecycle, reconnect backoff, REQ/CLOSE
subscription tracking, EVENT/EOSE/CLOSED dispatch, publish ACK
correlation, and an optional NIP-42 AUTH challenge handler.

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
| `default-transport` |   ✅    | Ship the tokio-tungstenite transport so `Relay::new(url)` works out of the box. |
| `nip42`             |   ✅    | Expose the `AuthHandler` trait + `Relay::on_auth(...)` hook.                    |
| `pool`              |   ✅    | The `nula_relay::pool` module: multi-relay orchestration.                       |
| `mock`              |   ❌    | The `nula_relay::transport::mock` transport for upper-layer tests.              |
| `server`            |   ❌    | The `nula_relay::server` module: in-process relay server.                       |
| `tracing`           |   ❌    | Emit `tracing` spans on every state transition / dispatch decision.             |

Disable defaults to plug in a custom transport:

```toml
nula-relay = { version = "0.1", default-features = false }
```

[NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md
[`nula`]: https://github.com/qntx/nula
