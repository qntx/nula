# nula-net

Runtime-agnostic Nostr WebSocket transport trait with an opt-out
`tokio-tungstenite` default implementation.

`nula-net` sits at Layer 2 of the [`nula`] workspace. It provides:

- a `WebSocketTransport` trait — object-safe, returns `BoxFuture`;
- typed `Message`, `CloseFrame`, `ConnectionMode`, and `Error`;
- a default `tokio`-backed implementation behind the
  `default-transport` feature (on by default);
- a `MockTransport` for tests behind the `mock` feature.

## Quickstart

```rust,no_run
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nula_core::RelayUrl;
use nula_net::{ConnectionMode, IntoWebSocketTransport, Message};

# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
let transport = nula_net::default::DefaultTransport::new().into_transport();
let url = RelayUrl::parse("wss://relay.damus.io")?;
let (mut sink, mut stream) = transport.connect(&url, &ConnectionMode::Direct).await?;

sink.send(Message::text(r#"["REQ","sub", {}]"#)).await?;

while let Some(frame) = stream.next().await {
    if let Message::Text(s) = frame? {
        println!("{s}");
    }
}
# Ok(()) }
```

## Feature flags

| Feature             | Default | Description                                                                                  |
| ------------------- | :-----: | -------------------------------------------------------------------------------------------- |
| `default-transport` |   ✅    | Bundle a `tokio-tungstenite`-backed `DefaultTransport` plus rustls + webpki roots for TLS.   |
| `mock`              |   ❌    | `MockTransport` and `MockHandle` for upper-layer integration tests.                          |
| `tracing`           |   ❌    | Emit `tracing` spans on handshake, send, recv. Field names follow ADR-0005 conventions.      |

Disable defaults for wasm or fully custom backends:

```toml
nula-net = { version = "0.1", default-features = false }
```

[`nula`]: https://github.com/qntx/nula
