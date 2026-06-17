# nula-nwc

NIP-47 Nostr Wallet Connect client.

Drive a remote Lightning wallet service over encrypted direct messages on top of a [`nula_relay::pool::RelayPool`].

## Features

| Feature             | Default | Description              |
| ------------------- | :-----: | ------------------------ |
| `nip04`             |   ✅    | Legacy NIP-04 fallback.  |
| `default-transport` |   ❌    | Embedded WebSocket pool. |

## Example

```rust,no_run
use std::sync::Arc;

use nula_nwc::{ConnectionUri, NostrWalletConnect, PayInvoiceRequest};
use nula_relay::pool::RelayPool;

# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
let uri = ConnectionUri::parse(
    "nostr+walletconnect://b889ff5b...?relay=wss://relay.example&secret=71a8c14c...",
)?;
let pool = RelayPool::builder().build()?;
let nwc = NostrWalletConnect::builder()
    .uri(uri)
    .embedded_pool(pool)
    .build()
    .await?;

let balance = nwc.get_balance().await?;
println!("balance: {} msat", balance.balance);
# Ok(()) }
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
