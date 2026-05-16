# nula-relay-builder

Programmable in-process Nostr relay server.

`nula-relay-builder` is Layer 4 of the [`nula`] workspace. It binds
a real `tokio::net::TcpListener`, speaks NIP-01 over WebSocket via
`tokio-tungstenite`, persists events through any
[`nula_storage::NostrDatabase`] backend, and accepts pluggable
[`WritePolicy`] / [`ReadPolicy`] hooks for filtering inbound traffic.

## Why a real server?

The crate exists for two purposes:

1. **End-to-end integration tests** for upper layers
   (`nula-relay-pool`, `nula-gossip`, `nula-sdk`). A pool that talks
   to a real WebSocket relay catches a different category of bug
   than one that drives `nula-net::mock`.
2. **Local development** — running a full Nostr stack against a
   throw-away relay on `127.0.0.1:0` avoids depending on the public
   relay graph for fast iteration.

The builder deliberately omits TLS, multi-host routing, and
production-grade rate limiting. Reach for [`nostr-rs-relay`] or a
similar binary when those are needed.

[`nula`]: https://github.com/qntx/nula
[`WritePolicy`]: src/policy.rs
[`ReadPolicy`]: src/policy.rs
[`nula_storage::NostrDatabase`]: ../nula-storage/src/database.rs
[`nostr-rs-relay`]: https://github.com/scsibug/nostr-rs-relay
