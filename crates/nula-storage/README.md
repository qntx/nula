# nula-storage

Nostr event-store trait surface plus first-party backends for the
`nula` workspace.

`nula-storage` defines [`NostrDatabase`] — a runtime-agnostic, dyn-safe
trait that any Nostr event store must implement — plus the protocol
semantics shared by every backend (NIP-09 deletion, NIP-40 expiration,
replaceable / addressable / ephemeral kind routing, NIP-62 vanish).

Backends ship as feature-gated modules, so a default build is
pure-Rust with zero C dependencies:

| Feature      | Module                     | Storage                 | Use case                  |
| ------------ | -------------------------- | ----------------------- | ------------------------- |
| `memory`     | `nula_storage::memory`     | `BTreeMap` + indexes    | Tests, ephemeral pools    |
| `redb`       | `nula_storage::redb`       | redb (pure-Rust B-tree) | Persistent client / relay |
| `test-suite` | `nula_storage::test_suite` | conformance harness     | Backend authors           |

`memory` is on by default; the persistent `redb` backend and the
conformance suite are opt-in. Every backend is pure Rust — even a
`redb` build links no C libraries and carries no `unsafe` code.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
