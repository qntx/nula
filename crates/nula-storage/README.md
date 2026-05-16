# nula-storage

Layer-3 event-store trait surface for the `nula` workspace.

`nula-storage` defines [`NostrDatabase`] — a runtime-agnostic, dyn-safe
trait that any Nostr event store must implement — plus the protocol
semantics shared by every backend (NIP-09 deletion, NIP-40 expiration,
replaceable / addressable / ephemeral kind routing, NIP-62 vanish).

Two first-party backends live in sibling crates:

| Crate                 | Storage                | Use case                       |
| --------------------- | ---------------------- | ------------------------------ |
| `nula-storage-memory` | `BTreeSet` + indexes   | Tests, ephemeral pools         |
| `nula-storage-lmdb`   | LMDB (`heed`)          | Persistent client / relay      |

## Status

Pre-release. Crate version `0.1.0`; the trait surface may evolve
incompatibly until the workspace cuts its first SemVer tag.

## License

Dual-licensed under MIT OR Apache-2.0.
