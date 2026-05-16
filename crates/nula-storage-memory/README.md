# nula-storage-memory

In-memory event store backend for the `nula` workspace.

`nula-storage-memory` implements the
[`nula_storage::NostrDatabase`](https://docs.rs/nula-storage) trait
against a `BTreeSet`-and-`HashMap` core. Suitable for tests, ephemeral
relay pools, and any caller that does not need on-disk persistence.

## Status

Pre-release. Trait surface tracks `nula-storage` versioned in lockstep.

## License

Dual-licensed under MIT OR Apache-2.0.
