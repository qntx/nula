# nula-storage-lmdb

LMDB-backed persistent event store for the `nula` workspace.

`nula-storage-lmdb` implements the
[`nula_storage::NostrDatabase`](https://docs.rs/nula-storage) trait
against an LMDB environment (via [`heed`](https://docs.rs/heed)). Events
are encoded with `postcard` and stored alongside five secondary indexes
that serve the common NIP-01 filter shapes without a full-table scan.

## Status

Pre-release. Trait surface tracks `nula-storage` versioned in lockstep.

## License

Dual-licensed under MIT OR Apache-2.0.
