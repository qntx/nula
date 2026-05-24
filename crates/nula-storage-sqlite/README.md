# nula-storage-sqlite

SQLite-backed [`nula_storage::NostrDatabase`](https://docs.rs/nula-storage)
implementation for the `nula` workspace.

## Architecture

This backend pairs a vendored [SQLite] file (used as an append-only
event log) with an in-process
[`nula_storage_memory::MemoryDatabase`](https://docs.rs/nula-storage-memory)
serving every read path. The SQLite layer survives across process
restarts; the in-memory layer enforces every NIP-09 / NIP-40 /
replaceable / addressable / NIP-62 protocol rule.

On startup the crate walks the SQLite `events` table and replays
every record through the in-memory store -- the same protocol logic
runs on the in-memory side, so the final state is identical to a
freshly-running process.

| Path                | Where it lives                                    |
| ------------------- | ------------------------------------------------- |
| `save_event`        | Memory enforcement → SQLite append on `Success`   |
| `event_by_id`       | Memory only                                       |
| `query`             | Memory only                                       |
| `count`             | Memory only                                       |
| `negentropy_items`  | Memory only                                       |
| `delete`            | Memory delete → SQLite `DELETE WHERE id IN (...)` |
| `wipe`              | Memory wipe → SQLite `DELETE FROM events`         |

This split is intentional: SQLite is an excellent durability story
but a poor index for the kind of multi-clause filtering NIP-01
demands. The memory replica handles the hot read path; SQLite
handles "survive a reboot".

## Quickstart

```rust,no_run
# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
use nula_storage::NostrDatabase;
use nula_storage_sqlite::SqliteDatabase;

let db = SqliteDatabase::open("./events.sqlite").await?;
let count = db.count(nula_core::Filter::new()).await?;
println!("stored events: {count}");
# Ok(()) }
```

[SQLite]: https://www.sqlite.org/index.html
