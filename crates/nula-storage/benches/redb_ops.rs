// Each bench file is its own crate pulling in the shared workspace
// dev-dependency set; only a subset is used here, and criterion's
// `criterion_group!` emits an undocumented `pub fn benches()`. Bench
// code uses the same panicking idioms the unit tests are allowed.
#![allow(
    missing_docs,
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::allow_attributes_without_reason,
    reason = "bench harness conventions: see the comment block above this attribute"
)]

//! redb backend hot paths: save, query, count, NIP-77 negentropy items.
//!
//! These guard the persistent read/write path against regressions —
//! especially the zero-parse projection behind `query` /
//! `negentropy_items` (P2): a regression that reintroduced a full
//! secp256k1 point-parse per stored candidate would show up here as a
//! large query/negentropy slowdown at the larger store sizes.
//!
//! Every bench builds a fresh redb file under a `TempDir`; read-path
//! benches pre-fill the store once, write-path benches start each
//! timed sample from an empty store via `iter_batched`.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use nula_core::event::{Event, EventBuilder};
use nula_core::filter::Filter;
use nula_core::key::Keys;
use nula_core::types::Timestamp;
use nula_storage::NostrDatabase;
use nula_storage::redb::RedbDatabase;
use tempfile::TempDir;
use tokio::runtime::Runtime;

const FIXTURE_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
/// Pre-fill sizes for the read-path benches.
const STORE_SIZES: &[usize] = &[100, 1_000];

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds")
}

fn fixture_keys() -> Keys {
    Keys::parse(FIXTURE_SECRET).expect("BIP-340 vector key parses")
}

/// Distinct, deterministically-signed text note per index (unique id +
/// strictly increasing `created_at` so none collide or replace).
fn make_event(keys: &Keys, i: usize) -> Event {
    EventBuilder::text_note(format!("note-{i}"))
        .created_at(Timestamp::from_secs(1_700_000_000 + i as u64))
        .sign_with_keys(keys)
        .expect("signing is infallible")
}

async fn fresh_db() -> (RedbDatabase, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("bench.redb");
    let db = RedbDatabase::builder(path)
        .build()
        .await
        .expect("redb opens");
    (db, dir)
}

async fn prefilled(keys: &Keys, n: usize) -> (RedbDatabase, TempDir) {
    let (db, dir) = fresh_db().await;
    for i in 0..n {
        db.save_event(&make_event(keys, i)).await.expect("save");
    }
    (db, dir)
}

fn bench_save(c: &mut Criterion) {
    let rt = runtime();
    let keys = fixture_keys();
    c.bench_function("redb/save_event", |b| {
        b.iter_batched(
            // Setup (untimed): a fresh empty store + a unique event.
            || {
                let (db, dir) = rt.block_on(fresh_db());
                (db, dir, make_event(&keys, 0))
            },
            // Routine (timed): the first save into an empty store.
            |(db, _dir, event)| {
                rt.block_on(db.save_event(&event)).expect("save");
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_query(c: &mut Criterion) {
    let rt = runtime();
    let keys = fixture_keys();
    let author = *keys.public_key();
    let mut group = c.benchmark_group("redb/query");
    for &n in STORE_SIZES {
        let (db, _dir) = rt.block_on(prefilled(&keys, n));
        group.bench_with_input(BenchmarkId::new("empty", n), &n, |b, _| {
            b.iter(|| {
                let events = rt.block_on(db.query(Filter::new())).expect("query");
                std::hint::black_box(events);
            });
        });
        group.bench_with_input(BenchmarkId::new("author", n), &n, |b, _| {
            b.iter(|| {
                let events = rt
                    .block_on(db.query(Filter::new().author(author)))
                    .expect("query");
                std::hint::black_box(events);
            });
        });
    }
    group.finish();
}

fn bench_negentropy_items(c: &mut Criterion) {
    let rt = runtime();
    let keys = fixture_keys();
    let mut group = c.benchmark_group("redb/negentropy_items");
    for &n in STORE_SIZES {
        let (db, _dir) = rt.block_on(prefilled(&keys, n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let items = rt
                    .block_on(db.negentropy_items(Filter::new()))
                    .expect("negentropy_items");
                std::hint::black_box(items);
            });
        });
    }
    group.finish();
}

fn bench_count(c: &mut Criterion) {
    let rt = runtime();
    let keys = fixture_keys();
    let (db, _dir) = rt.block_on(prefilled(&keys, 1_000));
    c.bench_function("redb/count", |b| {
        b.iter(|| {
            let total = rt.block_on(db.count(Filter::new())).expect("count");
            std::hint::black_box(total);
        });
    });
}

criterion_group!(
    benches,
    bench_save,
    bench_query,
    bench_negentropy_items,
    bench_count,
);
criterion_main!(benches);
