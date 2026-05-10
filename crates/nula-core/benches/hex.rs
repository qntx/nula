// See benches/event.rs for the rationale; same allow set applies to
// every bench in this directory.
#![allow(
    missing_docs,
    unused_crate_dependencies,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::missing_assert_message,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::excessive_nesting,
    clippy::explicit_into_iter_loop,
    clippy::allow_attributes_without_reason,
    reason = "bench harness conventions; see benches/event.rs"
)]

//! `util::hex` baseline benchmarks.
//!
//! Hex encode / decode is on every Nostr hot path: pubkeys, event ids,
//! tag values, signatures all round-trip through it. The crate uses
//! `faster-hex` underneath, which auto-selects SIMD where available;
//! these benches pin throughput so we'd notice if a refactor swapped to
//! a slower fallback.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nula_core::util::hex;

const SIZES: &[usize] = &[32, 64, 1_024];

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hex/encode");
    for &size in SIZES {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &bytes, |b, bytes| {
            b.iter(|| {
                let s = hex::encode(std::hint::black_box(bytes));
                std::hint::black_box(s);
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hex/decode");
    for &size in SIZES {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let encoded = hex::encode(&bytes);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &encoded, |b, encoded| {
            b.iter(|| {
                let decoded = hex::decode(std::hint::black_box(encoded.as_str()))
                    .expect("encoded round-trips");
                std::hint::black_box(decoded);
            });
        });
    }
    group.finish();
}

fn bench_decode_to_slice_32(c: &mut Criterion) {
    let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
    let encoded = hex::encode(bytes);
    c.bench_function("hex/decode_to_slice/32", |b| {
        b.iter(|| {
            let mut out = [0_u8; 32];
            hex::decode_to_slice(std::hint::black_box(encoded.as_str()), &mut out)
                .expect("round-trips");
            std::hint::black_box(out);
        });
    });
}

criterion_group!(
    benches,
    bench_encode,
    bench_decode,
    bench_decode_to_slice_32
);
criterion_main!(benches);
