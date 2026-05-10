// Each bench file is its own crate that pulls in the shared workspace
// dev-dependencies set; only a subset of those is used here, and
// criterion's `criterion_group!` macro emits an undocumented `pub fn
// benches()`. Bench code is also free to use the same panicking idioms
// the unit tests are allowed to (see `lib.rs`'s `#[cfg(test)]` allow
// block). Lifting these lints here keeps the production lint set
// strict everywhere else.
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
    reason = "bench harness conventions: see the comment block above this attribute"
)]

//! NIP-01 hot paths: canonical hashing, signing, verifying, JSON round-trip.
//!
//! These four targets cover the per-event cost incurred by every
//! relay-bound message:
//!
//! - `canonical/<size>` — `compute_event_id` over a synthetic event with
//!   `<size>`-byte content. Measures pure SHA-256 + canonical JSON
//!   serialisation.
//! - `sign/<tags>` — `EventBuilder::sign_with_keys` end-to-end, varying
//!   the tag count to surface tag-serialisation overhead.
//! - `verify/<size>` — `Event::verify` (id + Schnorr).
//! - `json_round_trip/<size>` — full `to_json` -> `from_json` cycle.
//!
//! The fixture key is BIP-340 test vector 0 so reproductions and
//! manual cross-checks against `rust-nostr` / `nostr-tools` are stable.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nula_core::{
    Event, EventBuilder, JsonUtil, Keys, Kind, Tag, Tags, Timestamp, UnsignedEvent,
    compute_event_id,
};

const FIXTURE_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const CONTENT_SIZES: &[usize] = &[16, 256, 4_096];
const TAG_COUNTS: &[usize] = &[0, 4, 32];

fn fixture_keys() -> Keys {
    Keys::parse(FIXTURE_SECRET).expect("BIP-340 vector key parses")
}

fn make_content(size: usize) -> String {
    "a".repeat(size)
}

fn make_tags(count: usize) -> Tags {
    let tags: Vec<Tag> = (0..count)
        .map(|i| Tag::new(["e", &format!("event-{i:032x}")]).expect("`e` tag is well-formed"))
        .collect();
    Tags::from_vec(tags)
}

fn fixture_event(content_size: usize, tag_count: usize) -> Event {
    let keys = fixture_keys();
    let mut builder = EventBuilder::new(Kind::TEXT_NOTE, make_content(content_size))
        .created_at(Timestamp::from_secs(1_700_000_000));
    for tag in make_tags(tag_count).into_iter() {
        builder = builder.tag(tag);
    }
    builder
        .sign_with_keys(&keys)
        .expect("signing is infallible")
}

fn bench_canonical(c: &mut Criterion) {
    let mut group = c.benchmark_group("event/canonical");
    for &size in CONTENT_SIZES {
        let keys = fixture_keys();
        let pubkey = *keys.public_key();
        let created_at = Timestamp::from_secs(1_700_000_000);
        let tags = make_tags(2);
        let content = make_content(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let id = compute_event_id(
                    std::hint::black_box(&pubkey),
                    std::hint::black_box(created_at),
                    std::hint::black_box(Kind::TEXT_NOTE),
                    std::hint::black_box(&tags),
                    std::hint::black_box(&content),
                );
                std::hint::black_box(id);
            });
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("event/sign");
    let keys = fixture_keys();
    for &tag_count in TAG_COUNTS {
        group.bench_with_input(
            BenchmarkId::from_parameter(tag_count),
            &tag_count,
            |b, &tag_count| {
                b.iter(|| {
                    let mut builder = EventBuilder::new(Kind::TEXT_NOTE, "hello, nostr")
                        .created_at(Timestamp::from_secs(1_700_000_000));
                    for tag in make_tags(tag_count).into_iter() {
                        builder = builder.tag(tag);
                    }
                    let event = builder
                        .sign_with_keys(&keys)
                        .expect("signing is infallible");
                    std::hint::black_box(event);
                });
            },
        );
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("event/verify");
    for &size in CONTENT_SIZES {
        let event = fixture_event(size, 2);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &event, |b, event| {
            b.iter(|| {
                event.verify().expect("event verifies");
            });
        });
    }
    group.finish();
}

fn bench_unsigned_canonical(c: &mut Criterion) {
    let keys = fixture_keys();
    let unsigned = UnsignedEvent::new(
        *keys.public_key(),
        Timestamp::from_secs(1_700_000_000),
        Kind::TEXT_NOTE,
        make_tags(2),
        make_content(256),
    );
    c.bench_function("event/unsigned_id", |b| {
        b.iter(|| {
            let id = unsigned.compute_id();
            std::hint::black_box(id);
        });
    });
}

fn bench_json_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("event/json_round_trip");
    for &size in CONTENT_SIZES {
        let event = fixture_event(size, 2);
        let json = event.try_to_json().expect("event serialises");
        group.throughput(Throughput::Bytes(json.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &json,
            |b, json: &String| {
                b.iter(|| {
                    let parsed = Event::from_json(json).expect("event parses");
                    std::hint::black_box(parsed);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_canonical,
    bench_sign,
    bench_verify,
    bench_unsigned_canonical,
    bench_json_round_trip,
);
criterion_main!(benches);
