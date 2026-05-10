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

//! NIP-19 bech32 encode / decode baselines.
//!
//! Every npub/nsec/note seen by an end user goes through this path.
//! The bench covers the three simple HRPs (npub, nsec, note) plus the
//! two TLV-bearing entities (`nprofile`, `nevent`) so we can spot a
//! regression caused by the encoder or by the TLV serialisation layer.

use criterion::{Criterion, criterion_group, criterion_main};
use nula_core::nips::nip19::{Nip19Event, Nip19Profile};
use nula_core::{EventId, FromBech32, PublicKey, SecretKey, ToBech32};

const PUBKEY_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const NOTE_HEX: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn fixture_pubkey() -> PublicKey {
    PublicKey::parse(PUBKEY_HEX).expect("BIP-340 sample parses")
}

fn fixture_seckey() -> SecretKey {
    SecretKey::parse(SECRET_HEX).expect("non-zero scalar")
}

fn fixture_event_id() -> EventId {
    EventId::parse(NOTE_HEX).expect("32-byte hex parses")
}

fn bench_encode_npub(c: &mut Criterion) {
    let pk = fixture_pubkey();
    c.bench_function("nip19/encode/npub", |b| {
        b.iter(|| {
            let s = pk.to_bech32().expect("encodes");
            std::hint::black_box(s);
        });
    });
}

fn bench_decode_npub(c: &mut Criterion) {
    let s = fixture_pubkey().to_bech32().expect("encodes");
    c.bench_function("nip19/decode/npub", |b| {
        b.iter(|| {
            let pk = PublicKey::from_bech32(std::hint::black_box(&s)).expect("decodes");
            std::hint::black_box(pk);
        });
    });
}

fn bench_encode_nsec(c: &mut Criterion) {
    let sk = fixture_seckey();
    c.bench_function("nip19/encode/nsec", |b| {
        b.iter(|| {
            let s = sk.to_bech32().expect("encodes");
            std::hint::black_box(s);
        });
    });
}

fn bench_decode_nsec(c: &mut Criterion) {
    let s = fixture_seckey().to_bech32().expect("encodes");
    c.bench_function("nip19/decode/nsec", |b| {
        b.iter(|| {
            let sk = SecretKey::from_bech32(std::hint::black_box(&s)).expect("decodes");
            std::hint::black_box(sk);
        });
    });
}

fn bench_encode_note(c: &mut Criterion) {
    let id = fixture_event_id();
    c.bench_function("nip19/encode/note", |b| {
        b.iter(|| {
            let s = id.to_bech32().expect("encodes");
            std::hint::black_box(s);
        });
    });
}

fn bench_decode_note(c: &mut Criterion) {
    let s = fixture_event_id().to_bech32().expect("encodes");
    c.bench_function("nip19/decode/note", |b| {
        b.iter(|| {
            let id = EventId::from_bech32(std::hint::black_box(&s)).expect("decodes");
            std::hint::black_box(id);
        });
    });
}

fn bench_encode_nprofile(c: &mut Criterion) {
    let profile = Nip19Profile {
        public_key: fixture_pubkey(),
        relays: Vec::new(),
    };
    c.bench_function("nip19/encode/nprofile", |b| {
        b.iter(|| {
            let s = profile.to_bech32().expect("encodes");
            std::hint::black_box(s);
        });
    });
}

fn bench_decode_nprofile(c: &mut Criterion) {
    let profile = Nip19Profile {
        public_key: fixture_pubkey(),
        relays: Vec::new(),
    };
    let s = profile.to_bech32().expect("encodes");
    c.bench_function("nip19/decode/nprofile", |b| {
        b.iter(|| {
            let p = Nip19Profile::from_bech32(std::hint::black_box(&s)).expect("decodes");
            std::hint::black_box(p);
        });
    });
}

fn bench_encode_nevent(c: &mut Criterion) {
    let nev = Nip19Event {
        event_id: fixture_event_id(),
        author: Some(fixture_pubkey()),
        kind: None,
        relays: Vec::new(),
    };
    c.bench_function("nip19/encode/nevent", |b| {
        b.iter(|| {
            let s = nev.to_bech32().expect("encodes");
            std::hint::black_box(s);
        });
    });
}

fn bench_decode_nevent(c: &mut Criterion) {
    let nev = Nip19Event {
        event_id: fixture_event_id(),
        author: Some(fixture_pubkey()),
        kind: None,
        relays: Vec::new(),
    };
    let s = nev.to_bech32().expect("encodes");
    c.bench_function("nip19/decode/nevent", |b| {
        b.iter(|| {
            let n = Nip19Event::from_bech32(std::hint::black_box(&s)).expect("decodes");
            std::hint::black_box(n);
        });
    });
}

criterion_group!(
    benches,
    bench_encode_npub,
    bench_decode_npub,
    bench_encode_nsec,
    bench_decode_nsec,
    bench_encode_note,
    bench_decode_note,
    bench_encode_nprofile,
    bench_decode_nprofile,
    bench_encode_nevent,
    bench_decode_nevent,
);
criterion_main!(benches);
