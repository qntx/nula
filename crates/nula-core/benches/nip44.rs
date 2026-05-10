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

//! NIP-44 v2 encrypt / decrypt baselines.
//!
//! NIP-44 sits on the inner loop of every gift-wrapped DM (NIP-17),
//! every Nostr Connect message (NIP-46), and every modern direct
//! message. The two costliest steps are `HKDF-Expand` (76-byte OKM) and
//! `ChaCha20` over the padded plaintext; the bench varies the plaintext
//! size to expose both.
//!
//! The fixture `ConversationKey` and nonce come from the official NIP-44
//! v2 valid vectors (`get_message_keys` test #1), so reproductions and
//! cross-implementation comparisons are unambiguous.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nula_core::nips::nip44::{ConversationKey, decrypt_with_conversation_key, encrypt_with_nonce};

/// First valid `get_message_keys` conversation key from `nip44.vectors.json`.
const CONVERSATION_KEY_HEX: &str =
    "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54";
const NONCE_HEX: &str = "e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72";

const PLAINTEXT_SIZES: &[usize] = &[16, 256, 4_096, 32_768];

fn fixture_conversation_key() -> ConversationKey {
    let mut bytes = [0_u8; 32];
    nula_core::util::hex::decode_to_slice(CONVERSATION_KEY_HEX, &mut bytes)
        .expect("known vector decodes");
    ConversationKey::from_byte_array(bytes)
}

fn fixture_nonce() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    nula_core::util::hex::decode_to_slice(NONCE_HEX, &mut bytes).expect("known vector decodes");
    bytes
}

fn make_plaintext(size: usize) -> String {
    "a".repeat(size)
}

fn bench_encrypt(c: &mut Criterion) {
    let key = fixture_conversation_key();
    let nonce = fixture_nonce();
    let mut group = c.benchmark_group("nip44/encrypt");
    for &size in PLAINTEXT_SIZES {
        let plaintext = make_plaintext(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &plaintext,
            |b, plaintext| {
                b.iter(|| {
                    let payload = encrypt_with_nonce(
                        std::hint::black_box(&key),
                        std::hint::black_box(plaintext.as_str()),
                        std::hint::black_box(&nonce),
                    )
                    .expect("encryption succeeds");
                    std::hint::black_box(payload);
                });
            },
        );
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let key = fixture_conversation_key();
    let nonce = fixture_nonce();
    let mut group = c.benchmark_group("nip44/decrypt");
    for &size in PLAINTEXT_SIZES {
        let fixture = make_plaintext(size);
        let payload =
            encrypt_with_nonce(&key, &fixture, &nonce).expect("fixture encryption succeeds");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                let decrypted = decrypt_with_conversation_key(
                    std::hint::black_box(&key),
                    std::hint::black_box(payload.as_str()),
                )
                .expect("payload decrypts");
                std::hint::black_box(decrypted);
            });
        });
    }
    group.finish();
}

fn bench_conversation_key_derive(c: &mut Criterion) {
    use nula_core::{PublicKey, SecretKey};

    let secret =
        SecretKey::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .expect("BIP-340 vector key parses");
    let peer = PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("BIP-340 vector pubkey parses");
    c.bench_function("nip44/conversation_key/derive", |b| {
        b.iter(|| {
            let key =
                ConversationKey::derive(std::hint::black_box(&secret), std::hint::black_box(&peer));
            std::hint::black_box(key);
        });
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_conversation_key_derive,
);
criterion_main!(benches);
