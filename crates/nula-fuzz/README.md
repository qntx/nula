# nula-fuzz

Coverage-guided fuzz harnesses for `nula-core`, built on [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) + `libFuzzer`. This crate is **detached from the parent workspace** — `cargo-fuzz` injects nightly-only RUSTFLAGS that would otherwise break the stable workspace build.

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target                  | Property under test                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| `canonical_bytes_cross` | `compute_event_id` matches a hand-rolled `serde_json::to_vec` path   |
| `nip19_round_trip`      | NIP-19 `decode → encode → decode` is idempotent and deterministic    |
| `nip44_decrypt`         | `nip44::decrypt` returns a `Result` for any input, never panics      |
| `filter_match_event`    | `Filter` JSON round-trips byte-identically; `matches` never panics   |
| `nip77_payload_decode`  | NIP-77 Negentropy `decode_payload` is total; round-trips re-encode   |
| `client_message_parse`  | `ClientMessage` `from_str` is total; successful parses round-trip    |
| `relay_message_parse`   | `RelayMessage` `from_str` is total; successful parses round-trip     |

## Quick start

```bash
# Run from the workspace root.
cd crates/nula-fuzz

# Build every target (verifies the harness compiles).
cargo +nightly fuzz build

# Smoke run for 10 seconds.
cargo +nightly fuzz run canonical_bytes_cross -- -max_total_time=10
cargo +nightly fuzz run nip19_round_trip      -- -max_total_time=10
cargo +nightly fuzz run nip44_decrypt          -- -max_total_time=10
cargo +nightly fuzz run filter_match_event    -- -max_total_time=10
cargo +nightly fuzz run nip77_payload_decode  -- -max_total_time=10
cargo +nightly fuzz run client_message_parse  -- -max_total_time=10
cargo +nightly fuzz run relay_message_parse   -- -max_total_time=10

# Long-running soak: an hour per target gives meaningful coverage.
cargo +nightly fuzz run canonical_bytes_cross -- -max_total_time=3600 -workers=8 -jobs=8
```

## Triage

Crashes land in `crates/nula-fuzz/artifacts/<target>/`. Reproduce with:

```bash
cargo +nightly fuzz run <target> crates/nula-fuzz/artifacts/<target>/crash-<hash>
```

Then minimise and capture as a regression test inside the corresponding `crates/nula-core/src/...` module before fixing.

## Adding a target

1. Drop a new `fuzz_targets/<name>.rs` containing a `fuzz_target!`
   block.
2. Add the matching `[[bin]]` stanza to `crates/nula-fuzz/Cargo.toml`.
3. Document the property under test in the table above.

Keep targets focused: one invariant per harness keeps crashes attributable.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
