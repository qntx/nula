# nula-core benchmarks

Criterion benches that pin the performance baseline for the hot paths in
`nula-core`. Each file targets a single subsystem so a regression points
straight at the responsible module.

| Bench file       | Subsystem under test                                  |
|------------------|--------------------------------------------------------|
| `event.rs`       | NIP-01 canonical hashing, signing, verifying           |
| `hex.rs`         | `util::hex` encode / decode (SIMD-aware via `faster-hex`) |
| `nip19.rs`       | bech32 encode / decode (`npub`, `nsec`, `note`)        |
| `nip44.rs`       | NIP-44 v2 encrypt / decrypt round trip                 |

## Running locally

```bash
# All benches (release build):
cargo bench -p nula-core

# A single bench:
cargo bench -p nula-core --bench event

# Only one Criterion target inside a bench:
cargo bench -p nula-core --bench nip44 -- "encrypt/64"
```

The default `cargo bench` runs in `release` mode. Use a stable, idle
machine: criterion's noise threshold is 5 % by default and a busy laptop
will spuriously flag regressions.

## Baselines

Phase 1 baselines live in `<workspace>/.bench/`:

```bash
# Save the current run as the W1 baseline:
cargo bench -p nula-core -- --save-baseline w1

# Compare a later run to it:
cargo bench -p nula-core -- --baseline w1
```

`--save-baseline` writes Criterion's per-target reports under
`target/criterion/<bench>/<id>/<baseline>/`; the workspace `.bench/`
directory captures the summary index for documentation.

## Adding a new bench

1. Create `benches/<name>.rs` using the template:

   ```rust
   use criterion::{Criterion, criterion_group, criterion_main};

   fn bench_<name>(c: &mut Criterion) {
       c.bench_function("<name>/baseline", |b| b.iter(|| {
           // Hot path under measurement.
       }));
   }

   criterion_group!(benches, bench_<name>);
   criterion_main!(benches);
   ```

2. Register it under `[[bench]]` in `crates/nula-core/Cargo.toml` with
   `harness = false` (criterion supplies its own).

3. Wire feature flags via `required-features = [...]` if the bench
   depends on a non-default cargo feature.
