# W1 baseline (2026-05-10)

First Phase 1 baseline. Numbers are the median of criterion's three
estimates; throughput is reported when criterion measured it.

## Environment

- **OS / arch**: Darwin / arm64 (Apple Silicon)
- **Rust**: `rustc 1.95.0 (59807616e 2026-04-14)`
- **Profile**: `bench` (release + LTO thin + 1 codegen unit)
- **Workload**: `--quick` for `event` / `nip19` / `nip44`; full run for `hex`
- **Notes**: numbers below are taken on a laptop under user load and are
  intended as **trend pins**, not absolute SLAs. Codspeed CI will own
  the deterministic baseline once W2 wires it in.

## Event (NIP-01)

| Bench                       | Median time | Throughput     |
|-----------------------------|------------:|---------------:|
| `event/canonical/16`        | n/a         | n/a            |
| `event/canonical/256`       | n/a         | n/a            |
| `event/canonical/4096`      | n/a         | n/a            |
| `event/sign/0`              | n/a         | n/a            |
| `event/sign/4`              | n/a         | n/a            |
| `event/sign/32`             | n/a         | n/a            |
| `event/verify/16`           | ~12 µs      | ~1.24 MiB/s    |
| `event/verify/256`          | 12.38 µs    | 19.72 MiB/s    |
| `event/verify/4096`         | 14.18 µs    | 275.57 MiB/s   |
| `event/unsigned_id`         | 320.50 ns   | —              |
| `event/json_round_trip/16`  | 2.69 µs     | 159.71 MiB/s   |
| `event/json_round_trip/256` | 2.71 µs     | 242.73 MiB/s   |
| `event/json_round_trip/4096`| 2.99 µs     | 1.4132 GiB/s   |

## Hex (`util::hex`)

| Bench                       | Median time | Throughput     |
|-----------------------------|------------:|---------------:|
| `hex/decode/32`             | 39.56 ns    | 771.51 MiB/s   |
| `hex/decode/64`             | 68.39 ns    | 892.40 MiB/s   |
| `hex/decode/1024`           | 852.51 ns   | 1.1187 GiB/s   |
| `hex/decode_to_slice/32`    | 25.30 ns    | —              |

## NIP-19 (bech32)

| Bench                       | Median time |
|-----------------------------|------------:|
| `nip19/encode/npub`         | n/a         |
| `nip19/decode/npub`         | n/a         |
| `nip19/encode/nsec`         | 203.80 ns   |
| `nip19/decode/nsec`         | 326.04 ns   |
| `nip19/encode/note`         | 202.86 ns   |
| `nip19/decode/note`         | 324.30 ns   |
| `nip19/encode/nprofile`     | 291.66 ns   |
| `nip19/decode/nprofile`     | 2.578 µs    |
| `nip19/encode/nevent`       | 474.22 ns   |
| `nip19/decode/nevent`       | 2.835 µs    |

## NIP-44 v2

| Bench                              | Median time | Throughput     |
|------------------------------------|------------:|---------------:|
| `nip44/encrypt/16`                 | 591.56 ns   | 25.79 MiB/s    |
| `nip44/encrypt/256`                | 869.78 ns   | 280.69 MiB/s   |
| `nip44/encrypt/4096`               | 5.44 µs     | 717.72 MiB/s   |
| `nip44/encrypt/32768`              | 39.97 µs    | 781.84 MiB/s   |
| `nip44/decrypt/16`                 | 604.44 ns   | 25.25 MiB/s    |
| `nip44/decrypt/256`                | 849.25 ns   | 287.48 MiB/s   |
| `nip44/decrypt/4096`               | 5.24 µs     | 744.83 MiB/s   |
| `nip44/decrypt/32768`              | 39.09 µs    | 799.44 MiB/s   |
| `nip44/conversation_key/derive`    | 17.54 µs    | —              |

## Observations

- **NIP-44 throughput** plateaus at ~780 MiB/s for big payloads, dominated
  by `ChaCha20`. The fixed cost (~600 ns) is HKDF-Expand + padded-buffer
  setup; for 16-byte messages that's ~95 % of the total.
- **`hex/decode_to_slice/32` is ~36 % faster** than `hex/decode/32`,
  matching the SIMD path in `faster-hex` when the output buffer is
  caller-provided. Worth surfacing this in NIP-19 / NIP-01 hot paths.
- **NIP-19 TLV decode (nprofile/nevent)** is ~8× slower than the simple
  HRPs (`nsec`/`note`). Bech32 decode itself is fast; the cost lives in
  TLV parsing. Candidate for W3+ optimisation.
- **`event/canonical/16`** missed measurement under `--quick`; rerun
  with `--baseline w1` after W2 wires Codspeed CI for full coverage.

## Targets to beat in future weeks

- W3 `smallvec` adoption: `event/sign/32` median ↓ ≥ 15 %
- W4 `bytes::Bytes` for content: `event/json_round_trip/4096` ↑ ≥ 20 % throughput
- W5 NIP-19 TLV parser revisit: `nip19/decode/nevent` ↓ ≥ 30 %
