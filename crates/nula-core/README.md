# nula-core

Protocol primitives for the [Nostr] protocol — events, filters, keys, messages, and shared types used across the `nula` workspace.

`nula-core` is the lowest layer of the workspace and is consumed by every client- or relay-facing crate. It deliberately avoids any I/O, async runtime, or networking dependency so it can be reused in tests, embedded relays, signers, and offline tooling.

## Modules

- `util` — hex / random / hash helpers and JSON traits used by every other module.
- `types` — `Timestamp`, `Url`, `RelayUrl`, image dimensions, and other shared
  value objects.
- `key` — `SecretKey`, `PublicKey`, and the `Keys` keypair (BIP-340 Schnorr).
- `event` — `Event`, `EventBuilder`, `UnsignedEvent`, `EventId`, `Kind`, `Tag`,
  `TagKind`, `TagStandard`, `Tags`.
- `filter` — `Filter`, `Alphabet`, `SingleLetterTag`.
- `message` — `ClientMessage`, `RelayMessage`, `SubscriptionId` plus the
  serialization rules described by NIP-01.
- `signer` — the `NostrSigner` trait used by every higher-level crate.
- `parser` — unified token stream that recognises NIP-21 references,
  URLs (NIP-27), hashtags (NIP-12), and line breaks in a single pass.

## Examples

Eight runnable examples live under [`examples/`](./examples/); each is opt-in via `cargo run --example <name>`. Pass `--features <feature>` for examples that need an opt-in NIP module.

| Example                  | Topic                                        | Required features |
|--------------------------|----------------------------------------------|-------------------|
| `01_basic_event`         | Generate keys, sign a kind-1 note, verify    | —                 |
| `04_dm_legacy`           | NIP-04 DM round-trip + tamper detection      | `nip04`           |
| `05_nip05_lookup`        | NIP-05 address parsing + offline verify      | —                 |
| `19_bech32_round_trip`   | Encode/decode every NIP-19 entity            | —                 |
| `44_payload`             | NIP-44 v2 encrypt/decrypt + size guards      | `nip44`           |
| `46_remote_signer`       | NIP-46 connect handshake (typed envelope)    | `nip46`           |
| `57_zap_request`         | NIP-57 zap request build + round-trip        | —                 |
| `99_parser`              | Walk a note with `NostrParser` token stream  | —                 |

[Nostr]: https://github.com/nostr-protocol/nostr

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
