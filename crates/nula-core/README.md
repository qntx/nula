# nula-core

Protocol primitives for the [Nostr] protocol — events, filters, keys, messages,
and shared types used across the `nula` workspace.

`nula-core` is the lowest layer of the workspace and is consumed by every
client- or relay-facing crate. It deliberately avoids any I/O, async runtime, or
networking dependency so it can be reused in tests, embedded relays, signers,
and offline tooling.

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

[Nostr]: https://github.com/nostr-protocol/nostr
