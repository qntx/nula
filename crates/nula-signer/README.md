# nula-signer-connect

> NIP-46 (Nostr Connect) remote signer client.

Layer 4 crate that lets a Nostr application sign events through a
remote bunker (NIP-46) without ever touching the user's secret key.
Built on top of [`nula-relay-pool`] for transport and exposes the
familiar [`nula_core::NostrSigner`] trait so any code already wired
against an in-process [`nula_core::Keys`] keeps working.

## Highlights

- **Both URI flows**: signer-initiated `bunker://` and
  client-initiated `nostrconnect://`. The client validates the
  `secret` echo to rule out impersonation in the `nostrconnect://`
  path.
- **All nine RPCs**: `connect`, `get_public_key`, `sign_event`,
  `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`,
  `nip44_decrypt`, `ping`, `switch_relays`.
- **Two pool modes**: bring your own `Arc<RelayPool>` to share
  connections with the rest of your app, or let the client build a
  short-lived embedded pool.
- **Object-safe `NostrSigner` impl**: drop into any
  `Arc<dyn NostrSigner>` slot without further glue.
- **`AuthUrlHandler`** trait for backends that want to surface the
  signer's `auth_url` UX prompts.

See [ADR-0009](../../docs/adr/0009-multi-relay-routing-remote-signer.md)
for the full design record.

[`nula-relay-pool`]: https://docs.rs/nula-relay-pool/
[`nula_core::Keys`]: https://docs.rs/nula-core/
[`nula_core::NostrSigner`]: https://docs.rs/nula-core/
