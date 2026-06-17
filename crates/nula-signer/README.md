# nula-signer

> NIP-46 (Nostr Connect) remote signer client.

Lets a Nostr application sign events through a remote bunker (NIP-46)
without ever touching the user's secret key. Built on top of
[`nula_relay::pool::RelayPool`] for transport and exposes the
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

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
