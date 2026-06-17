# nula-signer-browser

NIP-07 `window.nostr` browser-extension signer for
[nula](https://github.com/qntx/nula). Implements
[`nula_core::NostrSigner`] by delegating to a NIP-07 extension
(Alby, nos2x, …) injected into the page.

This crate compiles **only for `wasm32`**; on every other target it is
empty. It is detached from the parent workspace (like `nula-fuzz`)
because the wasm build needs a `getrandom_backend="wasm_js"` cfg and a
wasm-capable C toolchain for `secp256k1-sys`.

## Method mapping

| `NostrSigner` method | `window.nostr` call           |
| -------------------- | ----------------------------- |
| `get_public_key`     | `getPublicKey()`              |
| `sign_event`         | `signEvent(event)`            |
| `nip04_encrypt`      | `nip04.encrypt(pubkey, text)` |
| `nip04_decrypt`      | `nip04.decrypt(pubkey, text)` |
| `nip44_encrypt`      | `nip44.encrypt(pubkey, text)` |
| `nip44_decrypt`      | `nip44.decrypt(pubkey, text)` |

## Design notes

- **No `unsafe`.** `window.nostr` is reached dynamically through the
  safe `js_sys::Reflect` / `Function` / `JSON` surface rather than a
  `#[wasm_bindgen] extern "C"` block, so the crate keeps
  `#![forbid(unsafe_code)]`.
- **Stateless ⇒ `Send + Sync`.** `BrowserSigner` is zero-sized and
  re-reads `window.nostr` on every call, so it satisfies
  `NostrSigner: Send + Sync` with no `unsafe impl`. The returned
  futures are `!Send` (they hold `JsValue`s), which is exactly why
  `nula_core::signer::SignerFuture` drops its `Send` bound on `wasm32`.
- **Hardened `sign_event`.** The event returned by the extension is
  re-verified (`Event::verify`, id + Schnorr signature) and rejected if
  its `pubkey` differs from the unsigned author.

## Usage

```rust,ignore
use nula_core::NostrSigner;
use nula_signer_browser::BrowserSigner;

let signer = BrowserSigner::new();
let pubkey = signer.get_public_key().await?;
let event = signer.sign_event(unsigned).await?;
```

## Building

```sh
rustup target add wasm32-unknown-unknown

# secp256k1-sys compiles C to wasm, so a wasm-capable clang/llvm-ar is
# required (the system Apple clang has no wasm backend). macOS example:
brew install llvm

CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
AR_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/llvm-ar" \
CFLAGS_wasm32_unknown_unknown="-Wno-implicit-function-declaration" \
cargo build --target wasm32-unknown-unknown --release
```

The `getrandom_backend="wasm_js"` cfg is supplied automatically by
`.cargo/config.toml`. The `CFLAGS` flag relaxes a `memmove` implicit
declaration that recent clang versions treat as an error; the symbol is
provided by LLVM builtins at link time.

## Testing

Tests use `wasm-bindgen-test` and require a wasm runner:

```sh
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
AR_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/llvm-ar" \
CFLAGS_wasm32_unknown_unknown="-Wno-implicit-function-declaration" \
wasm-pack test --headless --firefox
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

[`nula_core::NostrSigner`]: https://docs.rs/nula-core
