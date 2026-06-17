# nula-keyring

Persist Nostr `Keys` in the operating system's native secret store.

`nula-keyring` is a thin async wrapper over the [`keyring`](https://docs.rs/keyring) crate, plumbed for `nula-core`'s [`Keys`] type. Secrets land in:

- **macOS** — Keychain (via `apple-native`)
- **Linux** — Secret Service over D-Bus (via `linux-native` /
  `linux-native-sync-persistent` for headless fallback)
- **Windows** — Credential Manager (via `windows-native`)

## Example

```rust,no_run
# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
use nula_core::Keys;
use nula_keyring::Keyring;

let keyring = Keyring::new("com.example.myapp");

// Generate + persist.
let keys = Keys::generate()?;
keyring.set("primary", &keys).await?;

// Reload on the next launch.
let restored = keyring.get("primary").await?;
assert_eq!(restored.public_key(), keys.public_key());

// Forget.
keyring.delete("primary").await?;
# Ok(()) }
```

Every async method has a sync sibling (`set_blocking`, `get_blocking`, `delete_blocking`) for callers that already run on a synchronous boundary.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
