# nula-keyring

Persist Nostr `Keys` in the operating system's native secret store.

`nula-keyring` is a thin async wrapper over the
[`keyring`](https://docs.rs/keyring) crate, plumbed for `nula-core`'s
[`Keys`] type. Secrets land in:

- **macOS** — Keychain (via `apple-native`)
- **Linux** — Secret Service over D-Bus (via `linux-native` /
  `linux-native-sync-persistent` for headless fallback)
- **Windows** — Credential Manager (via `windows-native`)

## Why a separate crate

The OS keyring backends pull in heavy native bindings (`Security.framework`
on macOS, `secret-service` on Linux, `wincred` on Windows). Keeping them
behind a separate crate means the rest of the workspace stays
zero-cost when an application doesn't actually need persistent secret
storage.

## Quickstart

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

## Sync API

Every async method has a sync sibling (`set_blocking`, `get_blocking`,
`delete_blocking`) for callers that already run on a synchronous
boundary -- e.g. CLI startup paths or system tray menus. The async
methods schedule the same blocking work on tokio's blocking pool so
they never starve the runtime.

[`Keys`]: https://docs.rs/nula-core/latest/nula_core/key/struct.Keys.html
