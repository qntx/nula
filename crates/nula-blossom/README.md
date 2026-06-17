# nula-blossom

Blossom blob transport client with NIP-24242 authorization.

Upload, download, and manage content-addressed blobs over HTTP. Every blob is identified by its SHA-256 digest and authorized with a signed `kind:24242` Nostr event.

## Example

```rust,no_run
use std::sync::Arc;

use nula_blossom::BlossomClient;
use nula_core::{Keys, NostrSigner, Url};

# async fn doc() -> Result<(), Box<dyn std::error::Error>> {
let signer: Arc<dyn NostrSigner> = Arc::new(Keys::generate()?);
let client = BlossomClient::new(signer);
let server = Url::parse("https://cdn.example.com")?;

let descriptor = client
    .upload(&server, b"hello blossom".to_vec(), Some("text/plain"))
    .await?;
let bytes = client.download(&server, &descriptor.sha256).await?;
assert_eq!(bytes, b"hello blossom");
# Ok(()) }
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
