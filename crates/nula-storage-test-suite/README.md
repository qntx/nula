# nula-storage-test-suite

Reusable conformance suite for any backend that implements
[`nula_storage::NostrDatabase`].

Backend authors implement the small
[`DatabaseFactory`] trait — one async constructor and one lifetime
guard — and call [`run_suite`]. The suite asserts:

- save-path semantics (success, duplicate, ephemeral, NIP-40
  expiration, NIP-09 deletion, replaceable / addressable replacement);
- query-path semantics (every `QueryPattern` shape, ordering,
  inclusive time bounds, `count` agreement with `query`,
  `delete` without tombstoning);
- concurrency safety (many concurrent saves into the same handle).

Capability-gated cases (currently `Features::FULL_TEXT_SEARCH`,
`Features::BOUNDED_CAPACITY`) are skipped automatically when the
backend does not advertise them.

The crate is `publish = false`: it only lives in the workspace as a
dev-dependency for first- and third-party storage backends.

## Usage

```rust,ignore
use std::sync::Arc;

use nula_storage::NostrDatabase;
use nula_storage_test_suite::{DatabaseFactory, run_suite};

struct MyBackendFactory;

impl DatabaseFactory for MyBackendFactory {
    type Guard = ();

    async fn build(&self) -> (Arc<dyn NostrDatabase>, ()) {
        let db = MyBackend::new().await;
        (Arc::new(db), ())
    }
}

#[tokio::test]
async fn conformance() {
    run_suite(&MyBackendFactory).await;
}
```

For backends that need temp-directory cleanup, point `Guard` at a
`TempDir` (or any other RAII handle) and the suite will drop it
between cases.
