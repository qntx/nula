# ADR-0004: Error handling via `thiserror`

**Status**: Accepted
**Date**: 2026-05-14

## Context

Every layer in the workspace surfaces fallible operations: NIP-44
decryption, bech32 decoding, WebSocket I/O, LMDB transactions,
NIP-46 RPC, gossip routing. We need a single error-handling style
that:

- preserves the **source chain** so a caller can walk
  `std::error::Error::source()` and find the underlying I/O,
  cryptographic, or protocol failure;
- supports **structured matching** at API boundaries (a SDK consumer
  may want to retry on `Error::Transport(_)` but bubble up
  `Error::Protocol(_)`);
- stays **non-exhaustive** so adding a variant in a minor release
  does not break downstream pattern matches;
- carries **`Send + Sync + 'static`** automatically because every
  future in the workspace is `Send` (see ADR-0003);
- compiles with `#![forbid(unsafe_code)]` and our strict clippy
  `pedantic` + `nursery` lint set.

The reference checkout uses a mix of hand-written `Display`
implementations (`database/nostr-database/src/error.rs`) and ad-hoc
`Box<dyn Error>` boxing. We have already standardised on `thiserror`
in `nula-core` (see `crates/nula-core/src/event/error.rs`,
`crates/nula-core/src/nips/nip44.rs`, etc.); this ADR records the
contract so the upper layers do not regress.

## Decision

Every public error enum across the workspace is defined with
`thiserror::Error` under the following constraints:

1. **Module-local `Error` enum**. The crate root exports a top-level
   `Error` for the most common boundary (e.g.
   `nula_core::Error`). Submodules with non-trivial failure surfaces
   (NIP-44, NIP-46, NIP-19) keep their own narrower enum (e.g.
   `nip44::Error`) and the crate-level enum has a `#[from]`
   conversion arm.
2. **`#[non_exhaustive]` on every public enum**. Variants are
   additive; consumers must `_ =>` match.
3. **One source per variant**. Use `#[source]` for the underlying
   cause, never `#[from]` plus a manual `From` impl. If two
   underlying types should map to one variant, introduce a
   `#[from]` newtype that holds either.
4. **`Send + Sync + 'static` is mandatory**. No boxed `&dyn Trait`
   inside variants without those bounds. Trait objects must use
   `Box<dyn Error + Send + Sync + 'static>` (we add the alias
   `nula_core::error::AnyError` for this).
5. **No `anyhow` or `eyre` in public APIs**. Application binaries
   (`nula-cli`, examples) may use `anyhow::Result` internally; library
   crates may not.
6. **Display messages are user-facing**. They contain enough context
   to triage without consulting source code (e.g. include the URL
   that failed to connect, the NIP number, the event id prefix), but
   never include secret material (see ADR-0005 redaction rules).
7. **`#[track_caller]` on constructor methods** of error variants
   that carry hand-built messages (`Error::msg("...")` style). This
   makes panicking unit tests show the test line rather than the
   `Error::msg` implementation.
8. **No `String` variants**. Every variant either carries typed
   data or a `'static str` description. Free-form strings end up as
   black boxes for downstream pattern matching.

### Template

```rust
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("transport: {0}")]
    Transport(#[from] crate::transport::Error),

    #[error("decode {kind}: {context}")]
    Decode {
        kind: &'static str,
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("relay {url} closed the stream: {reason}")]
    RelayClosed {
        url: crate::types::RelayUrl,
        reason: &'static str,
    },
}
```

### Cross-crate conversion

When a higher layer wraps a lower layer's error, it does so with a
single `#[from]` arm:

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Core(#[from] nula_core::Error),

    #[error(transparent)]
    Net(#[from] nula_net::Error),
    // …
}
```

`#[error(transparent)]` keeps the lower-level message intact so the
caller sees the most precise variant when printing.

## Consequences

### Positive

- Consumers can implement structured retry policies by matching on
  enum variants without parsing `Display` strings.
- `cargo doc` renders every error variant with its message and
  source type, making the failure surface part of the public API.
- `large_error_threshold = 128` in `clippy.toml` is enforceable; our
  `Error` enums stay below ~80 bytes, which means `Result<T, Error>`
  remains cheap to pass by value.

### Negative

- Adding a new wrapped backend means writing a `#[from]` arm in two
  places (the inner crate and the SDK façade). This is mechanical.
- We cannot use `?` to convert two different boxed sources into one
  enum variant — that would require a manual `From`. We accept this
  for clarity.

### Rollback

If we ever need a uniform "I don't care" error type for upper-layer
glue code, we can introduce an `Error::Other(AnyError)` arm without
changing existing variants because the enum is non-exhaustive. This
is the only sanctioned escape hatch.

## References

- ADR-0001 — Workspace architecture.
- ADR-0003 — Async runtime layering.
- [`thiserror`](https://docs.rs/thiserror/latest/thiserror/).
- [`std::error::Error::source`](https://doc.rust-lang.org/std/error/trait.Error.html#method.source).
