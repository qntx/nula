# ADR-0003: Async runtime layering strategy

**Status**: Accepted
**Date**: 2026-05-14

## Context

The workspace spans layers with very different runtime constraints:

- `nula-core` is pure protocol code. No timers, no sockets, no
  blocking. It must build for `wasm32-unknown-unknown` and for
  embedded `std`-only targets without dragging in a runtime.
- `nula-net` exposes async traits over WebSocket transports. The
  _trait surface_ must remain runtime-agnostic so we can plug in
  `tokio-tungstenite` natively, `wasm-bindgen`'s `WebSocket` in
  browsers, and (later) custom transports for embedded systems. The
  crate _also_ ships a default `tokio-tungstenite` implementation
  behind a feature gate so the common-case install is immediately
  useful — see the "Default-impl gating" section below.
- `nula-relay`, `nula-storage-lmdb`, `nula-relay-pool`, `nula-gossip`,
  `nula-signer-connect`, `nula-sdk`, `nula-cli` are firmly inside
  Tokio territory: timers, `mpsc` channels, `Arc<RwLock>`, structured
  concurrency. Trying to abstract over executors at this level adds
  generics with no upside — every realistic deployment is on Tokio.

Upstream `rust-nostr` already solved this with a similar split (look
at `sdk/src/transport/websocket.rs`: the trait returns `BoxedFuture`
and only the default `tokio-tungstenite` transport opts into Tokio).
We are adopting the same idea with sharper names.

The question is **how strict the trait surface is**:

- Option A: every public async method in lower layers (≤ `nula-net`)
  returns `BoxFuture<'_, T>` so callers can implement it on any
  runtime.
- Option B: lower layers expose async methods directly via `async fn`
  in traits (stable since Rust 1.75). Implementers commit to a
  runtime when they implement.
- Option C: hybrid — `BoxFuture` for "transport-shaped" traits
  (WebSocket, Storage backends) and `async fn` everywhere else.

`async fn` in traits is ergonomic but inherits one major restriction:
the returned future is not nameable, which blocks `dyn Trait` usage.
Transport and storage traits **must** be object-safe (we erase the
backend behind `Arc<dyn …>` in the pool layer), so they need the
explicit `BoxFuture` return type.

## Decision

We adopt **Option C (hybrid)** with these contracts:

- **Object-safe traits in layers 2–3 return `BoxFuture<'_, Result<…, Error>>`**.
  Examples:
  - `nula_net::WebSocketTransport::connect(&self, url: &RelayUrl, mode: &ConnectionMode) -> BoxFuture<'_, Result<(WebSocketSink, WebSocketStream), Error>>`
  - `nula_storage::NostrDatabase::save_event(&self, event: &Event) -> BoxFuture<'_, Result<(), Error>>`
- **Non-object-safe helpers may use `async fn`**. The
  `nula_storage::NostrDatabaseExt` trait, for instance, can use
  `async fn` because callers only need it via the concrete backend
  type or via the parent `NostrDatabase` trait that already returns
  `BoxFuture`.
- **Upper layers (`nula-relay`, `nula-relay-pool`, `nula-gossip`,
  `nula-sdk`, `nula-cli`) depend on Tokio**. They use `tokio::time`,
  `tokio::sync::{mpsc, broadcast, RwLock}`, `tokio::task::spawn`.
  The Tokio version is pinned at the workspace level
  (`tokio = "1.x"`, latest stable LTS at port time).
- **`nula-core` is runtime-free**. It does not import `tokio` even
  behind a feature flag. The only async surface it exposes is on the
  `NostrSigner` trait, which already uses `BoxFuture<'_, …>` per
  upstream convention.
- **No `async-trait` macro**. `BoxFuture` is hand-written; the macro
  adds a `Pin<Box<…>>` allocation per method call and a private
  lifetime parameter that compounds with our generic signing
  bounds. Hand-writing keeps the rustdoc output legible.
- **`#[must_use]` on every future-returning method** to surface
  silently-dropped subscriptions and connection futures during code
  review.

### Concrete `BoxFuture` alias

`nula-net` exports a single alias used by every dependent crate. On
non-wasm targets it carries the `Send` bound so futures move between
Tokio tasks; on `wasm32-unknown-unknown` the bound is dropped because
browser-side futures rarely satisfy it:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;
```

`WebSocketSink` and `WebSocketStream` are aliased the same way (with
the `Send` bound on native, without it on wasm). This keeps the
public types in sync with the futures they yield, so a single
`#[cfg]` flip switches the whole crate between native and wasm
shapes.

### Default-impl gating

`nula-net` is a single crate, but the runtime cost is split via Cargo
features:

| Feature             | Default | Pulls in                                               |
| ------------------- | :-----: | ------------------------------------------------------ |
| _none_              |    —    | Trait surface only — compiles on `wasm32`.             |
| `default-transport` |   ✅    | `tokio` + `tokio-tungstenite` + rustls + webpki-roots. |
| `mock`              |   ❌    | `tokio::sync::mpsc` for `MockTransport`.               |
| `tracing`           |   ❌    | `tracing` spans on handshake/send/recv.                |

A wasm consumer or someone supplying a custom backend writes
`nula-net = { default-features = false }` and gets a pure trait
crate. Native consumers do nothing and inherit a working client.

This mirrors `reqwest`'s shape (default `default-tls` ships rustls +
the native impl; opt out for fully custom transports) and keeps
upper layers (`nula-relay`, `nula-relay-pool`, `nula-sdk`) free to
depend on `nula-net` without taking a position on which backend the
end binary will use.

## Consequences

### Positive

- Downstream callers can plug a custom transport (e.g. mock socket
  in tests) without depending on Tokio at all.
- `nula-storage-memory` and `nula-storage-lmdb` can be swapped at
  runtime because both yield `BoxFuture` from the same trait.
- `nula-core` stays publishable as a `wasm32`-friendly crate.

### Negative

- Each trait method allocates one `Box` per call. For NIP-44 codec
  paths that's irrelevant. For storage hot loops we add a benchmark
  in `nula-storage-memory` to keep the cost visible.
- `BoxFuture` signatures are noisier in rustdoc than `async fn`.
  We mitigate this with `#[doc(hidden)]` re-exports and explicit
  prose in trait docstrings that explain why the alias exists.

### Rollback

If `async fn` in traits ever becomes object-safe on stable (the
relevant RFC, `dyn-async-trait`, is in nightly experimentation as of
2026-05), we revisit this ADR and migrate the object-safe traits in a
single MAJOR bump of every layer-2/3 crate.

## References

- ADR-0001 — Workspace architecture.
- [Rust 1.75 release notes — async fn in traits](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html#async-fn-and-return-position-impl-trait-in-traits).
- [rust-nostr `sdk/src/transport/websocket.rs`](https://github.com/rust-nostr/nostr/blob/master/sdk/src/transport/websocket.rs).
- [`tokio-tungstenite`](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/).
