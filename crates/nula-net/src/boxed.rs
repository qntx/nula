//! Boxed, type-erased async return shapes used across object-safe
//! trait surfaces in `nula-*` crates.
//!
//! Two aliases live here, one for one-shot async values
//! ([`BoxFuture`]) and one for asynchronous streams ([`BoxStream`]).
//! Both resolve to the standard `Pin<Box<dyn …>>` shape with a `Send`
//! bound on every non-wasm target so callers can move the boxed
//! handle across `tokio::spawn` boundaries without ceremony. On
//! `wasm32-unknown-unknown` the `Send` bound is dropped because
//! browser-side transports (e.g. `wasm-bindgen`'s `WebSocket`) cannot
//! satisfy it.
//!
//! Library code that wants to return one of these from a non-trait
//! method should still prefer `impl Future<Output = T> + Send + 'a`
//! (or `impl Stream<Item = T> + Send + 'a`) so the compiler can pick
//! a stack future / stream when possible; reach for these aliases
//! only when the trait must be object-safe.

use std::future::Future;
use std::pin::Pin;

use futures::Stream;

/// Boxed, type-erased async return value used across object-safe
/// trait surfaces.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed, type-erased async return value used across object-safe
/// trait surfaces. On `wasm32` the `Send` bound is dropped because
/// browser transports cannot satisfy it.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Boxed, type-erased asynchronous stream used across object-safe
/// trait surfaces (notably the multi-relay [`stream_events`] APIs in
/// `nula-relay-pool`).
///
/// [`stream_events`]: https://docs.rs/nula-relay-pool
#[cfg(not(target_arch = "wasm32"))]
pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;

/// Boxed, type-erased asynchronous stream used across object-safe
/// trait surfaces. On `wasm32` the `Send` bound is dropped because
/// browser transports cannot satisfy it.
#[cfg(target_arch = "wasm32")]
pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + 'a>>;
