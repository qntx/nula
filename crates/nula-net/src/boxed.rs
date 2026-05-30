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

pub use nula_core::boxed::{BoxFuture, BoxStream};
