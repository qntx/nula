//! Type-erased async return shape used by every object-safe trait
//! method in this crate.
//!
//! The alias resolves to the standard `Pin<Box<dyn Future>>` shape with
//! a `Send` bound on every non-wasm target so callers can move the
//! future across `tokio::spawn` boundaries without ceremony. On
//! `wasm32-unknown-unknown` the `Send` bound is dropped because
//! browser-side transports (e.g. `wasm-bindgen`'s `WebSocket`) cannot
//! satisfy it.
//!
//! Library code that wants to return one of these futures from a
//! non-trait method should still prefer `impl Future<Output = T> +
//! Send + 'a` so the compiler can pick a stack future when possible;
//! reach for this alias only when the trait must be object-safe.

use std::future::Future;
use std::pin::Pin;

/// Boxed, type-erased async return value used across the transport
/// trait surface.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Boxed, type-erased async return value used across the transport
/// trait surface. On `wasm32` the `Send` bound is dropped because
/// browser transports cannot satisfy it.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
