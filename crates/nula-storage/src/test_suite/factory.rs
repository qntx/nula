//! [`DatabaseFactory`]: how a backend hands the suite a fresh,
//! empty database for each case.
//!
//! The trait deliberately exposes the database as an
//! `Arc<dyn NostrDatabase>`. The cases run through the public trait
//! surface only, so they never need to peek at the concrete type.

use std::future::Future;
use std::sync::Arc;

use crate::NostrDatabase;

/// Hand the suite a fresh database plus an RAII guard that keeps the
/// underlying storage (temp dir, mmap, …) alive for the case's
/// duration.
///
/// Backends that hold no out-of-process state set
/// `type Guard = ();`. Backends that need cleanup (the redb backend
/// uses `tempfile::TempDir`) hand the guard back so the case can
/// drop it when it finishes.
///
/// `async fn in trait` is used here because the only callers are
/// monomorphised: [`crate::test_suite::run_suite`] is generic over `F`. The
/// trait stays non-`dyn`-safe on purpose; nothing in the suite asks
/// for `Box<dyn DatabaseFactory>`.
pub trait DatabaseFactory: Send + Sync {
    /// RAII guard that owns any out-of-process resources backing the
    /// returned database.
    ///
    /// Must be `Send` so the guard can survive across `.await` in the
    /// case body. Drop runs after each case returns.
    type Guard: Send;

    /// Build a fresh, empty database and the matching guard.
    ///
    /// The returned database must:
    ///
    /// - be empty (no events, no tombstones, no addressable history);
    /// - be independent of any database previously returned by the
    ///   same factory — concurrent cases must not see each other's
    ///   data;
    /// - be reusable across many invocations of `build`.
    fn build(&self) -> impl Future<Output = (Arc<dyn NostrDatabase>, Self::Guard)> + Send;
}
