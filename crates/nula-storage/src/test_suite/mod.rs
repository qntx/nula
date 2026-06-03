//! Reusable conformance suite for any backend that implements
//! [`crate::NostrDatabase`].
//!
//! Gated behind the `test-suite` feature. Backends in this crate use
//! it from their own integration tests; third-party backends enable
//! `nula-storage = { features = ["test-suite"] }` as a dev-dependency.
//!
//! Backend authors implement the [`DatabaseFactory`] trait — a single
//! async constructor that hands the suite a fresh database plus an
//! RAII guard — and call [`run_suite`]. The suite then exercises every
//! save-path semantic, every query-path semantic, NIP-09 deletion,
//! NIP-40 expiration, replaceable / addressable replacement, and
//! concurrency safety; capability-gated cases skip themselves when
//! the backend does not advertise the matching
//! [`crate::Features`] flag.
//!
//! # Quickstart
//!
//! ```rust,ignore
//! use std::sync::Arc;
//!
//! use nula_storage::NostrDatabase;
//! use nula_storage::test_suite::{DatabaseFactory, run_suite};
//!
//! struct MyBackendFactory;
//!
//! impl DatabaseFactory for MyBackendFactory {
//!     type Guard = ();
//!
//!     async fn build(&self) -> (Arc<dyn NostrDatabase>, ()) {
//!         (Arc::new(MyBackend::new().await), ())
//!     }
//! }
//!
//! #[tokio::test]
//! async fn conformance() {
//!     run_suite(&MyBackendFactory).await;
//! }
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test-support module; every panic surfaces as a test failure"
)]

pub mod cases;
pub mod factory;
pub mod helpers;

pub use self::factory::DatabaseFactory;

/// Run every case the suite ships against `factory`.
///
/// Cases are independent: each one calls [`DatabaseFactory::build`]
/// to acquire its own fresh database. A failure in one case panics
/// via the underlying test harness, which reports the failing
/// function name in the standard backtrace.
///
/// Backends that want partial coverage can call the per-category
/// helpers ([`run_save_path`], [`run_query_path`], …) or the
/// per-case `cases::*` functions directly.
pub async fn run_suite<F: DatabaseFactory>(factory: &F) {
    run_save_path(factory).await;
    run_query_path(factory).await;
    run_nip09(factory).await;
    run_replaceable(factory).await;
    run_concurrency(factory).await;
}

/// Save-path semantics (`save_event`, `check_id`, `wipe`, NIP-40).
pub async fn run_save_path<F: DatabaseFactory>(factory: &F) {
    cases::save_event::first_save_succeeds(factory).await;
    cases::save_event::duplicate_id_is_rejected(factory).await;
    cases::save_event::ephemeral_kind_is_dropped(factory).await;
    cases::save_event::check_id_reports_states(factory).await;
    cases::save_event::wipe_clears_every_table(factory).await;
    cases::save_event::already_expired_event_is_rejected(factory).await;
    cases::save_event::future_expiration_event_is_accepted(factory).await;
}

/// Query-path semantics (every `QueryPattern` variant, ordering,
/// time bounds, `count`, non-tombstoning `delete`).
pub async fn run_query_path<F: DatabaseFactory>(factory: &F) {
    cases::query_filters::empty_filter_returns_everything_newest_first(factory).await;
    cases::query_filters::author_filter_uses_index_and_orders_correctly(factory).await;
    cases::query_filters::kind_author_filter_drops_other_kinds(factory).await;
    cases::query_filters::coordinate_filter_targets_addressable(factory).await;
    cases::query_filters::time_bounds_are_inclusive(factory).await;
    cases::query_filters::limit_caps_returned_events(factory).await;
    cases::query_filters::count_matches_query_length(factory).await;
    cases::query_filters::negentropy_items_match_query(factory).await;
    cases::query_filters::delete_matching_drops_events_without_tombstoning(factory).await;
}

/// NIP-09 deletion semantics.
pub async fn run_nip09<F: DatabaseFactory>(factory: &F) {
    cases::nip09_deletion::deletion_removes_event_and_tombstones_id(factory).await;
    cases::nip09_deletion::deletion_only_targets_own_events(factory).await;
    cases::nip09_deletion::deletion_tombstones_addressable_coordinate(factory).await;
}

/// Replaceable / addressable kind routing.
pub async fn run_replaceable<F: DatabaseFactory>(factory: &F) {
    cases::replaceable::newer_metadata_replaces_older(factory).await;
    cases::replaceable::older_metadata_is_rejected_as_replaced(factory).await;
    cases::replaceable::addressable_coordinate_replacement(factory).await;
    cases::replaceable::addressable_different_d_tags_coexist(factory).await;
}

/// Concurrency safety under many concurrent writers.
pub async fn run_concurrency<F: DatabaseFactory>(factory: &F) {
    cases::concurrency::concurrent_saves_do_not_lose_events(factory).await;
}
