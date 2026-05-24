//! Individual conformance cases.
//!
//! Each module exports a set of `pub async fn case_*<F: DatabaseFactory>`
//! functions. They are aggregated by [`crate::run_suite`] but can also
//! be called individually if a backend only wants partial coverage.

pub mod concurrency;
pub mod nip09_deletion;
pub mod query_filters;
pub mod replaceable;
pub mod save_event;
