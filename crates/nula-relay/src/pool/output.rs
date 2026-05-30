//! Partial-success container returned by every multi-relay operation.
//!
//! Multi-relay fan-out is an inherently *partial* operation: in any
//! production deployment some relays will be slow, offline, or
//! adversarial at any given moment. Wrapping the per-call return
//! value alongside the per-relay verdict lets the caller decide
//! whether the partial outcome is good enough rather than treating
//! "any failure" as a hard error.

use std::collections::{HashMap, HashSet};

use nula_core::RelayUrl;

/// Per-call result of a multi-relay operation.
///
/// `value` is the operation-specific payload (the published
/// [`nula_core::EventId`] for `send_event`, the
/// [`nula_core::SubscriptionId`] for `subscribe`, `()` for `connect`,
/// …). `success` records the relays that completed the call without
/// error. `failed` maps each rejecting relay to its stringified
/// error.
///
/// The error string is **already rendered** at the boundary so
/// downstream observability (logs, metrics, broadcast notifications)
/// can carry it without re-introducing crate-private error types
/// into the type signature.
#[derive(Debug, Clone)]
pub struct Output<T> {
    /// The operation-specific payload (event id, subscription id, …).
    pub value: T,
    /// Relays that handled the operation without raising an error.
    pub success: HashSet<RelayUrl>,
    /// Relays that rejected the operation, with the error rendered.
    pub failed: HashMap<RelayUrl, String>,
}

impl<T> Output<T> {
    /// Construct an empty output around `value`. Both `success` and
    /// `failed` start out empty.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            value,
            success: HashSet::new(),
            failed: HashMap::new(),
        }
    }

    /// Returns `true` when **every** relay the operation targeted
    /// succeeded, **and** at least one relay was targeted.
    #[must_use]
    pub fn is_full_success(&self) -> bool {
        !self.success.is_empty() && self.failed.is_empty()
    }

    /// Returns `true` when at least one relay succeeded **and** at
    /// least one relay failed. A useful signal for callers that want
    /// to log degraded but acceptable outcomes.
    #[must_use]
    pub fn is_partial_success(&self) -> bool {
        !self.success.is_empty() && !self.failed.is_empty()
    }

    /// Returns `true` when no relay succeeded. Includes the
    /// degenerate "no relay was even targeted" case.
    #[must_use]
    pub fn is_total_failure(&self) -> bool {
        self.success.is_empty()
    }

    /// Map the payload while preserving the success / failure sets.
    #[must_use]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Output<U> {
        Output {
            value: f(self.value),
            success: self.success,
            failed: self.failed,
        }
    }
}

impl<T: Default> Default for Output<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).expect("hardcoded test url")
    }

    #[test]
    fn empty_output_is_total_failure() {
        let out: Output<()> = Output::default();
        assert!(out.is_total_failure());
        assert!(!out.is_full_success());
        assert!(!out.is_partial_success());
    }

    #[test]
    fn full_success_classifies() {
        let mut out: Output<()> = Output::default();
        out.success.insert(url("wss://a"));
        out.success.insert(url("wss://b"));
        assert!(out.is_full_success());
        assert!(!out.is_partial_success());
        assert!(!out.is_total_failure());
    }

    #[test]
    fn partial_success_classifies() {
        let mut out: Output<()> = Output::default();
        out.success.insert(url("wss://a"));
        out.failed.insert(url("wss://b"), "boom".into());
        assert!(out.is_partial_success());
        assert!(!out.is_full_success());
        assert!(!out.is_total_failure());
    }

    #[test]
    fn map_preserves_sets() {
        let mut out: Output<u32> = Output::new(7);
        out.success.insert(url("wss://a"));
        out.failed.insert(url("wss://b"), "x".into());

        let mapped = out.map(|n| n * 2);
        assert_eq!(mapped.value, 14);
        assert_eq!(mapped.success.len(), 1);
        assert_eq!(mapped.failed.len(), 1);
    }
}
