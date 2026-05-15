//! Reconnect policy and the AWS-recommended *full jitter* backoff
//! algorithm.
//!
//! Reference: <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>.
//!
//! The full-jitter formula picks a delay uniformly between `0` and
//! `min(cap, base * 2^attempts)`. It is provably the lowest-variance
//! variant among the common backoff schemes (constant, equal jitter,
//! decorrelated jitter) when many clients reconnect to the same
//! server after a fault — the property we want when a relay flaps.

use std::time::Duration;

/// How a [`crate::Relay`] should react to a dropped connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconnectPolicy {
    /// Never reconnect. After the first disconnect the relay
    /// transitions to [`crate::RelayStatus::Terminated`].
    Never,

    /// Wait a fixed duration, then retry. Useful in tests and
    /// well-behaved private networks.
    Constant(Duration),

    /// AWS *full jitter* exponential backoff:
    /// `sleep = random(0, min(cap, base * 2^attempts))`.
    Exponential {
        /// Base unit of the exponential. The first delay is bounded
        /// by `[0, base)`; the second by `[0, 2 * base)`; …
        base: Duration,
        /// Hard ceiling on any single sleep, regardless of
        /// `attempts`. Prevents long-flapping connections from
        /// blocking observers for hours.
        cap: Duration,
    },
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::Exponential {
            base: Duration::from_millis(500),
            cap: Duration::from_secs(60),
        }
    }
}

impl ReconnectPolicy {
    /// Compute the next sleep before retrying.
    ///
    /// Returns `None` when [`Self::Never`] is configured — the caller
    /// must treat that as a signal to transition to
    /// [`crate::RelayStatus::Terminated`].
    ///
    /// `attempts` is the number of failed connect attempts so far.
    /// Pass `0` for the first retry, `1` for the second, and so on.
    #[must_use]
    pub fn next_delay(self, attempts: u32) -> Option<Duration> {
        match self {
            Self::Never => None,
            Self::Constant(d) => Some(d),
            Self::Exponential { base, cap } => Some(full_jitter(base, cap, attempts)),
        }
    }
}

/// AWS *full jitter*: `random(0, min(cap, base * 2^attempts))`.
///
/// `attempts` is clamped at 32 to avoid `u128` overflow on
/// pathologically long flap streaks. The cap is honoured.
fn full_jitter(base: Duration, cap: Duration, attempts: u32) -> Duration {
    let shift = attempts.min(32);
    // `base * 2^shift` in u128 nanos. The clamp on `shift` plus the
    // `Duration::MAX` saturation keeps every step well under `u128`
    // range.
    let exp = base.as_nanos().saturating_mul(1u128 << shift);
    let upper = exp.min(cap.as_nanos());
    if upper == 0 {
        return Duration::ZERO;
    }
    let rand_nanos = u128::from(rand_u64()) % upper;
    // `Duration::from_nanos` takes u64; clamp again at u64::MAX (which
    // corresponds to ~584 years and will never happen in practice).
    let nanos = u64::try_from(rand_nanos).unwrap_or(u64::MAX);
    Duration::from_nanos(nanos)
}

/// 64 bits of randomness via `getrandom`. The crate is already a
/// dependency of `nula-core` and ships with the workspace.
fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // `getrandom` only fails on platforms without an OS RNG (early
    // boot, sandboxes that block syscalls). Returning `0` makes the
    // backoff degenerate to "retry immediately" rather than panic;
    // that is the right behaviour for an availability-critical path.
    if getrandom::fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_returns_none() {
        assert_eq!(ReconnectPolicy::Never.next_delay(0), None);
        assert_eq!(ReconnectPolicy::Never.next_delay(99), None);
    }

    #[test]
    fn constant_returns_fixed() {
        let policy = ReconnectPolicy::Constant(Duration::from_millis(250));
        assert_eq!(policy.next_delay(0), Some(Duration::from_millis(250)));
        assert_eq!(policy.next_delay(7), Some(Duration::from_millis(250)));
    }

    #[test]
    fn exponential_respects_cap() {
        let policy = ReconnectPolicy::Exponential {
            base: Duration::from_millis(100),
            cap: Duration::from_secs(2),
        };
        for attempt in 0..30 {
            let delay = policy.next_delay(attempt).unwrap();
            assert!(
                delay <= Duration::from_secs(2),
                "delay {delay:?} exceeded cap on attempt {attempt}"
            );
        }
    }

    #[test]
    fn exponential_zero_base_yields_zero() {
        let policy = ReconnectPolicy::Exponential {
            base: Duration::ZERO,
            cap: Duration::from_secs(1),
        };
        assert_eq!(policy.next_delay(0), Some(Duration::ZERO));
        assert_eq!(policy.next_delay(10), Some(Duration::ZERO));
    }
}
