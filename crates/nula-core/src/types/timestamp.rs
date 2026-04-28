//! Unix timestamp in seconds.
//!
//! Per [NIP-01], every event carries a `created_at` field — a non-negative
//! integer counting seconds since the Unix epoch. This module wraps a [`u64`]
//! in a strongly-typed [`Timestamp`] so we never confuse seconds, milliseconds,
//! or signed-vs-unsigned representations on the wire.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;
use core::num::ParseIntError;
use core::ops::{Add, Sub};
use core::str::FromStr;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unix timestamp in seconds.
///
/// Internally stored as a [`u64`] so the value matches what the wire format
/// requires (a non-negative JSON integer). Constructors are infallible by
/// design — out-of-band errors are reported via [`Error`].
///
/// # Example
///
/// ```
/// use nula_core::Timestamp;
///
/// let now = Timestamp::now().unwrap();
/// let one_minute_later = now + 60;
/// assert!(one_minute_later > now);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(u64);

/// Errors raised when constructing a [`Timestamp`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The system clock is set before the Unix epoch.
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(#[from] SystemTimeError),
    /// The string was not a valid non-negative integer.
    #[error("invalid timestamp string: {0}")]
    Parse(#[from] ParseIntError),
}

impl Timestamp {
    /// The earliest possible timestamp (`0`, the Unix epoch).
    pub const ZERO: Self = Self(0);
    /// The largest possible timestamp.
    pub const MAX: Self = Self(u64::MAX);

    /// Construct a timestamp from raw seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Return the number of seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Read the current system clock as a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is set before the Unix epoch.
    pub fn now() -> Result<Self, TimestampError> {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(Self(secs))
    }

    /// Return the saturating sum of two timestamps.
    #[must_use]
    pub const fn saturating_add(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// Return the saturating difference of two timestamps.
    #[must_use]
    pub const fn saturating_sub(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }

    /// Return this timestamp as a [`SystemTime`].
    #[must_use]
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0)
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.parse::<u64>()?;
        Ok(Self(value))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Add<u64> for Timestamp {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl Sub<u64> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secs_round_trip() {
        let ts = Timestamp::from_secs(1_700_000_000);
        assert_eq!(ts.as_secs(), 1_700_000_000);
    }

    #[test]
    fn ordering() {
        let lhs = Timestamp::from_secs(10);
        let rhs = Timestamp::from_secs(20);
        assert!(lhs < rhs);
        assert_eq!(rhs - 5, Timestamp::from_secs(15));
        assert_eq!(lhs + 100, Timestamp::from_secs(110));
    }

    #[test]
    fn saturation() {
        assert_eq!(Timestamp::MAX.saturating_add(1), Timestamp::MAX);
        assert_eq!(Timestamp::ZERO.saturating_sub(1), Timestamp::ZERO);
    }

    #[test]
    fn display_and_parse() {
        let ts = Timestamp::from_secs(42);
        let s = ts.to_string();
        assert_eq!(s, "42");
        assert_eq!(Timestamp::from_str(&s).unwrap(), ts);
    }

    #[test]
    fn serde_round_trip() {
        let ts = Timestamp::from_secs(1_700_000_000);
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "1700000000");
        let parsed: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ts);
    }

    #[test]
    fn now_is_after_2020() {
        let ts = Timestamp::now().unwrap();
        assert!(ts > Timestamp::from_secs(1_577_836_800));
    }

    #[test]
    fn parse_error() {
        assert!(Timestamp::from_str("abc").is_err());
        assert!(Timestamp::from_str("-5").is_err());
    }

    #[test]
    fn to_system_time_round_trip() {
        let ts = Timestamp::from_secs(1_700_000_000);
        let st = ts.to_system_time();
        let back = st.duration_since(UNIX_EPOCH).expect("UNIX_EPOCH ordering");
        assert_eq!(back.as_secs(), 1_700_000_000);
    }
}
