//! Pluggable admission policies for inbound traffic.
//!
//! Two trait surfaces, both object-safe:
//!
//! - [`WritePolicy`] decides whether an inbound `EVENT` is persisted
//!   and acknowledged with `OK true …`. Rejecting an event surfaces
//!   `OK false <reason>` to the client.
//! - [`ReadPolicy`] decides whether a `REQ` filter is honoured. A
//!   rejected filter is replied to with `CLOSED <id> <reason>` and
//!   no events are streamed for it.
//!
//! Both traits use [`nula_net::BoxFuture`] so implementations stay
//! object-safe and the runtime cfg-split established in ADR-0003
//! reaches the relay-builder layer unchanged.

use std::fmt::Debug;

use nula_core::{Event, Filter};
use nula_net::BoxFuture;

/// Verdict returned by a [`WritePolicy`] / [`ReadPolicy`].
///
/// `Accept` means "the request meets policy and may proceed";
/// `Reject(reason)` means "decline the request and surface this
/// reason to the client". Reasons are `'static` strings so the
/// policy stays cheap to clone and trivial to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmitVerdict {
    /// The request meets policy and may proceed.
    Accept,
    /// The request is declined; `reason` is surfaced verbatim to the
    /// client in the corresponding `OK` / `CLOSED` frame.
    Reject(&'static str),
}

impl AdmitVerdict {
    /// `true` when the verdict is [`Self::Accept`].
    #[must_use]
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }

    /// The static reason string when this is a `Reject`, otherwise
    /// the empty string.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Accept => "",
            Self::Reject(r) => r,
        }
    }
}

/// Decide whether an inbound `EVENT` is accepted.
///
/// The default behaviour (no policy installed) is "always accept".
pub trait WritePolicy: Debug + Send + Sync {
    /// Inspect `event` and return whether it should be persisted.
    fn admit_event<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, AdmitVerdict>;
}

/// Decide whether an inbound `REQ` filter is honoured.
///
/// The default behaviour (no policy installed) is "always accept".
pub trait ReadPolicy: Debug + Send + Sync {
    /// Inspect `filter` and return whether the relay should stream
    /// matches for it. Each filter in a `REQ` frame is evaluated
    /// independently.
    fn admit_filter<'a>(&'a self, filter: &'a Filter) -> BoxFuture<'a, AdmitVerdict>;
}

/// `WritePolicy` that accepts every event. Used when no custom
/// policy is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllWrites;

impl WritePolicy for AcceptAllWrites {
    fn admit_event<'a>(&'a self, _event: &'a Event) -> BoxFuture<'a, AdmitVerdict> {
        Box::pin(async { AdmitVerdict::Accept })
    }
}

/// `ReadPolicy` that accepts every filter. Used when no custom
/// policy is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllReads;

impl ReadPolicy for AcceptAllReads {
    fn admit_filter<'a>(&'a self, _filter: &'a Filter) -> BoxFuture<'a, AdmitVerdict> {
        Box::pin(async { AdmitVerdict::Accept })
    }
}
