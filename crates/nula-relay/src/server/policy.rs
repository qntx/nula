//! Pluggable admission policies for inbound traffic.
//!
//! Two trait surfaces, both object-safe:
//!
//! - [`WritePolicy`] decides whether an inbound `EVENT` (from a given
//!   client address) is persisted. A rejection surfaces
//!   `OK false "<prefix>: <message>"` to the client.
//! - [`QueryPolicy`] decides whether a `REQ` / NIP-77 filter is
//!   honoured, and may **rewrite** it in place (e.g. clamp an unbounded
//!   `limit`). A rejection surfaces `CLOSED <id> "<prefix>: <message>"`.
//!
//! Both traits use [`nula_core::boxed::BoxFuture`] so implementations stay
//! object-safe (ADR-0003), receive the client [`SocketAddr`] for
//! IP-aware decisions, and report rejections with a NIP-20
//! [`MachineReadablePrefix`] (ADR-0012).

use std::collections::HashSet;
use std::fmt::Debug;
use std::net::SocketAddr;

use nula_core::boxed::BoxFuture;
use nula_core::message::MachineReadablePrefix;
use nula_core::{Event, Filter, PublicKey};

/// Verdict returned by a [`WritePolicy`] / [`QueryPolicy`].
///
/// `Accept` means "the request meets policy and may proceed";
/// `Reject { prefix, message }` declines it and carries the NIP-20
/// machine-readable category plus a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmitVerdict {
    /// The request meets policy and may proceed.
    Accept,
    /// The request is declined. `prefix` is the NIP-20 machine-readable
    /// category and `message` the human-readable detail; the relay
    /// renders them as `"<prefix>: <message>"` in the `OK` / `CLOSED`
    /// frame.
    Reject {
        /// NIP-20 machine-readable prefix (e.g. `Blocked`, `Restricted`).
        prefix: MachineReadablePrefix,
        /// Human-readable rejection detail.
        message: String,
    },
}

impl AdmitVerdict {
    /// Construct a [`Self::Reject`] verdict.
    #[must_use]
    pub fn reject(prefix: MachineReadablePrefix, message: impl Into<String>) -> Self {
        Self::Reject {
            prefix,
            message: message.into(),
        }
    }

    /// `true` when the verdict is [`Self::Accept`].
    #[must_use]
    pub const fn is_accept(&self) -> bool {
        matches!(self, Self::Accept)
    }
}

/// Decide whether an inbound `EVENT` is accepted.
///
/// The default behaviour (no policy installed) is "always accept".
pub trait WritePolicy: Debug + Send + Sync {
    /// Inspect `event` (received from client `addr`) and return whether
    /// it should be persisted.
    fn admit_event<'a>(&'a self, event: &'a Event, addr: SocketAddr)
    -> BoxFuture<'a, AdmitVerdict>;
}

/// Decide whether an inbound `REQ` / NIP-77 filter is honoured,
/// optionally rewriting it in place.
///
/// The default behaviour (no policy installed) is "always accept,
/// rewrite nothing".
pub trait QueryPolicy: Debug + Send + Sync {
    /// Inspect — and optionally mutate — `filter` for the query from
    /// client `addr`. Each filter in a `REQ` frame is evaluated
    /// independently; mutations (e.g. clamping `limit`) take effect
    /// before the query runs.
    fn admit_query<'a>(
        &'a self,
        filter: &'a mut Filter,
        addr: SocketAddr,
    ) -> BoxFuture<'a, AdmitVerdict>;
}

/// `WritePolicy` that accepts every event. Used when no custom
/// policy is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllWrites;

impl WritePolicy for AcceptAllWrites {
    fn admit_event<'a>(
        &'a self,
        _event: &'a Event,
        _addr: SocketAddr,
    ) -> BoxFuture<'a, AdmitVerdict> {
        Box::pin(async { AdmitVerdict::Accept })
    }
}

/// `QueryPolicy` that accepts every filter and rewrites nothing. Used
/// when no custom policy is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllQueries;

impl QueryPolicy for AcceptAllQueries {
    fn admit_query<'a>(
        &'a self,
        _filter: &'a mut Filter,
        _addr: SocketAddr,
    ) -> BoxFuture<'a, AdmitVerdict> {
        Box::pin(async { AdmitVerdict::Accept })
    }
}

/// `WritePolicy` for an author-restricted relay.
///
/// Only admits events whose author is in an allowlist (mirrors upstream
/// `nostr-relay-builder`'s pubkey mode); every other author is rejected
/// with a `blocked:` reason.
#[derive(Debug, Clone, Default)]
pub struct AuthorAllowlist {
    allowed: HashSet<PublicKey>,
}

impl AuthorAllowlist {
    /// Build an allowlist from an iterator of permitted authors.
    #[must_use]
    pub fn new(authors: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            allowed: authors.into_iter().collect(),
        }
    }

    /// `true` when `author` may publish to this relay.
    #[must_use]
    pub fn allows(&self, author: &PublicKey) -> bool {
        self.allowed.contains(author)
    }
}

impl WritePolicy for AuthorAllowlist {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        _addr: SocketAddr,
    ) -> BoxFuture<'a, AdmitVerdict> {
        let allowed = self.allowed.contains(&event.pubkey);
        Box::pin(async move {
            if allowed {
                AdmitVerdict::Accept
            } else {
                AdmitVerdict::reject(
                    MachineReadablePrefix::Blocked,
                    "author is not on this relay's allowlist",
                )
            }
        })
    }
}
