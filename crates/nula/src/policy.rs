//! Client-side admission policy.
//!
//! [`AdmitPolicy`] is the SDK's symmetric counterpart to the
//! relay-side `WritePolicy` / `QueryPolicy` traits in
//! `nula_relay::server`: it lets a [`Client`] gate which relays it
//! is willing to *register*, *connect to*, and which inbound events
//! it is willing to *persist* during sync / fetch flows.
//!
//! The trait is **opt-in** -- without a call to
//! [`crate::ClientBuilder::admit_policy`] every gate defaults to
//! [`AdmitStatus::Success`], so existing call sites are unaffected.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use nula_core::types::RelayUrl;
//! use nula_core::BoxFuture;
//! use nula::policy::{AdmitPolicy, AdmitStatus, PolicyError};
//!
//! #[derive(Debug)]
//! struct AllowOnlyTls;
//!
//! impl AdmitPolicy for AllowOnlyTls {
//!     fn admit_relay<'a>(
//!         &'a self,
//!         relay_url: &'a RelayUrl,
//!     ) -> BoxFuture<'a, Result<AdmitStatus, PolicyError>> {
//!         Box::pin(async move {
//!             if relay_url.as_str().starts_with("wss://") {
//!                 Ok(AdmitStatus::Success)
//!             } else {
//!                 Ok(AdmitStatus::rejected("plain ws is forbidden"))
//!             }
//!         })
//!     }
//! }
//! ```
//!
//! [`Client`]: crate::Client

use std::error::Error as StdError;
use std::fmt;

use nula_core::BoxFuture;
use nula_core::event::Event;
use nula_core::message::SubscriptionId;
use nula_core::types::RelayUrl;

/// Verdict returned by every [`AdmitPolicy`] hook.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AdmitStatus {
    /// The action is admitted. The SDK proceeds normally.
    Success,
    /// The action is rejected. The SDK surfaces this back to the
    /// caller as [`crate::Error::PolicyRejected`].
    Rejected {
        /// Optional human-readable reason. Surfaced verbatim on
        /// [`crate::Error::PolicyRejected::reason`].
        reason: Option<String>,
    },
}

impl AdmitStatus {
    /// `AdmitStatus::Success`. Sugar for the common case.
    #[must_use]
    pub const fn success() -> Self {
        Self::Success
    }

    /// `AdmitStatus::Rejected` with the supplied reason.
    pub fn rejected<S>(reason: S) -> Self
    where
        S: Into<String>,
    {
        Self::Rejected {
            reason: Some(reason.into()),
        }
    }

    /// `true` when this verdict is [`Self::Success`].
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Errors a policy implementation can raise from a backend call
/// (e.g. a remote allowlist lookup that timed out).
#[derive(Debug)]
pub enum PolicyError {
    /// Wraps an error returned by the policy's backing store.
    Backend(Box<dyn StdError + Send + Sync>),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "policy backend error: {e}"),
        }
    }
}

impl StdError for PolicyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Backend(e) => Some(&**e),
        }
    }
}

impl PolicyError {
    /// Wrap a backend error.
    pub fn backend<E>(error: E) -> Self
    where
        E: Into<Box<dyn StdError + Send + Sync>>,
    {
        Self::Backend(error.into())
    }
}

/// Client-side admission policy. Every method has a default
/// implementation that returns [`AdmitStatus::Success`], so users
/// override only the hooks they care about.
///
/// The trait is `Send + Sync` so an `Arc<dyn AdmitPolicy>` can be
/// shared across tasks; futures are boxed via [`BoxFuture`] for
/// object safety -- the same convention used by every other
/// `nula-*` async trait surface.
pub trait AdmitPolicy: fmt::Debug + Send + Sync {
    /// Decide whether `relay_url` may be added to the pool.
    ///
    /// Called once per `add_relay*` call site; the verdict is not
    /// cached -- if the policy state changes between calls the new
    /// verdict applies.
    fn admit_relay<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
    ) -> BoxFuture<'a, Result<AdmitStatus, PolicyError>> {
        let _ = relay_url;
        Box::pin(async move { Ok(AdmitStatus::Success) })
    }

    /// Decide whether the SDK may *connect* to `relay_url`.
    ///
    /// Called from [`crate::Client::connect_relay`] /
    /// [`crate::Client::try_connect_relay`]. A policy can use this
    /// to block connections to a relay that is registered but
    /// temporarily quarantined.
    fn admit_connection<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
    ) -> BoxFuture<'a, Result<AdmitStatus, PolicyError>> {
        let _ = relay_url;
        Box::pin(async move { Ok(AdmitStatus::Success) })
    }

    /// Decide whether the SDK should *persist* an inbound event
    /// arriving on `subscription_id` from `relay_url`.
    ///
    /// Called from the NIP-77 sync persistence path before
    /// `database.save_event`; rejected events are dropped from the
    /// `received` set on the [`crate::SyncSummary`] and never make
    /// it into the local store. The hook is also re-exported via
    /// [`crate::Client::admit_policy`] so callers consuming raw
    /// subscription / fetch streams can apply the same gate.
    fn admit_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        subscription_id: &'a SubscriptionId,
        event: &'a Event,
    ) -> BoxFuture<'a, Result<AdmitStatus, PolicyError>> {
        let _ = (relay_url, subscription_id, event);
        Box::pin(async move { Ok(AdmitStatus::Success) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_status_helpers() {
        assert!(AdmitStatus::success().is_success());
        let rejected = AdmitStatus::rejected("nope");
        assert!(!rejected.is_success());
        assert!(matches!(
            rejected,
            AdmitStatus::Rejected {
                reason: Some(reason),
            } if reason == "nope"
        ));
    }

    #[test]
    fn policy_error_chains_backend() {
        let inner: Box<dyn StdError + Send + Sync> = "blocked".into();
        let err = PolicyError::backend(inner);
        assert!(err.source().is_some());
        let msg = err.to_string();
        assert!(msg.contains("blocked"), "msg={msg:?}");
    }
}
