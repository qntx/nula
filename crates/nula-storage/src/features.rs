//! Backend identification + capability flags.
//!
//! [`Backend`] names the concrete storage engine for telemetry / metrics.
//! [`Features`] is a bitflag set advertising optional capabilities so
//! upper layers (relay pool, gossip) can branch on backend support
//! without downcasting.

use bitflags::bitflags;

/// Identifier for the concrete backend behind a [`crate::NostrDatabase`].
///
/// Used by callers that want to log / meter per-backend. Two backends
/// can never share the same variant; if a new first-party backend ships
/// it gets a new variant and the enum stays `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// In-process `BTreeSet`-backed store (`memory` module).
    Memory,
    /// redb-backed persistent store (`redb` module).
    Redb,
    /// Custom third-party backend; the inner `&'static str` is the
    /// crate name for telemetry.
    Custom(&'static str),
}

impl Backend {
    /// Lower-snake-case name suitable as a metric label / tracing field.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Redb => "redb",
            Self::Custom(name) => name,
        }
    }
}

bitflags! {
    /// Optional capabilities advertised by a backend.
    ///
    /// Upper layers (notably `nula-relay-pool` for negentropy and the
    /// future search-aware `nula` facade) read this set to pick
    /// query strategies. Backends declare their support set inside
    /// [`crate::NostrDatabase::features`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Features: u32 {
        /// Backend persists data across process restarts.
        const PERSISTENT      = 1 << 0;
        /// Backend supports NIP-50 full-text search on `Filter::search`.
        const FULL_TEXT_SEARCH = 1 << 1;
        /// Backend can serve `negentropy_items` from a secondary index
        /// rather than fully materialising events.
        const FAST_NEGENTROPY = 1 << 2;
        /// Backend enforces a maximum event count and evicts when full.
        const BOUNDED_CAPACITY = 1 << 3;
    }
}
