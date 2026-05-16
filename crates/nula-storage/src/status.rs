//! Status enums returned by save / lookup operations.
//!
//! These are the public outcome types for [`crate::NostrDatabase`]. Backends
//! map their internal book-keeping to these variants so callers can react
//! to outcomes without learning a backend-specific vocabulary.

/// Outcome of a [`crate::NostrDatabase::save_event`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SaveEventStatus {
    /// The event was accepted and is now retrievable through `query` /
    /// `event_by_id`.
    Success,
    /// The event was rejected; the inner [`RejectedReason`] carries the
    /// reason. Rejection is **not** an error — the database is healthy
    /// and the protocol semantics required dropping the event.
    Rejected(RejectedReason),
}

impl SaveEventStatus {
    /// Convenience predicate. Returns `true` iff the variant is
    /// [`SaveEventStatus::Success`].
    #[must_use]
    #[inline]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Reason an event was rejected by [`crate::NostrDatabase::save_event`].
///
/// Variants are ordered roughly by frequency in production traffic
/// (duplicate first, then ephemeral kinds, then deletion / expiration
/// edge cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectedReason {
    /// The event ID is already in the store. Idempotent re-publishes
    /// land here.
    Duplicate,
    /// The event's kind sits in the NIP-01 ephemeral range
    /// (20000..30000); ephemeral kinds are not persisted by design.
    Ephemeral,
    /// A NIP-09 deletion request previously marked this event ID as
    /// removed. The store refuses to resurrect it.
    Deleted,
    /// The event's NIP-40 expiration tag is at or before "now"; the
    /// event is dead-on-arrival.
    Expired,
    /// A newer replaceable / addressable event already occupies the
    /// `(kind, author)` / `(kind, author, d)` coordinate. The older
    /// candidate loses.
    Replaced,
    /// The event's author has issued a NIP-62 vanish request; further
    /// writes from that pubkey are dropped.
    Vanished,
    /// The event's author / target relationship violates a backend
    /// policy that does not fit any other variant (e.g. a deletion
    /// event targeting another author's content).
    InvalidDelete,
}

/// State of an event ID inside a [`crate::NostrDatabase`].
///
/// Returned by [`crate::NostrDatabase::check_id`]. The three variants
/// cover every legal state the database can hold for an arbitrary ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DatabaseEventStatus {
    /// The event is currently stored and can be retrieved.
    Saved,
    /// The event was deleted via NIP-09 or replaced by a newer
    /// addressable version. It is tombstoned; the store remembers the
    /// ID and refuses to resurrect it.
    Deleted,
    /// The store has no record of the event, neither alive nor
    /// tombstoned.
    NotExistent,
}
