//! Sorted, deduplicated result set returned by [`crate::NostrDatabase::query`].
//!
//! `Events` is a thin newtype over `Vec<Event>` with a single invariant:
//! **events are sorted in descending order by `created_at`, tie-broken
//! by ascending `EventId`**. This matches the NIP-01 SUBSCRIBE wire
//! ordering and lets callers feed the iterator straight into
//! `["EVENT", id, ...]` frames without re-sorting.

use std::collections::HashSet;
use std::iter::FusedIterator;

use nula_core::event::{Event, EventId};

/// Sorted, deduplicated set of [`Event`] returned by a query.
///
/// Iteration yields the newest event first. Equality compares the
/// underlying event multisets; iteration order is part of the public
/// contract.
#[derive(Debug, Clone, Default)]
pub struct Events {
    inner: Vec<Event>,
}

impl Events {
    /// Build an empty result set.
    ///
    /// Equivalent to `Events::default()` but reads better at call sites
    /// where the empty value is the meaningful one.
    #[must_use]
    #[inline]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a result set from an already-sorted-and-deduplicated
    /// iterator.
    ///
    /// Backends call this when they know the input is in canonical
    /// order. The constructor performs no sorting, no deduplication,
    /// and no bounds checking; misuse degrades query results but cannot
    /// violate memory safety.
    #[must_use]
    #[inline]
    pub fn from_sorted<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Event>,
    {
        Self {
            inner: iter.into_iter().collect(),
        }
    }

    /// Build a result set from an arbitrary iterator, sorting and
    /// deduplicating in one pass.
    ///
    /// Use this when the backend cannot cheaply preserve canonical
    /// order — e.g. when it merges several secondary-index streams.
    #[must_use]
    pub fn from_unsorted<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Event>,
    {
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut inner: Vec<Event> = iter.into_iter().filter(|e| seen.insert(e.id)).collect();
        inner.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Self { inner }
    }

    /// Number of events in the set.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the set is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Newest event (the first one in canonical order), borrowed.
    #[must_use]
    #[inline]
    pub fn first(&self) -> Option<&Event> {
        self.inner.first()
    }

    /// Newest event, consumed out of the set.
    #[must_use]
    pub fn first_owned(mut self) -> Option<Event> {
        if self.inner.is_empty() {
            None
        } else {
            Some(self.inner.swap_remove(0))
        }
    }

    /// Borrowing iterator yielding events in canonical (newest-first)
    /// order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, Event> {
        self.inner.iter()
    }

    /// Consume the set and return the underlying `Vec`.
    #[must_use]
    #[inline]
    pub fn into_vec(self) -> Vec<Event> {
        self.inner
    }
}

impl IntoIterator for Events {
    type Item = Event;
    type IntoIter = std::vec::IntoIter<Event>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a Events {
    type Item = &'a Event;
    type IntoIter = std::slice::Iter<'a, Event>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl PartialEq for Events {
    /// Equality compares the underlying event multisets; because
    /// `Events` already enforces canonical order, this is equivalent
    /// to slice equality.
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Events {}

impl FromIterator<Event> for Events {
    /// Collect from an arbitrary iterator, sorting and deduplicating.
    ///
    /// Equivalent to [`Events::from_unsorted`].
    fn from_iter<I: IntoIterator<Item = Event>>(iter: I) -> Self {
        Self::from_unsorted(iter)
    }
}

// Marker to satisfy `clippy::iter_not_returning_iterator` — the inner
// iterator type already implements `FusedIterator`, but we restate it
// here so downstream generic code can rely on the bound.
const fn _assert_fused()
where
    std::vec::IntoIter<Event>: FusedIterator,
{
}
