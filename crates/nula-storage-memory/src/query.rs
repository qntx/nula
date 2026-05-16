//! Filter → index-plan classification.
//!
//! [`QueryPattern`] maps a [`Filter`] to the most selective index the
//! store can use to satisfy it. Selecting the right pattern lets common
//! query shapes (author-only, `(kind, author)`, addressable coordinate
//! lookups) skip the full-table scan entirely.

use nula_core::event::{Alphabet, Kind, SingleLetterTag};
use nula_core::filter::Filter;
use nula_core::key::PublicKey;

/// The shape of a filter, classified by which secondary index can
/// answer it without a full scan.
#[derive(Debug, Clone)]
pub(crate) enum QueryPattern {
    /// One author, nothing else selective. Use `by_author`.
    Author(PublicKey),
    /// One `(kind, author)`. Use `by_kind_author`.
    KindAuthor(Kind, PublicKey),
    /// Addressable lookup: kind in 30000..40000 + author + d-tag.
    /// Use `by_coordinate` for an O(1) hit.
    Coordinate {
        kind: Kind,
        author: PublicKey,
        identifier: String,
    },
    /// No selective single-key index applies; fall back to the
    /// global sorted index and apply the filter pointwise.
    Generic,
}

impl From<&Filter> for QueryPattern {
    fn from(filter: &Filter) -> Self {
        // We never refine queries that asked for specific event ids;
        // the caller is already addressing the primary table.
        if filter.ids.as_ref().is_some_and(|v| !v.is_empty()) {
            return Self::Generic;
        }
        // A free-text search demands a pointwise scan.
        if filter.search.is_some() {
            return Self::Generic;
        }

        let authors_len = filter.authors.as_ref().map_or(0, Vec::len);
        let kinds_len = filter.kinds.as_ref().map_or(0, Vec::len);

        let first_author = filter.authors.as_ref().and_then(|v| v.first()).copied();
        let first_kind = filter.kinds.as_ref().and_then(|v| v.first()).copied();

        // Read the `d` single-letter tag selector if it has exactly
        // one value; addressable coordinate lookups demand that.
        let identifier = filter
            .generic_tags
            .get(&single_letter_d())
            .and_then(|values| {
                if values.len() == 1 {
                    values.first().cloned()
                } else {
                    None
                }
            });
        let other_tags = filter.generic_tags.len()
            - usize::from(filter.generic_tags.contains_key(&single_letter_d()));

        match (authors_len, kinds_len, first_author, first_kind, identifier) {
            (1, 1, Some(author), Some(kind), Some(d))
                if kind.is_addressable() && other_tags == 0 =>
            {
                Self::Coordinate {
                    kind,
                    author,
                    identifier: d,
                }
            }
            (1, 1, Some(author), Some(kind), None) if other_tags == 0 => {
                Self::KindAuthor(kind, author)
            }
            (1, 0, Some(author), None, None) if other_tags == 0 => Self::Author(author),
            _ => Self::Generic,
        }
    }
}

/// Build the `d` single-letter tag selector once per call site.
const fn single_letter_d() -> SingleLetterTag {
    SingleLetterTag::lowercase(Alphabet::D)
}

#[cfg(test)]
mod tests {
    use nula_core::event::{EventId, Kind};
    use nula_core::filter::Filter;
    use nula_core::key::Keys;

    use super::*;

    fn pubkey() -> PublicKey {
        *Keys::generate().expect("os rng").public_key()
    }

    fn event_id() -> EventId {
        EventId::from_slice(&[0u8; 32]).expect("32-byte slice")
    }

    #[test]
    fn empty_filter_is_generic() {
        let pattern: QueryPattern = (&Filter::new()).into();
        assert!(matches!(pattern, QueryPattern::Generic));
    }

    #[test]
    fn single_author_picks_author_pattern() {
        let f = Filter::new().author(pubkey());
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::Author(_)));
    }

    #[test]
    fn kind_plus_single_author_picks_kind_author() {
        let f = Filter::new().author(pubkey()).kind(Kind::TEXT_NOTE);
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::KindAuthor(_, _)));
    }

    #[test]
    fn addressable_with_d_tag_picks_coordinate() {
        let f = Filter::new()
            .author(pubkey())
            .kind(Kind::LONG_FORM_TEXT_NOTE)
            .identifier("post-1");
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::Coordinate { .. }));
    }

    #[test]
    fn multi_author_is_generic() {
        let f = Filter::new().authors([pubkey(), pubkey()]);
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::Generic));
    }

    #[test]
    fn ids_filter_is_generic() {
        let f = Filter::new().author(pubkey()).ids([event_id()]);
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::Generic));
    }

    #[test]
    fn extra_generic_tag_blocks_kind_author() {
        let f = Filter::new()
            .author(pubkey())
            .kind(Kind::TEXT_NOTE)
            .hashtag("rust");
        let pattern: QueryPattern = (&f).into();
        assert!(matches!(pattern, QueryPattern::Generic));
    }
}
