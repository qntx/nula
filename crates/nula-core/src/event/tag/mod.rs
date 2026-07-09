//! Event tags.
//!
//! A tag is an array of strings whose first element names the tag and whose
//! remaining elements carry tag-specific data. NIP-01 calls out single-letter
//! lowercase tags as the queryable subset (clients can filter by them via
//! [`Filter::generic_tags`]). Uppercase single-letter tags carry meaning to
//! relays/clients but are not queryable.
//!
//! The module is layered:
//!
//! - [`single_letter::SingleLetterTag`] — the fixed-shape lowercase/uppercase
//!   single-letter identifier used by both tags and filters.
//! - [`kind::TagKind`] — the discriminator stored at the head of every tag.
//! - [`tag::Tag`] — a raw `Vec<String>` with helpers around the head.
//! - [`list::Tags`] — an ordered collection with helpful indexing.
//!
//! [`Filter::generic_tags`]: crate::filter::Filter

pub mod kind;
pub mod list;
pub mod single_letter;
#[expect(
    clippy::module_inception,
    reason = "the inner `tag` module exposes the `Tag` struct; the outer module groups every tag-related submodule"
)]
pub mod tag;

pub use self::kind::TagKind;
pub use self::list::Tags;
pub use self::single_letter::{Alphabet, AlphabetError, SingleLetterTag, SingleLetterTagError};
pub use self::tag::{Tag, TagError};
