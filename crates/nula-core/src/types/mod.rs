//! Shared value objects used across the Nostr protocol.
//!
//! These types are pure data: no I/O, no allocations beyond what is required
//! to hold their canonical representation. They are exposed at the crate root
//! so consumers can write `use nula_core::Timestamp` without diving into the
//! module hierarchy.

pub mod image;
pub mod relay_url;
pub mod timestamp;
pub mod url;

pub use self::image::{ImageDimensions, ImageError};
pub use self::relay_url::{RelayUrl, RelayUrlError};
pub use self::timestamp::{Timestamp, TimestampError};
pub use self::url::{Url, UrlError};
