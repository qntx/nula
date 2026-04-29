//! Convenience re-exports for the most common Nostr types.
//!
//! Glob-importing this module pulls in the surface most application code
//! needs without sending the caller spelunking through `nula_core::*`:
//!
//! ```
//! use nula_core::prelude::*;
//!
//! let keys = Keys::generate().unwrap();
//! let event = EventBuilder::text_note("hello, nostr")
//!     .sign_with_keys(&keys)
//!     .unwrap();
//! event.verify().unwrap();
//! ```
//!
//! The list intentionally stays *small*: every re-export here is a type
//! the average caller touches by name. Less common items (`Tag`,
//! `TagKind`, `ImageDimensions`, the various `*Error` enums, …) live at
//! the crate root and stay one explicit `use` away. This keeps the
//! prelude mass-import idiom safe — no naming collisions with `std::*`
//! or with user code, and no surprise re-exports if we add new modules
//! later.

pub use crate::event::{Coordinate, Event, EventBuilder, EventId, Kind, UnsignedEvent};
pub use crate::filter::Filter;
pub use crate::key::{Keys, PublicKey, SecretKey};
pub use crate::message::{ClientMessage, RelayMessage, SubscriptionId};
pub use crate::metadata::Metadata;
pub use crate::nips::nip19::{FromBech32, Nip19Entity, ToBech32};
pub use crate::signer::NostrSigner;
pub use crate::types::{RelayUrl, Timestamp, Url};
pub use crate::util::JsonUtil;
