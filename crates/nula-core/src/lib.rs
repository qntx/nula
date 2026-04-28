// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Protocol primitives for the [Nostr] protocol used across the `nula` workspace.
//!
//! `nula-core` is the lowest layer of the workspace. It defines the on-the-wire
//! data model (events, filters, tags, messages), the cryptographic identity
//! (keys, signatures), and a small set of shared value types. It performs no
//! I/O, has no async runtime dependency, and is safe to reuse from tests,
//! relays, signers, and offline tooling.
//!
//! Higher-level crates layer pool management, transports, databases, gossip,
//! signers, and relay servers on top of these primitives.
//!
//! [Nostr]: https://github.com/nostr-protocol/nostr

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-core")]
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_assert_message,
        clippy::missing_errors_doc,
        clippy::tests_outside_test_module,
        reason = "test code may use panicking and indexing idioms for brevity"
    )
)]

pub mod event;
pub mod filter;
pub mod key;
pub mod message;
pub mod metadata;
pub mod nip02;
pub mod nip09;
pub mod nip10;
pub mod nip11;
pub mod nip13;
pub mod nip19;
pub mod nip22;
pub mod nip40;
pub mod nip42;
pub mod nip65;
pub mod nip70;
pub mod signer;
pub mod types;
pub mod util;

pub use self::event::{
    Alphabet, AlphabetError, Coordinate, CoordinateError, Event, EventBuilder, EventBuilderError,
    EventError, EventId, EventIdError, Kind, SingleLetterTag, SingleLetterTagError, Tag, TagError,
    TagKind, Tags, UnsignedEvent, UnsignedEventError, compute_event_id,
};
pub use self::filter::Filter;
pub use self::key::{Keys, PublicKey, PublicKeyError, SecretKey, SecretKeyError};
pub use self::message::{
    ClientMessage, ClientMessageError, MachineReadablePrefix, MachineReadablePrefixError,
    RelayMessage, RelayMessageError, SubscriptionId, SubscriptionIdError,
};
pub use self::metadata::Metadata;
pub use self::nip02::{Contact, ContactList, ContactListError};
pub use self::nip09::{AuthorityError, DeletionError, DeletionRequest};
pub use self::nip10::{EventReference, NoteMarker, NoteMarkerError, ThreadContext, ThreadError};
pub use self::nip11::{
    KindRange, RelayFee, RelayFees, RelayInformation, RelayLimitation, RelayRetention,
};
pub use self::nip13::{MineError, PowAttempt, PowError};
pub use self::nip19::{
    FromBech32, FromBech32Error, MAX_NIP19_LENGTH, Nip19Coordinate, Nip19Entity, Nip19Event,
    Nip19Profile, ToBech32, ToBech32Error,
};
pub use self::nip22::{Comment, CommentError, CommentScope};
pub use self::nip40::{ExpirationError, IsExpiredError};
pub use self::nip42::AuthError;
pub use self::nip65::{RelayList, RelayListError, RelayMarker, RelayMarkerError};
pub use self::signer::{NostrSigner, SignerError, SignerFuture, boxed_signer_future};
pub use self::types::{
    ImageDimensions, ImageError, RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError,
};
pub use self::util::{HexError, JsonUtil, RngError};
