//! [NIP-20] Command Results — *moved to NIP-01*.
//!
//! Upstream marked NIP-20 as `final mandatory` and folded its
//! contents into [NIP-01]. The protocol surface that NIP-20 used to
//! own (`OK` / `CLOSED` reason strings and their standardised
//! machine-readable prefixes) now lives directly in
//! [`crate::message::relay`].
//!
//! This module exists purely as a discoverability anchor so that
//! readers grepping for `nip20` or scrolling the [`crate::nips`]
//! index find the right entry point. The actual types are
//! re-exported here.
//!
//! # Spec ↔ source map
//!
//! | Spec section               | Module / type                                      |
//! |----------------------------|----------------------------------------------------|
//! | `OK` command result        | [`RelayMessage::Ok`]                               |
//! | `CLOSED` reason            | [`RelayMessage::Closed`]                           |
//! | Machine-readable prefixes  | [`MachineReadablePrefix`]                          |
//! | Prefix parse / format API  | [`MachineReadablePrefix::from_reason`], [`MachineReadablePrefix::as_str`] |
//!
//! [NIP-20]: https://github.com/nostr-protocol/nips/blob/master/20.md
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

pub use crate::message::{
    MachineReadablePrefix, MachineReadablePrefixError, RelayMessage, RelayMessageError,
};
