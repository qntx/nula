//! Wire messages exchanged over a relay WebSocket.
//!
//! Per [NIP-01], every Nostr message is a JSON array whose first element is
//! the command name and whose subsequent elements depend on the command. This
//! module models the two message families:
//!
//! - [`client::ClientMessage`] — sent from a client to a relay,
//! - [`relay::RelayMessage`] — sent from a relay to a client.
//!
//! [`SubscriptionId`] is the opaque identifier shared by `REQ`, `EVENT`,
//! `EOSE`, `CLOSE`, and `CLOSED` to correlate subscriptions.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

pub mod client;
pub mod relay;
pub mod subscription_id;

pub use self::client::{ClientMessage, ClientMessageError};
pub use self::relay::{
    MachineReadablePrefix, MachineReadablePrefixError, RelayMessage, RelayMessageError,
};
pub use self::subscription_id::{SubscriptionId, SubscriptionIdError};
