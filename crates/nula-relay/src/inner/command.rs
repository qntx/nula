//! Commands carried from the public [`crate::Relay`] handle to the
//! [`super::Inner`] actor.
//!
//! Each command is fire-and-respond: the caller awaits a `oneshot`
//! reply that the actor signals once the command has been observed
//! and (where relevant) processed against the current connection
//! state. Failure to deliver the reply (e.g. when the actor has
//! shut down between send and process) surfaces in the public API
//! as [`crate::Error::Shutdown`].

use nula_core::Filter;
use nula_core::{ClientMessage, Event, SubscriptionId};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::options::{PublishOptions, SubscribeOptions};
use crate::subscription::SubscriptionItem;

/// Reply slot for a command. The actor `send`s exactly once per
/// matching command, then closes the channel.
pub(crate) type Reply<T> = oneshot::Sender<T>;

/// Sender used to forward subscription items to a
/// [`crate::SubscriptionHandle`]. The actor populates the handle
/// when [`Command::Subscribe`] is processed.
pub(crate) type SubscriptionSink = mpsc::UnboundedSender<SubscriptionItem>;

/// Public-API commands the actor processes.
#[derive(Debug)]
pub(crate) enum Command {
    /// Move into [`crate::RelayStatus::Connecting`] and attempt a
    /// handshake. Replies once the connection is `Connected` or the
    /// configured connect timeout fires.
    Connect { reply: Reply<Result<(), Error>> },

    /// Tear down the current socket without terminating the actor.
    /// The reconnect timer is cancelled. After this command the
    /// caller can issue [`Self::Connect`] again to come back online.
    Disconnect { reply: Reply<()> },

    /// Register a new subscription. The actor allocates a slot,
    /// writes the [`crate::SubscriptionItem`] sender into its map,
    /// and (when connected) issues the `["REQ", …]` frame.
    Subscribe {
        id: SubscriptionId,
        filters: Vec<Filter>,
        options: SubscribeOptions,
        sink: SubscriptionSink,
        reply: Reply<Result<(), Error>>,
    },

    /// Register a NIP-77 reconciliation session. The actor
    /// allocates a subscription slot (so inbound `NEG-MSG` /
    /// `NEG-ERR` frames route correctly) and emits a
    /// `["NEG-OPEN", …]` frame instead of a `["REQ", …]`.
    /// Sessions are not re-issued across reconnects -- see
    /// [`super::state::SubscriptionEntry::skip_reissue`].
    SubscribeNeg {
        id: SubscriptionId,
        filter: Filter,
        initial_message_hex: String,
        sink: SubscriptionSink,
        reply: Reply<Result<(), Error>>,
    },

    /// Publish an event. Replies once the relay returns `OK <id>` or
    /// the configured publish timeout fires.
    Publish {
        event: Event,
        options: PublishOptions,
        reply: Reply<Result<(), Error>>,
    },

    /// Reply to a NIP-42 challenge with a signed kind-22242 event.
    /// Available only when the `nip42` feature is on.
    #[cfg(feature = "nip42")]
    Authenticate {
        event: Event,
        reply: Reply<Result<(), Error>>,
    },

    /// Ship an arbitrary [`ClientMessage`] frame over the current
    /// connection. The actor serialises the message, pushes it on
    /// the sink, and replies as soon as the underlying transport
    /// accepts (or rejects) the write -- there is no per-message
    /// `OK` correlation, since the message types this command
    /// targets (e.g. NIP-77 `NegOpen`) drive their own reply
    /// streams through normal subscription notifications.
    SendMsg {
        message: ClientMessage,
        reply: Reply<Result<(), Error>>,
    },

    /// Stop the actor. After the actor processes this command no
    /// further commands are honoured; pending replies are cancelled
    /// with [`crate::Error::Shutdown`].
    Shutdown,
}
