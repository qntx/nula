//! Messages a client sends to a relay.
//!
//! Per [NIP-01], every message is a heterogeneous JSON array tagged by its
//! command (`"EVENT"`, `"REQ"`, `"CLOSE"`, `"AUTH"`, `"COUNT"`). Custom
//! `Serialize`/`Deserialize` impls preserve the wire shape; the public enum
//! layout matches the protocol surface so callers don't have to know about
//! the magic command strings.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::subscription_id::SubscriptionId;
use crate::event::Event;
use crate::filter::Filter;

const TAG_EVENT: &str = "EVENT";
const TAG_REQ: &str = "REQ";
const TAG_CLOSE: &str = "CLOSE";
const TAG_AUTH: &str = "AUTH";
const TAG_COUNT: &str = "COUNT";

/// Errors raised when parsing a [`ClientMessage`].
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ClientMessageError {
    /// The wire array was empty.
    #[error("client message must not be empty")]
    Empty,
    /// The message tag was not recognised.
    #[error("unknown client message tag `{0}`")]
    UnknownTag(String),
    /// The message tag was recognised but the payload was malformed.
    #[error("malformed `{tag}` message: {reason}")]
    Malformed {
        /// The wire tag string.
        tag: &'static str,
        /// Human-readable explanation.
        reason: String,
    },
}

/// Messages sent from a client to a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientMessage {
    /// Publish an event to the relay.
    ///
    /// Wire form: `["EVENT", <event>]`.
    Event(Event),
    /// Open or replace a subscription with one or more filters.
    ///
    /// Wire form: `["REQ", <subscription_id>, <filter1>, <filter2>, …]`.
    Req {
        /// Subscription identifier.
        subscription_id: SubscriptionId,
        /// Filters that the relay must AND together when resolving.
        filters: Vec<Filter>,
    },
    /// Close a subscription.
    ///
    /// Wire form: `["CLOSE", <subscription_id>]`.
    Close(SubscriptionId),
    /// Reply to a NIP-42 challenge with a signed kind-22242 event.
    ///
    /// Wire form: `["AUTH", <event>]`.
    Auth(Event),
    /// Count events matching a filter (NIP-45).
    ///
    /// Wire form: `["COUNT", <subscription_id>, <filter>]`.
    Count {
        /// Subscription identifier.
        subscription_id: SubscriptionId,
        /// Counting filter.
        filter: Filter,
    },
}

impl ClientMessage {
    /// Convenience constructor for [`ClientMessage::Event`].
    #[must_use]
    pub const fn event(event: Event) -> Self {
        Self::Event(event)
    }

    /// Convenience constructor for [`ClientMessage::Req`].
    #[must_use]
    pub const fn req(subscription_id: SubscriptionId, filters: Vec<Filter>) -> Self {
        Self::Req {
            subscription_id,
            filters,
        }
    }

    /// Convenience constructor for [`ClientMessage::Close`].
    #[must_use]
    pub const fn close(subscription_id: SubscriptionId) -> Self {
        Self::Close(subscription_id)
    }

    /// Convenience constructor for [`ClientMessage::Auth`].
    #[must_use]
    pub const fn auth(event: Event) -> Self {
        Self::Auth(event)
    }

    /// Convenience constructor for [`ClientMessage::Count`].
    #[must_use]
    pub const fn count(subscription_id: SubscriptionId, filter: Filter) -> Self {
        Self::Count {
            subscription_id,
            filter,
        }
    }
}

impl Serialize for ClientMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Event(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_EVENT)?;
                seq.serialize_element(event)?;
                seq.end()
            }
            Self::Req {
                subscription_id,
                filters,
            } => {
                let mut seq = serializer.serialize_seq(Some(2 + filters.len()))?;
                seq.serialize_element(TAG_REQ)?;
                seq.serialize_element(subscription_id)?;
                for f in filters {
                    seq.serialize_element(f)?;
                }
                seq.end()
            }
            Self::Close(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_CLOSE)?;
                seq.serialize_element(id)?;
                seq.end()
            }
            Self::Auth(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_AUTH)?;
                seq.serialize_element(event)?;
                seq.end()
            }
            Self::Count {
                subscription_id,
                filter,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(TAG_COUNT)?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(filter)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ClientMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClientVisitor;

        impl<'de> Visitor<'de> for ClientVisitor {
            type Value = ClientMessage;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Nostr client message array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ClientMessage, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let tag: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom(ClientMessageError::Empty))?;
                match tag.as_str() {
                    TAG_EVENT => decode_event(&mut seq),
                    TAG_REQ => decode_req(&mut seq),
                    TAG_CLOSE => decode_close(&mut seq),
                    TAG_AUTH => decode_auth(&mut seq),
                    TAG_COUNT => decode_count(&mut seq),
                    other => Err(de::Error::custom(ClientMessageError::UnknownTag(
                        other.to_owned(),
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(ClientVisitor)
    }
}

fn decode_event<'de, A>(seq: &mut A) -> Result<ClientMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let event: Event = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_EVENT,
            reason: "missing event".to_owned(),
        })
    })?;
    Ok(ClientMessage::Event(event))
}

fn decode_req<'de, A>(seq: &mut A) -> Result<ClientMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let subscription_id: SubscriptionId = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_REQ,
            reason: "missing subscription id".to_owned(),
        })
    })?;
    let mut filters = Vec::new();
    while let Some(filter) = seq.next_element::<Filter>()? {
        filters.push(filter);
    }
    if filters.is_empty() {
        return Err(de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_REQ,
            reason: "REQ requires at least one filter".to_owned(),
        }));
    }
    Ok(ClientMessage::Req {
        subscription_id,
        filters,
    })
}

fn decode_close<'de, A>(seq: &mut A) -> Result<ClientMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let id: SubscriptionId = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_CLOSE,
            reason: "missing subscription id".to_owned(),
        })
    })?;
    Ok(ClientMessage::Close(id))
}

fn decode_auth<'de, A>(seq: &mut A) -> Result<ClientMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let event: Event = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_AUTH,
            reason: "missing event".to_owned(),
        })
    })?;
    Ok(ClientMessage::Auth(event))
}

fn decode_count<'de, A>(seq: &mut A) -> Result<ClientMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let subscription_id: SubscriptionId = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_COUNT,
            reason: "missing subscription id".to_owned(),
        })
    })?;
    let filter: Filter = seq.next_element()?.ok_or_else(|| {
        de::Error::custom(ClientMessageError::Malformed {
            tag: TAG_COUNT,
            reason: "missing filter".to_owned(),
        })
    })?;
    Ok(ClientMessage::Count {
        subscription_id,
        filter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::event::EventBuilder;
    use crate::types::Timestamp;
    use crate::{Kind, Tag};

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn signed_event() -> Event {
        EventBuilder::text_note("hello")
            .tag(Tag::new(["alt", "test"]).unwrap())
            .created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&keys())
            .unwrap()
    }

    #[test]
    fn event_round_trip() {
        let msg = ClientMessage::event(signed_event());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.starts_with("[\"EVENT\","));
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn req_round_trip() {
        let msg = ClientMessage::req(
            SubscriptionId::new("sub-1").unwrap(),
            vec![Filter::new().kind(Kind::TEXT_NOTE)],
        );
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.starts_with("[\"REQ\",\"sub-1\","));
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn req_rejects_zero_filters() {
        let json = "[\"REQ\",\"sub-1\"]";
        let err = serde_json::from_str::<ClientMessage>(json).unwrap_err();
        assert!(err.to_string().contains("at least one filter"));
    }

    #[test]
    fn close_round_trip() {
        let msg = ClientMessage::close(SubscriptionId::new("sub-1").unwrap());
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "[\"CLOSE\",\"sub-1\"]");
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn auth_round_trip() {
        let msg = ClientMessage::auth(signed_event());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.starts_with("[\"AUTH\","));
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn count_round_trip() {
        let msg = ClientMessage::count(
            SubscriptionId::new("sub-1").unwrap(),
            Filter::new().kind(Kind::TEXT_NOTE),
        );
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.starts_with("[\"COUNT\",\"sub-1\","));
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn unknown_tag_rejected() {
        let json = "[\"FOO\",\"sub-1\"]";
        let err = serde_json::from_str::<ClientMessage>(json).unwrap_err();
        assert!(err.to_string().contains("unknown client message tag"));
    }

    #[test]
    fn empty_array_rejected() {
        let json = "[]";
        let err = serde_json::from_str::<ClientMessage>(json).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }
}
