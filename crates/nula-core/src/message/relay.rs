// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Messages a relay sends to a client.
//!
//! Per [NIP-01], every relay-to-client message is a JSON array tagged by its
//! command. NIP-20 documents the [`MachineReadablePrefix`] applied to `OK`
//! and `CLOSED` reasons; this module exposes the parsed prefix so callers can
//! switch on it without re-parsing the wire string.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;
use core::str::FromStr;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::subscription_id::SubscriptionId;
use crate::event::{Event, EventId};

const TAG_EVENT: &str = "EVENT";
const TAG_OK: &str = "OK";
const TAG_EOSE: &str = "EOSE";
const TAG_CLOSED: &str = "CLOSED";
const TAG_NOTICE: &str = "NOTICE";
const TAG_AUTH: &str = "AUTH";
const TAG_COUNT: &str = "COUNT";

/// Errors raised when constructing a [`MachineReadablePrefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MachineReadablePrefixError {
    /// The prefix string was not one of the known NIP-20 prefixes.
    #[error("unknown machine-readable prefix")]
    Unknown,
}

/// Standardised reason prefix used in `OK` / `CLOSED` reasons (NIP-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MachineReadablePrefix {
    /// `duplicate:` — the relay already had the event.
    Duplicate,
    /// `pow:` — proof-of-work requirements were not met.
    Pow,
    /// `blocked:` — the author or pubkey is blocked by the relay.
    Blocked,
    /// `rate-limited:` — the client hit a rate limit.
    RateLimited,
    /// `invalid:` — the event failed validation.
    Invalid,
    /// `error:` — the relay encountered an internal error.
    Error,
    /// `restricted:` — the author lacks permission (e.g. NIP-42 not done).
    Restricted,
    /// `auth-required:` — NIP-42 authentication is required.
    AuthRequired,
    /// `payment-required:` — paid relay; the client has not paid yet.
    PaymentRequired,
}

impl MachineReadablePrefix {
    /// Static wire string (without the trailing colon).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Pow => "pow",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate-limited",
            Self::Invalid => "invalid",
            Self::Error => "error",
            Self::Restricted => "restricted",
            Self::AuthRequired => "auth-required",
            Self::PaymentRequired => "payment-required",
        }
    }

    /// Try to extract the prefix from a NIP-20 reason such as `"pow: 24"`.
    /// Returns `None` if the string does not start with a known prefix
    /// followed by `:`.
    #[must_use]
    pub fn from_reason(reason: &str) -> Option<Self> {
        let (prefix, _rest) = reason.split_once(':')?;
        prefix.parse().ok()
    }
}

impl fmt::Display for MachineReadablePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MachineReadablePrefix {
    type Err = MachineReadablePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = match s {
            "duplicate" => Self::Duplicate,
            "pow" => Self::Pow,
            "blocked" => Self::Blocked,
            "rate-limited" => Self::RateLimited,
            "invalid" => Self::Invalid,
            "error" => Self::Error,
            "restricted" => Self::Restricted,
            "auth-required" => Self::AuthRequired,
            "payment-required" => Self::PaymentRequired,
            _ => return Err(MachineReadablePrefixError::Unknown),
        };
        Ok(value)
    }
}

/// Errors raised when parsing a [`RelayMessage`].
#[derive(Debug, Clone, Error)]
pub enum RelayMessageError {
    /// The wire array was empty.
    #[error("relay message must not be empty")]
    Empty,
    /// The message tag was not recognised.
    #[error("unknown relay message tag `{0}`")]
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

/// Messages sent from a relay to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// A subscription event match.
    ///
    /// Wire form: `["EVENT", <subscription_id>, <event>]`.
    Event {
        /// Subscription identifier originally supplied by the client.
        subscription_id: SubscriptionId,
        /// The matched event.
        event: Event,
    },
    /// Acknowledgement for a published [`crate::Event`].
    ///
    /// Wire form: `["OK", <event_id>, <accepted>, <message>]`.
    Ok {
        /// Event id the relay is acknowledging.
        event_id: EventId,
        /// `true` if the event was accepted.
        accepted: bool,
        /// Human-readable reason. Use [`MachineReadablePrefix::from_reason`]
        /// to recover a structured reason.
        message: String,
    },
    /// End-of-stored-events sentinel: the relay has finished sending stored
    /// matches; future events arrive in real time.
    ///
    /// Wire form: `["EOSE", <subscription_id>]`.
    EndOfStoredEvents(SubscriptionId),
    /// The relay closed the subscription.
    ///
    /// Wire form: `["CLOSED", <subscription_id>, <reason>]`.
    Closed {
        /// Subscription identifier.
        subscription_id: SubscriptionId,
        /// Reason string. Use [`MachineReadablePrefix::from_reason`] to
        /// recover a structured reason.
        message: String,
    },
    /// A free-form notice intended for end-user display.
    ///
    /// Wire form: `["NOTICE", <message>]`.
    Notice(String),
    /// NIP-42 authentication challenge.
    ///
    /// Wire form: `["AUTH", <challenge>]`.
    Auth(String),
    /// Count reply for a previously issued `COUNT` request (NIP-45).
    ///
    /// Wire form: `["COUNT", <subscription_id>, {"count": <n>}]`.
    Count {
        /// Subscription identifier.
        subscription_id: SubscriptionId,
        /// Number of matching events.
        count: u64,
    },
}

impl Serialize for RelayMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Event {
                subscription_id,
                event,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(TAG_EVENT)?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(event)?;
                seq.end()
            }
            Self::Ok {
                event_id,
                accepted,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element(TAG_OK)?;
                seq.serialize_element(event_id)?;
                seq.serialize_element(accepted)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::EndOfStoredEvents(id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_EOSE)?;
                seq.serialize_element(id)?;
                seq.end()
            }
            Self::Closed {
                subscription_id,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(TAG_CLOSED)?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::Notice(message) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_NOTICE)?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Self::Auth(challenge) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(TAG_AUTH)?;
                seq.serialize_element(challenge)?;
                seq.end()
            }
            Self::Count {
                subscription_id,
                count,
            } => {
                #[derive(Serialize)]
                struct CountPayload {
                    count: u64,
                }

                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element(TAG_COUNT)?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(&CountPayload { count: *count })?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RelayMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RelayVisitor;

        impl<'de> Visitor<'de> for RelayVisitor {
            type Value = RelayMessage;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Nostr relay message array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RelayMessage, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let tag: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom(RelayMessageError::Empty))?;
                match tag.as_str() {
                    TAG_EVENT => decode_event(&mut seq),
                    TAG_OK => decode_ok(&mut seq),
                    TAG_EOSE => decode_eose(&mut seq),
                    TAG_CLOSED => decode_closed(&mut seq),
                    TAG_NOTICE => decode_notice(&mut seq),
                    TAG_AUTH => decode_auth(&mut seq),
                    TAG_COUNT => decode_count(&mut seq),
                    other => Err(de::Error::custom(RelayMessageError::UnknownTag(
                        other.to_owned(),
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(RelayVisitor)
    }
}

fn malformed<E: de::Error>(tag: &'static str, reason: &str) -> E {
    E::custom(RelayMessageError::Malformed {
        tag,
        reason: reason.to_owned(),
    })
}

fn decode_event<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let subscription_id: SubscriptionId = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_EVENT, "missing subscription id"))?;
    let event: Event = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_EVENT, "missing event"))?;
    Ok(RelayMessage::Event {
        subscription_id,
        event,
    })
}

fn decode_ok<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let event_id: EventId = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_OK, "missing event id"))?;
    let accepted: bool = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_OK, "missing accepted flag"))?;
    let message: String = seq.next_element()?.unwrap_or_default();
    Ok(RelayMessage::Ok {
        event_id,
        accepted,
        message,
    })
}

fn decode_eose<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let id: SubscriptionId = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_EOSE, "missing subscription id"))?;
    Ok(RelayMessage::EndOfStoredEvents(id))
}

fn decode_closed<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let subscription_id: SubscriptionId = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_CLOSED, "missing subscription id"))?;
    let message: String = seq.next_element()?.unwrap_or_default();
    Ok(RelayMessage::Closed {
        subscription_id,
        message,
    })
}

fn decode_notice<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let message: String = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_NOTICE, "missing message"))?;
    Ok(RelayMessage::Notice(message))
}

fn decode_auth<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    let challenge: String = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_AUTH, "missing challenge"))?;
    Ok(RelayMessage::Auth(challenge))
}

fn decode_count<'de, A>(seq: &mut A) -> Result<RelayMessage, A::Error>
where
    A: SeqAccess<'de>,
{
    #[derive(Deserialize)]
    struct CountPayload {
        count: u64,
    }

    let subscription_id: SubscriptionId = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_COUNT, "missing subscription id"))?;
    let payload: CountPayload = seq
        .next_element()?
        .ok_or_else(|| malformed::<A::Error>(TAG_COUNT, "missing count payload"))?;
    Ok(RelayMessage::Count {
        subscription_id,
        count: payload.count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::event::EventBuilder;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn signed_event() -> Event {
        EventBuilder::text_note("hello")
            .sign_with_keys(&keys())
            .unwrap()
    }

    fn sub() -> SubscriptionId {
        SubscriptionId::new("sub-1").unwrap()
    }

    #[test]
    fn event_round_trip() {
        let msg = RelayMessage::Event {
            subscription_id: sub(),
            event: signed_event(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.starts_with("[\"EVENT\",\"sub-1\","));
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn ok_round_trip_with_message() {
        let msg = RelayMessage::Ok {
            event_id: signed_event().id,
            accepted: false,
            message: "blocked: spam".to_owned(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn ok_with_empty_message_round_trip() {
        let msg = RelayMessage::Ok {
            event_id: signed_event().id,
            accepted: true,
            message: String::new(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn eose_round_trip() {
        let msg = RelayMessage::EndOfStoredEvents(sub());
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "[\"EOSE\",\"sub-1\"]");
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn closed_round_trip() {
        let msg = RelayMessage::Closed {
            subscription_id: sub(),
            message: "auth-required: please authenticate".to_owned(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn notice_round_trip() {
        let msg = RelayMessage::Notice("welcome".to_owned());
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "[\"NOTICE\",\"welcome\"]");
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn auth_challenge_round_trip() {
        let msg = RelayMessage::Auth("challenge-string".to_owned());
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn count_round_trip() {
        let msg = RelayMessage::Count {
            subscription_id: sub(),
            count: 42,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "[\"COUNT\",\"sub-1\",{\"count\":42}]");
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn machine_readable_prefix_parses() {
        assert_eq!(
            MachineReadablePrefix::from_reason("blocked: spam"),
            Some(MachineReadablePrefix::Blocked)
        );
        assert_eq!(
            MachineReadablePrefix::from_reason("auth-required: please"),
            Some(MachineReadablePrefix::AuthRequired)
        );
        assert!(MachineReadablePrefix::from_reason("no prefix").is_none());
        assert!(MachineReadablePrefix::from_reason("unknown: thing").is_none());
    }

    #[test]
    fn unknown_tag_rejected() {
        let json = "[\"WAT\",\"x\"]";
        let err = serde_json::from_str::<RelayMessage>(json).unwrap_err();
        assert!(err.to_string().contains("unknown relay message tag"));
    }
}
