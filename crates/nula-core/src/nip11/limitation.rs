// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! NIP-11 server-side limitation declarations (`limitation` object).
//!
//! Every field is optional: relays advertise only the limits they enforce.

use serde::{Deserialize, Serialize};

/// Hard caps the relay applies to client behaviour.
///
/// All fields are optional; absent values mean "the relay does not advertise
/// a limit". `Default` produces an empty advertisement.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayLimitation {
    /// Maximum size in bytes of an inbound WebSocket message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_length: Option<u64>,
    /// Maximum number of concurrent subscriptions per connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_subscriptions: Option<u32>,
    /// Maximum filter count per `REQ`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_filters: Option<u32>,
    /// Maximum value the client may set for `limit` in a filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_limit: Option<u32>,
    /// Maximum length (chars) of a subscription id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_subid_length: Option<u32>,
    /// Maximum number of tags an event may carry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_event_tags: Option<u32>,
    /// Maximum content length (bytes) for any single event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_content_length: Option<u64>,
    /// Minimum NIP-13 `PoW` difficulty required for accepted events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pow_difficulty: Option<u8>,
    /// Whether NIP-42 authentication is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<bool>,
    /// Whether NIP-11 payment is required to use the relay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_required: Option<bool>,
    /// Whether write access is restricted (e.g. invite-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_writes: Option<bool>,
    /// Inclusive lower bound on `created_at` (seconds since the epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_lower_limit: Option<i64>,
    /// Inclusive upper bound on `created_at` (seconds since the epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_upper_limit: Option<i64>,
    /// Default limit applied to `REQ` when the client omits one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_limit: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_serializes_to_empty_object() {
        let json = serde_json::to_string(&RelayLimitation::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn round_trip_subset() {
        let limitation = RelayLimitation {
            max_message_length: Some(16_384),
            max_subscriptions: Some(20),
            min_pow_difficulty: Some(20),
            auth_required: Some(true),
            ..RelayLimitation::default()
        };
        let json = serde_json::to_string(&limitation).unwrap();
        let parsed: RelayLimitation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, limitation);
    }
}
