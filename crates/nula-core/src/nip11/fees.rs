//! NIP-11 fee schedule (`fees` object).

use serde::{Deserialize, Serialize};

use crate::event::Kind;

/// Per-class fee structure (admission, subscription, publication).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayFees {
    /// Fees collected once when a client first joins the relay.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub admission: Vec<RelayFee>,
    /// Periodic subscription fees.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subscription: Vec<RelayFee>,
    /// Per-event publication fees.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub publication: Vec<RelayFee>,
}

/// A single line item in a [`RelayFees`] schedule.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFee {
    /// Numeric amount (NIP-11 leaves the meaning to the relay).
    pub amount: u64,
    /// Currency / accounting unit (e.g. `"msats"`).
    pub unit: String,
    /// Optional billing period in seconds (subscription fees only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    /// Restrict this entry to specific event kinds (publication fees only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<Kind>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fees_round_trip() {
        let fees = RelayFees {
            admission: vec![RelayFee {
                amount: 1000,
                unit: "msats".into(),
                period: None,
                kinds: None,
            }],
            subscription: vec![RelayFee {
                amount: 5000,
                unit: "msats".into(),
                period: Some(2_592_000),
                kinds: None,
            }],
            publication: vec![RelayFee {
                amount: 100,
                unit: "msats".into(),
                period: None,
                kinds: Some(vec![Kind::TEXT_NOTE]),
            }],
        };
        let json = serde_json::to_string(&fees).unwrap();
        let parsed: RelayFees = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fees);
    }

    #[test]
    fn empty_arrays_omitted() {
        let fees = RelayFees::default();
        let json = serde_json::to_string(&fees).unwrap();
        assert_eq!(json, "{}");
    }
}
