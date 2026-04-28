// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! NIP-11 retention policy (`retention` array).
//!
//! Each [`RelayRetention`] entry tells clients how long the relay holds a
//! given class of events. NIP-11 lets the `kinds` array mix bare integers
//! and `[start, end]` 2-element arrays; [`KindRange`] models that union.

use core::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use crate::event::Kind;

/// Retention rule advertised by the relay.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayRetention {
    /// Event kinds covered by this rule.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<KindRange>,
    /// Maximum retention time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    /// Maximum number of events stored under this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// Either a single [`Kind`] or an inclusive `[start, end]` kind range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum KindRange {
    /// One specific kind.
    Single(Kind),
    /// Inclusive range from `start` to `end`.
    Range {
        /// Lowest matching kind.
        start: Kind,
        /// Highest matching kind.
        end: Kind,
    },
}

impl Serialize for KindRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(kind) => serializer.serialize_u16(kind.as_u16()),
            Self::Range { start, end } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&start.as_u16())?;
                seq.serialize_element(&end.as_u16())?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KindRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(KindRangeVisitor)
    }
}

struct KindRangeVisitor;

impl<'de> Visitor<'de> for KindRangeVisitor {
    type Value = KindRange;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a kind (u16) or a [start, end] kind range")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        let narrowed =
            u16::try_from(value).map_err(|_| E::custom("kind exceeds the 16-bit range"))?;
        Ok(KindRange::Single(Kind::from(narrowed)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        let unsigned = u64::try_from(value).map_err(|_| E::custom("kind must be non-negative"))?;
        self.visit_u64(unsigned)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let start: u16 = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("kind range missing start"))?;
        let end: u16 = seq
            .next_element()?
            .ok_or_else(|| de::Error::custom("kind range missing end"))?;
        if seq.next_element::<u16>()?.is_some() {
            return Err(de::Error::custom(
                "kind range must contain exactly two elements",
            ));
        }
        if start > end {
            return Err(de::Error::custom("kind range start must be <= end"));
        }
        Ok(KindRange::Range {
            start: Kind::from(start),
            end: Kind::from(end),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_kind_round_trip() {
        let kr = KindRange::Single(Kind::TEXT_NOTE);
        let json = serde_json::to_string(&kr).unwrap();
        assert_eq!(json, "1");
        let parsed: KindRange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kr);
    }

    #[test]
    fn range_round_trip() {
        let kr = KindRange::Range {
            start: Kind::from(40_u16),
            end: Kind::from(49_u16),
        };
        let json = serde_json::to_string(&kr).unwrap();
        assert_eq!(json, "[40,49]");
        let parsed: KindRange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kr);
    }

    #[test]
    fn deserialize_mixed_array() {
        let json = "[0,1,[5,7],[40,49]]";
        let parsed: Vec<KindRange> = serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed,
            vec![
                KindRange::Single(Kind::from(0_u16)),
                KindRange::Single(Kind::from(1_u16)),
                KindRange::Range {
                    start: Kind::from(5_u16),
                    end: Kind::from(7_u16),
                },
                KindRange::Range {
                    start: Kind::from(40_u16),
                    end: Kind::from(49_u16),
                },
            ]
        );
    }

    #[test]
    fn rejects_inverted_range() {
        let err = serde_json::from_str::<KindRange>("[10,5]").unwrap_err();
        assert!(err.to_string().contains("start must be <= end"));
    }

    #[test]
    fn rejects_three_element_array() {
        let err = serde_json::from_str::<KindRange>("[1,2,3]").unwrap_err();
        assert!(err.to_string().contains("exactly two elements"));
    }

    #[test]
    fn retention_round_trip() {
        let rules = vec![
            RelayRetention {
                kinds: vec![
                    KindRange::Single(Kind::from(0_u16)),
                    KindRange::Single(Kind::from(1_u16)),
                    KindRange::Range {
                        start: Kind::from(5_u16),
                        end: Kind::from(7_u16),
                    },
                ],
                time: Some(3600),
                count: None,
            },
            RelayRetention {
                kinds: Vec::new(),
                time: Some(3600),
                count: Some(100),
            },
        ];
        let json = serde_json::to_string(&rules).unwrap();
        let parsed: Vec<RelayRetention> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rules);
    }
}
