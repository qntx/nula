//! [NIP-69] Peer-to-peer Order events.
//!
//! `kind: 38383` addressable events pool P2P buy/sell orders across
//! platforms (Mostro, `lnp2pBot`, `RoboSats`, Peach, …) into one shared
//! liquidity book. The order lives entirely in tags; `.content` stays
//! empty.
//!
//! Mandatory tags: `d` (order id), `k` (`sell` / `buy`), `f` (ISO 4217
//! currency), `s` (status), `amt` (satoshis, `0` = market price at
//! take time), `fa` (fiat amount, two values for range orders), `pm`
//! (payment methods), `premium` (percent), `network`, `layer`,
//! `expires_at`, `y` (platform), `z` (`order`). Optional: `source`,
//! `rating`, `name`, `g` (geohash), `bond`, `expiration` (NIP-40).
//!
//! [NIP-69]: https://github.com/nostr-protocol/nips/blob/master/69.md

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::types::Timestamp;

/// `kind: 38383` — peer-to-peer order.
pub const KIND_P2P_ORDER: Kind = Kind::P2P_ORDER;

/// The only `z` (document) value this NIP defines.
pub const ORDER_DOCUMENT: &str = "order";

/// Order side (`k` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrderSide {
    /// Maker sells bitcoin.
    Sell,
    /// Maker buys bitcoin.
    Buy,
}

impl OrderSide {
    /// Wire form used by the `k` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sell => "sell",
            Self::Buy => "buy",
        }
    }
}

impl fmt::Display for OrderSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OrderSide {
    type Err = OrderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sell" => Ok(Self::Sell),
            "buy" => Ok(Self::Buy),
            other => Err(OrderError::InvalidSide(other.to_owned())),
        }
    }
}

/// Order lifecycle status (`s` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrderStatus {
    /// Order is open and takeable.
    Pending,
    /// Maker canceled the order.
    Canceled,
    /// A taker accepted; trade is running.
    InProgress,
    /// Trade completed successfully.
    Success,
    /// Order expired without being taken.
    Expired,
}

impl OrderStatus {
    /// Wire form used by the `s` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Canceled => "canceled",
            Self::InProgress => "in-progress",
            Self::Success => "success",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OrderStatus {
    type Err = OrderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "canceled" => Ok(Self::Canceled),
            "in-progress" => Ok(Self::InProgress),
            "success" => Ok(Self::Success),
            "expired" => Ok(Self::Expired),
            other => Err(OrderError::InvalidStatus(other.to_owned())),
        }
    }
}

/// Fiat amount (`fa` tag): a fixed amount or a `[min, max]` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FiatAmount {
    /// Single fixed fiat amount.
    Fixed(u64),
    /// Range order: minimum and maximum fiat amount.
    Range {
        /// Minimum fiat amount.
        min: u64,
        /// Maximum fiat amount.
        max: u64,
    },
}

/// Typed bundle for a `kind: 38383` peer-to-peer order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pOrder {
    /// Unique order identifier (`d` tag).
    pub id: String,
    /// Order side (`k` tag).
    pub side: OrderSide,
    /// ISO 4217 currency code of the fiat leg (`f` tag).
    pub currency: String,
    /// Lifecycle status (`s` tag).
    pub status: OrderStatus,
    /// Bitcoin amount in satoshis (`amt` tag); `0` means the sat
    /// amount is fixed at take time from a public price API.
    pub amount_sats: u64,
    /// Fiat amount or range (`fa` tag).
    pub fiat_amount: FiatAmount,
    /// Accepted payment methods (`pm` tag values).
    pub payment_methods: Vec<String>,
    /// Premium percentage the maker asks over market (`premium` tag).
    pub premium: String,
    /// Trade network, e.g. `mainnet` / `testnet` (`network` tag).
    pub network: String,
    /// Trade layer, e.g. `onchain` / `lightning` (`layer` tag).
    pub layer: String,
    /// Deadline after which the order status should flip to expired
    /// (`expires_at` tag).
    pub expires_at: Timestamp,
    /// Publishing platform (`y` tag).
    pub platform: String,
    /// Optional order URL (`source` tag).
    pub source: Option<String>,
    /// Optional platform-defined maker rating JSON (`rating` tag).
    pub rating: Option<String>,
    /// Optional maker display name (`name` tag).
    pub name: Option<String>,
    /// Optional geohash for face-to-face trades (`g` tag).
    pub geohash: Option<String>,
    /// Optional security-deposit amount (`bond` tag).
    pub bond: Option<u64>,
    /// Optional NIP-40 relay-side expiration (`expiration` tag).
    pub expiration: Option<Timestamp>,
}

/// Errors raised while building or parsing a NIP-69 order.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OrderError {
    /// Event kind is not `38383`.
    #[error("unexpected kind for NIP-69 order: {}", .0.as_u16())]
    WrongKind(Kind),
    /// A mandatory tag is missing.
    #[error("NIP-69 order missing mandatory `{0}` tag")]
    MissingTag(&'static str),
    /// The `k` tag is neither `sell` nor `buy`.
    #[error("invalid order side: {0}")]
    InvalidSide(String),
    /// The `s` tag is not a documented status.
    #[error("invalid order status: {0}")]
    InvalidStatus(String),
    /// A numeric column failed to parse.
    #[error("invalid numeric value in `{0}` tag")]
    InvalidNumber(&'static str),
    /// The `z` tag is not `order`.
    #[error("invalid document type: {0}")]
    InvalidDocument(String),
}

fn tag_value<'e>(event: &'e Event, name: &'static str) -> Result<&'e str, OrderError> {
    event
        .tags
        .find_first(&TagKind::from_wire(name))
        .and_then(Tag::content)
        .ok_or(OrderError::MissingTag(name))
}

fn parse_u64(raw: &str, tag: &'static str) -> Result<u64, OrderError> {
    raw.parse().map_err(|_err| OrderError::InvalidNumber(tag))
}

impl P2pOrder {
    /// Parse a `kind: 38383` peer-to-peer order event.
    ///
    /// # Errors
    ///
    /// See [`OrderError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, OrderError> {
        if event.kind != KIND_P2P_ORDER {
            return Err(OrderError::WrongKind(event.kind));
        }
        let document = tag_value(event, "z")?;
        if document != ORDER_DOCUMENT {
            return Err(OrderError::InvalidDocument(document.to_owned()));
        }
        let fa_tag = event
            .tags
            .find_first(&TagKind::from_wire("fa"))
            .ok_or(OrderError::MissingTag("fa"))?;
        let fiat_amount = match (fa_tag.get(1), fa_tag.get(2)) {
            (Some(min), Some(max)) => FiatAmount::Range {
                min: parse_u64(min, "fa")?,
                max: parse_u64(max, "fa")?,
            },
            (Some(value), None) => FiatAmount::Fixed(parse_u64(value, "fa")?),
            _ => return Err(OrderError::MissingTag("fa")),
        };
        let pm_tag = event
            .tags
            .find_first(&TagKind::from_wire("pm"))
            .ok_or(OrderError::MissingTag("pm"))?;
        let payment_methods: Vec<String> = pm_tag.values().iter().skip(1).cloned().collect();
        if payment_methods.is_empty() {
            return Err(OrderError::MissingTag("pm"));
        }
        let expires_at =
            Timestamp::from_secs(parse_u64(tag_value(event, "expires_at")?, "expires_at")?);
        let bond = match event
            .tags
            .find_first(&TagKind::from_wire("bond"))
            .and_then(Tag::content)
        {
            Some(raw) => Some(parse_u64(raw, "bond")?),
            None => None,
        };
        let expiration = match event
            .tags
            .find_first(&TagKind::from_wire("expiration"))
            .and_then(Tag::content)
        {
            Some(raw) => Some(Timestamp::from_secs(parse_u64(raw, "expiration")?)),
            None => None,
        };
        let optional = |name: &'static str| tag_value(event, name).ok().map(str::to_owned);
        Ok(Self {
            id: tag_value(event, "d")?.to_owned(),
            side: tag_value(event, "k")?.parse()?,
            currency: tag_value(event, "f")?.to_owned(),
            status: tag_value(event, "s")?.parse()?,
            amount_sats: parse_u64(tag_value(event, "amt")?, "amt")?,
            fiat_amount,
            payment_methods,
            premium: tag_value(event, "premium")?.to_owned(),
            network: tag_value(event, "network")?.to_owned(),
            layer: tag_value(event, "layer")?.to_owned(),
            expires_at,
            platform: tag_value(event, "y")?.to_owned(),
            source: optional("source"),
            rating: optional("rating"),
            name: optional("name"),
            geohash: optional("g"),
            bond,
            expiration,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-69 `kind: 38383` peer-to-peer order event.
    #[must_use]
    pub fn p2p_order(order: &P2pOrder) -> Self {
        let simple = |name: &str, value: String| Tag::with(&TagKind::from_wire(name), [value]);
        let mut builder = Self::new(KIND_P2P_ORDER, "")
            .tag(Tag::d(order.id.clone()))
            .tag(simple("k", order.side.as_str().to_owned()))
            .tag(simple("f", order.currency.clone()))
            .tag(simple("s", order.status.as_str().to_owned()))
            .tag(simple("amt", order.amount_sats.to_string()));
        builder = match order.fiat_amount {
            FiatAmount::Fixed(value) => builder.tag(simple("fa", value.to_string())),
            FiatAmount::Range { min, max } => builder.tag(Tag::with(
                &TagKind::from_wire("fa"),
                [min.to_string(), max.to_string()],
            )),
        };
        builder = builder
            .tag(Tag::with(
                &TagKind::from_wire("pm"),
                order.payment_methods.iter().cloned(),
            ))
            .tag(simple("premium", order.premium.clone()))
            .tag(simple("network", order.network.clone()))
            .tag(simple("layer", order.layer.clone()))
            .tag(simple("expires_at", order.expires_at.as_secs().to_string()))
            .tag(simple("y", order.platform.clone()))
            .tag(simple("z", ORDER_DOCUMENT.to_owned()));
        if let Some(source) = &order.source {
            builder = builder.tag(simple("source", source.clone()));
        }
        if let Some(rating) = &order.rating {
            builder = builder.tag(simple("rating", rating.clone()));
        }
        if let Some(name) = &order.name {
            builder = builder.tag(simple("name", name.clone()));
        }
        if let Some(geohash) = &order.geohash {
            builder = builder.tag(simple("g", geohash.clone()));
        }
        if let Some(bond) = order.bond {
            builder = builder.tag(simple("bond", bond.to_string()));
        }
        if let Some(expiration) = order.expiration {
            builder = builder.tag(simple("expiration", expiration.as_secs().to_string()));
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample_order() -> P2pOrder {
        P2pOrder {
            id: "ede61c96-4c13-4519-bf3a-dcf7f1e9d842".to_owned(),
            side: OrderSide::Sell,
            currency: "VES".to_owned(),
            status: OrderStatus::Pending,
            amount_sats: 0,
            fiat_amount: FiatAmount::Fixed(100),
            payment_methods: vec!["face to face".to_owned(), "bank transfer".to_owned()],
            premium: "1".to_owned(),
            network: "mainnet".to_owned(),
            layer: "lightning".to_owned(),
            expires_at: Timestamp::from_secs(1_719_391_096),
            platform: "lnp2pbot".to_owned(),
            source: Some("https://t.me/p2plightning/xxxxxxx".to_owned()),
            rating: None,
            name: Some("Nakamoto".to_owned()),
            geohash: None,
            bond: Some(0),
            expiration: Some(Timestamp::from_secs(1_719_995_896)),
        }
    }

    #[test]
    fn round_trip() {
        let order = sample_order();
        let event = EventBuilder::p2p_order(&order)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = P2pOrder::from_event(&event).unwrap();
        assert_eq!(parsed, order);
    }

    #[test]
    fn range_order_round_trip() {
        let mut order = sample_order();
        order.fiat_amount = FiatAmount::Range { min: 50, max: 500 };
        let event = EventBuilder::p2p_order(&order)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = P2pOrder::from_event(&event).unwrap();
        assert_eq!(parsed.fiat_amount, FiatAmount::Range { min: 50, max: 500 });
    }

    #[test]
    fn side_and_status_wire_forms() {
        assert_eq!("sell".parse::<OrderSide>().unwrap(), OrderSide::Sell);
        assert_eq!("buy".parse::<OrderSide>().unwrap(), OrderSide::Buy);
        assert!("hold".parse::<OrderSide>().is_err());
        assert_eq!(
            "in-progress".parse::<OrderStatus>().unwrap(),
            OrderStatus::InProgress
        );
        assert!("open".parse::<OrderStatus>().is_err());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            P2pOrder::from_event(&event),
            Err(OrderError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_mandatory_tag_is_rejected() {
        // An order with the `z` tag but nothing else must fail on the
        // first missing mandatory tag.
        let event = EventBuilder::new(KIND_P2P_ORDER, "")
            .tag(Tag::with(&TagKind::from_wire("z"), [ORDER_DOCUMENT]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            P2pOrder::from_event(&event),
            Err(OrderError::MissingTag(_))
        ));
    }

    #[test]
    fn wrong_document_type_is_rejected() {
        let event = EventBuilder::new(KIND_P2P_ORDER, "")
            .tag(Tag::with(&TagKind::from_wire("z"), ["invoice"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            P2pOrder::from_event(&event),
            Err(OrderError::InvalidDocument(_))
        ));
    }
}
