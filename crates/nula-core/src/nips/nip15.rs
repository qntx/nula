//! [NIP-15] Nostr Marketplace.
//!
//! NIP-15 lets a `merchant` publish *stalls* (`kind: 30017`), *products*
//! (`kind: 30018`) and *auctions* (`kind: 30020`) as addressable events whose
//! `content` carries a JSON payload, and exchange *orders* / *payment
//! requests* / *payment verifications* with a `customer` over encrypted direct
//! messages (NIP-04 / NIP-17).
//!
//! # Relationship to upstream `rust-nostr`
//!
//! This module is a superset of the upstream implementation and corrects two
//! spec deviations:
//!
//! - **Product `d` tag.** NIP-15 addresses a product by its *own* id, so the
//!   `kind: 30018` event carries `["d", <product id>]`. Upstream emits the
//!   *stall* id here; this module uses the product id per the spec.
//! - **Order item field.** The spec names the order line item field
//!   `product_id`; this module matches that (upstream uses `id`).
//!
//! It also adds [`AuctionData`] (typed `kind: 30020` support, absent
//! upstream) and `from_event` parsers for every addressable type.
//!
//! [NIP-15]: https://github.com/nostr-protocol/nips/blob/master/15.md
//!
//! # Example
//!
//! ```
//! use nula_core::nips::nip15::{ProductData, StallData};
//! use nula_core::Keys;
//!
//! let keys = Keys::generate().unwrap();
//!
//! let stall = StallData::new("stall-1", "My Stall", "USD");
//! let stall_event = stall.to_event_builder().unwrap().sign_with_keys(&keys).unwrap();
//! assert_eq!(StallData::from_event(&stall_event).unwrap().id, "stall-1");
//!
//! let product = ProductData::new("prod-1", "stall-1", "Widget", "USD").price(9.99);
//! let product_event = product.to_event_builder().unwrap().sign_with_keys(&keys).unwrap();
//! // Addressable by the *product* id, per NIP-15.
//! assert_eq!(product_event.tags.identifier(), Some("prod-1"));
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, Tag};
use crate::key::PublicKey;
use crate::util::json::JsonUtil;

/// A shipping zone offered by a stall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShippingMethod {
    /// Merchant-defined shipping zone id (echoed back in customer orders).
    pub id: String,
    /// Human-readable name of the shipping zone.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    /// Base cost for this zone, in the stall's currency.
    pub cost: f64,
    /// Regions covered by this zone.
    #[serde(default)]
    pub regions: Vec<String>,
}

impl ShippingMethod {
    /// Create a shipping method with the given id and base cost.
    #[must_use]
    pub fn new<S>(id: S, cost: f64) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            name: None,
            cost,
            regions: Vec::new(),
        }
    }

    /// Set the display name.
    #[must_use]
    pub fn name<S>(mut self, name: S) -> Self
    where
        S: Into<String>,
    {
        self.name = Some(name.into());
        self
    }

    /// Set the covered regions.
    #[must_use]
    pub fn regions(mut self, regions: Vec<String>) -> Self {
        self.regions = regions;
        self
    }

    /// Project to the per-product [`ShippingCost`] that references this zone.
    #[must_use]
    pub fn to_shipping_cost(&self) -> ShippingCost {
        ShippingCost {
            id: self.id.clone(),
            cost: self.cost,
        }
    }
}

/// A per-product surcharge for a given shipping zone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShippingCost {
    /// Id of the [`ShippingMethod`] this surcharge applies to.
    pub id: String,
    /// Extra cost added on top of the zone's base cost.
    pub cost: f64,
}

/// Stall payload (`kind: 30017` content).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StallData {
    /// Merchant-generated stall id (also the `d` tag).
    pub id: String,
    /// Stall name.
    pub name: String,
    /// Optional stall description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Currency used across the stall (ISO 4217 or `"BTC"` / `"SAT"`).
    pub currency: String,
    /// Shipping zones offered by the stall.
    #[serde(default)]
    pub shipping: Vec<ShippingMethod>,
}

impl StallData {
    /// Create a stall with the mandatory fields.
    #[must_use]
    pub fn new<S>(id: S, name: S, currency: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            currency: currency.into(),
            shipping: Vec::new(),
        }
    }

    /// Set the stall description.
    #[must_use]
    pub fn description<S>(mut self, description: S) -> Self
    where
        S: Into<String>,
    {
        self.description = Some(description.into());
        self
    }

    /// Set the shipping zones.
    #[must_use]
    pub fn shipping(mut self, shipping: Vec<ShippingMethod>) -> Self {
        self.shipping = shipping;
        self
    }

    /// Build the `kind: 30017` [`EventBuilder`].
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if the payload cannot be serialized
    /// (e.g. a shipping cost is `NaN`).
    pub fn to_event_builder(&self) -> Result<EventBuilder, serde_json::Error> {
        let content = self.try_to_json()?;
        Ok(EventBuilder::new(Kind::MARKETPLACE_STALL, content).tag(Tag::d(self.id.clone())))
    }

    /// Parse a [`StallData`] from a `kind: 30017` [`Event`].
    ///
    /// # Errors
    ///
    /// Returns [`MarketplaceError`] if the kind is wrong or the JSON content
    /// is malformed.
    pub fn from_event(event: &Event) -> Result<Self, MarketplaceError> {
        expect_kind(event, Kind::MARKETPLACE_STALL)?;
        Ok(Self::from_json(&event.content)?)
    }
}

/// Product payload (`kind: 30018` content).
///
/// `categories` is carried in `t` tags rather than the JSON body, so it is
/// skipped during serialization and re-populated by [`ProductData::from_event`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductData {
    /// Merchant-generated product id (also the `d` tag).
    pub id: String,
    /// Id of the stall this product belongs to.
    pub stall_id: String,
    /// Product name.
    pub name: String,
    /// Optional product description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Optional image URLs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub images: Option<Vec<String>>,
    /// Currency (matches the stall's currency).
    pub currency: String,
    /// Unit price.
    pub price: f64,
    /// Available quantity; `None` means unlimited (digital goods, services).
    pub quantity: Option<u64>,
    /// Optional `[name, value]` specification pairs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub specs: Option<Vec<Vec<String>>>,
    /// Per-zone shipping surcharges.
    #[serde(default)]
    pub shipping: Vec<ShippingCost>,
    /// Category hashtags (carried in `t` tags, not the JSON body).
    #[serde(skip_serializing, default)]
    pub categories: Option<Vec<String>>,
}

impl ProductData {
    /// Create a product with the mandatory fields. Quantity defaults to `1`.
    #[must_use]
    pub fn new<S>(id: S, stall_id: S, name: S, currency: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            stall_id: stall_id.into(),
            name: name.into(),
            description: None,
            images: None,
            currency: currency.into(),
            price: 0.0,
            quantity: Some(1),
            specs: None,
            shipping: Vec::new(),
            categories: None,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn description<S>(mut self, description: S) -> Self
    where
        S: Into<String>,
    {
        self.description = Some(description.into());
        self
    }

    /// Set the image URLs.
    #[must_use]
    pub fn images(mut self, images: Vec<String>) -> Self {
        self.images = Some(images);
        self
    }

    /// Set the unit price.
    #[must_use]
    pub const fn price(mut self, price: f64) -> Self {
        self.price = price;
        self
    }

    /// Set the available quantity (`None` = unlimited).
    #[must_use]
    pub const fn quantity(mut self, quantity: Option<u64>) -> Self {
        self.quantity = quantity;
        self
    }

    /// Set the `[name, value]` specification pairs. Pairs that are not exactly
    /// two elements are dropped.
    #[must_use]
    pub fn specs(mut self, specs: Vec<Vec<String>>) -> Self {
        let valid: Vec<Vec<String>> = specs.into_iter().filter(|s| s.len() == 2).collect();
        self.specs = Some(valid);
        self
    }

    /// Set the per-zone shipping surcharges.
    #[must_use]
    pub fn shipping(mut self, shipping: Vec<ShippingCost>) -> Self {
        self.shipping = shipping;
        self
    }

    /// Set the category hashtags.
    #[must_use]
    pub fn categories(mut self, categories: Vec<String>) -> Self {
        self.categories = Some(categories);
        self
    }

    /// Build the `kind: 30018` [`EventBuilder`].
    ///
    /// The event is addressable by the **product** id (`["d", <id>]`) and
    /// carries one `t` tag per category.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if the payload cannot be serialized.
    pub fn to_event_builder(&self) -> Result<EventBuilder, serde_json::Error> {
        let content = self.try_to_json()?;
        let mut builder =
            EventBuilder::new(Kind::MARKETPLACE_PRODUCT, content).tag(Tag::d(self.id.clone()));
        if let Some(categories) = &self.categories {
            for category in categories {
                builder = builder.tag(Tag::t(category));
            }
        }
        Ok(builder)
    }

    /// Parse a [`ProductData`] from a `kind: 30018` [`Event`].
    ///
    /// Categories are read from the event's `t` tags (the JSON body never
    /// carries them).
    ///
    /// # Errors
    ///
    /// Returns [`MarketplaceError`] if the kind is wrong or the JSON content
    /// is malformed.
    pub fn from_event(event: &Event) -> Result<Self, MarketplaceError> {
        expect_kind(event, Kind::MARKETPLACE_PRODUCT)?;
        let mut product = Self::from_json(&event.content)?;
        product.categories = collect_hashtags(event);
        Ok(product)
    }
}

/// Auction payload (`kind: 30020` content).
///
/// Auctions are structurally similar to fixed-price products but priced by
/// bidding. Typed support for them is absent from upstream `rust-nostr`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuctionData {
    /// Merchant-generated auction id (also the `d` tag).
    pub id: String,
    /// Id of the stall this auction belongs to.
    pub stall_id: String,
    /// Auction name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Optional image URLs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub images: Option<Vec<String>>,
    /// Starting bid, in the stall's currency.
    pub starting_bid: u64,
    /// Optional Unix start date; omit to schedule later.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub start_date: Option<u64>,
    /// Auction duration in seconds after `start_date`.
    pub duration: u64,
    /// Optional `[name, value]` specification pairs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub specs: Option<Vec<Vec<String>>>,
    /// Per-zone shipping surcharges.
    #[serde(default)]
    pub shipping: Vec<ShippingCost>,
}

impl AuctionData {
    /// Create an auction with the mandatory fields.
    #[must_use]
    pub fn new<S>(id: S, stall_id: S, name: S, starting_bid: u64, duration: u64) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            stall_id: stall_id.into(),
            name: name.into(),
            description: None,
            images: None,
            starting_bid,
            start_date: None,
            duration,
            specs: None,
            shipping: Vec::new(),
        }
    }

    /// Build the `kind: 30020` [`EventBuilder`], addressable by the auction id.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if the payload cannot be serialized.
    pub fn to_event_builder(&self) -> Result<EventBuilder, serde_json::Error> {
        let content = self.try_to_json()?;
        Ok(EventBuilder::new(Kind::MARKETPLACE_AUCTION, content).tag(Tag::d(self.id.clone())))
    }

    /// Parse an [`AuctionData`] from a `kind: 30020` [`Event`].
    ///
    /// # Errors
    ///
    /// Returns [`MarketplaceError`] if the kind is wrong or the JSON content
    /// is malformed.
    pub fn from_event(event: &Event) -> Result<Self, MarketplaceError> {
        expect_kind(event, Kind::MARKETPLACE_AUCTION)?;
        Ok(Self::from_json(&event.content)?)
    }
}

/// A single line item inside a [`CustomerOrder`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerOrderItem {
    /// Id of the ordered product.
    pub product_id: String,
    /// Quantity ordered.
    pub quantity: u64,
}

/// A customer's contact details attached to an order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerContact {
    /// Customer's Nostr public key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nostr: Option<PublicKey>,
    /// Customer's phone number.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phone: Option<String>,
    /// Customer's email address.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
}

/// Customer order message (`type: 0`), sent to the merchant over an encrypted DM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerOrder {
    /// Customer-generated order id.
    pub id: String,
    /// Message discriminant; always `0`.
    #[serde(rename = "type")]
    pub message_type: u8,
    /// Customer name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    /// Shipping address (for physical goods).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub address: Option<String>,
    /// Free-form message to the merchant.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// Customer contact details.
    pub contact: CustomerContact,
    /// Ordered items.
    pub items: Vec<CustomerOrderItem>,
    /// Selected shipping zone id.
    pub shipping_id: String,
}

impl CustomerOrder {
    /// Create an order with the mandatory fields and `type: 0`.
    #[must_use]
    pub fn new<S>(
        id: S,
        contact: CustomerContact,
        items: Vec<CustomerOrderItem>,
        shipping_id: S,
    ) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            message_type: 0,
            name: None,
            address: None,
            message: None,
            contact,
            items,
            shipping_id: shipping_id.into(),
        }
    }
}

/// A single payment option in a [`MerchantPaymentRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentOption {
    /// Payment type (`url`, `btc`, `ln`, `lnurl`, …).
    #[serde(rename = "type")]
    pub option_type: String,
    /// Payment link (URL, lightning invoice, on-chain address, …).
    pub link: String,
}

/// Merchant payment request message (`type: 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerchantPaymentRequest {
    /// Order id this request answers.
    pub id: String,
    /// Message discriminant; always `1`.
    #[serde(rename = "type")]
    pub message_type: u8,
    /// Optional message to the customer.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// Available payment options.
    pub payment_options: Vec<PaymentOption>,
}

impl MerchantPaymentRequest {
    /// Create a payment request with `type: 1`.
    #[must_use]
    pub fn new<S>(id: S, payment_options: Vec<PaymentOption>) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            message_type: 1,
            message: None,
            payment_options,
        }
    }
}

/// Merchant payment/shipping verification message (`type: 2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerchantVerifyPayment {
    /// Order id this verification answers.
    pub id: String,
    /// Message discriminant; always `2`.
    #[serde(rename = "type")]
    pub message_type: u8,
    /// Optional message to the customer.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// Whether payment was received.
    pub paid: bool,
    /// Whether the order shipped.
    pub shipped: bool,
}

impl MerchantVerifyPayment {
    /// Create a verification message with `type: 2`.
    #[must_use]
    pub fn new<S>(id: S, paid: bool, shipped: bool) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: id.into(),
            message_type: 2,
            message: None,
            paid,
            shipped,
        }
    }
}

/// Errors raised when parsing a marketplace event.
#[derive(Debug, Error)]
#[non_exhaustive]
#[allow(
    variant_size_differences,
    reason = "the serde_json::Error source is already boxed to an 8-byte pointer (the smallest sound representation), but still trips the heuristic against the small UnexpectedKind variant — mirrors nip18::RepostError"
)]
pub enum MarketplaceError {
    /// The event's kind did not match the expected marketplace kind.
    #[error("expected kind {expected}, got {got}")]
    UnexpectedKind {
        /// The expected marketplace kind.
        expected: u16,
        /// What the event actually advertised.
        got: u16,
    },
    /// The event `content` was not valid JSON for the target payload.
    ///
    /// The [`serde_json::Error`] is boxed to keep the enum small (it is
    /// markedly larger than the other variants).
    #[error("invalid marketplace JSON content: {0}")]
    InvalidContent(#[source] Box<serde_json::Error>),
}

impl From<serde_json::Error> for MarketplaceError {
    fn from(value: serde_json::Error) -> Self {
        Self::InvalidContent(Box::new(value))
    }
}

fn expect_kind(event: &Event, expected: Kind) -> Result<(), MarketplaceError> {
    if event.kind == expected {
        Ok(())
    } else {
        Err(MarketplaceError::UnexpectedKind {
            expected: expected.as_u16(),
            got: event.kind.as_u16(),
        })
    }
}

fn collect_hashtags(event: &Event) -> Option<Vec<String>> {
    let hashtags: Vec<String> = event
        .tags
        .find_letter(Alphabet::T)
        .filter_map(Tag::content)
        .map(str::to_owned)
        .collect();
    if hashtags.is_empty() {
        None
    } else {
        Some(hashtags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn stall_json_is_byte_compatible_with_upstream() {
        let stall = StallData::new("123", "Test Stall", "USD")
            .description("Test Description")
            .shipping(vec![ShippingMethod::new("123", 5.0).name("default")]);
        assert_eq!(
            stall.try_to_json().unwrap(),
            r#"{"id":"123","name":"Test Stall","description":"Test Description","currency":"USD","shipping":[{"id":"123","name":"default","cost":5.0,"regions":[]}]}"#
        );
    }

    #[test]
    fn stall_round_trip_through_event() {
        let stall = StallData::new("s1", "Stall", "USD").shipping(vec![
            ShippingMethod::new("z1", 2.5).regions(vec!["EU".to_owned()]),
        ]);
        let event = stall
            .to_event_builder()
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, Kind::MARKETPLACE_STALL);
        assert_eq!(event.tags.identifier(), Some("s1"));
        assert_eq!(StallData::from_event(&event).unwrap(), stall);
    }

    #[test]
    fn product_is_addressable_by_product_id_not_stall_id() {
        // Regression against the upstream `stall_id` bug: NIP-15 addresses a
        // product by its own id.
        let product = ProductData::new("prod-9", "stall-1", "Widget", "USD").price(9.99);
        let event = product
            .to_event_builder()
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, Kind::MARKETPLACE_PRODUCT);
        assert_eq!(event.tags.identifier(), Some("prod-9"));
    }

    #[test]
    fn product_round_trip_with_categories_from_tags() {
        let product = ProductData::new("p1", "s1", "Thing", "SAT")
            .price(1000.0)
            .quantity(Some(3))
            .images(vec!["https://img.example/x.png".to_owned()])
            .specs(vec![vec!["size".to_owned(), "M".to_owned()]])
            .categories(vec!["electronics".to_owned(), "phones".to_owned()]);
        let event = product
            .to_event_builder()
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();

        // The content body must NOT carry categories.
        assert!(!event.content.contains("categories"));
        // Categories come back from the `t` tags.
        let parsed = ProductData::from_event(&event).unwrap();
        assert_eq!(parsed, product);
    }

    #[test]
    fn product_unlimited_quantity_serializes_as_null() {
        let product = ProductData::new("p1", "s1", "Service", "USD").quantity(None);
        assert!(
            product
                .try_to_json()
                .unwrap()
                .contains(r#""quantity":null"#)
        );
    }

    #[test]
    fn auction_round_trip_through_event() {
        let auction = AuctionData::new("a1", "s1", "Rare Item", 100, 86_400);
        let event = auction
            .to_event_builder()
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, Kind::MARKETPLACE_AUCTION);
        assert_eq!(event.tags.identifier(), Some("a1"));
        assert_eq!(AuctionData::from_event(&event).unwrap(), auction);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            StallData::from_event(&event).unwrap_err(),
            MarketplaceError::UnexpectedKind {
                expected: 30_017,
                got: 1
            }
        ));
    }

    #[test]
    fn order_uses_product_id_field() {
        let order = CustomerOrder::new(
            "o1",
            CustomerContact {
                nostr: None,
                phone: None,
                email: Some("a@b.c".to_owned()),
            },
            vec![CustomerOrderItem {
                product_id: "p1".to_owned(),
                quantity: 2,
            }],
            "z1",
        );
        let json = order.try_to_json().unwrap();
        assert!(json.contains(r#""type":0"#));
        assert!(json.contains(r#""product_id":"p1""#));
        assert_eq!(CustomerOrder::from_json(&json).unwrap(), order);
    }

    #[test]
    fn payment_messages_carry_type_discriminants() {
        let req = MerchantPaymentRequest::new(
            "o1",
            vec![PaymentOption {
                option_type: "ln".to_owned(),
                link: "lnbc...".to_owned(),
            }],
        );
        assert!(req.try_to_json().unwrap().contains(r#""type":1"#));

        let verify = MerchantVerifyPayment::new("o1", true, false);
        assert!(verify.try_to_json().unwrap().contains(r#""type":2"#));
    }
}
