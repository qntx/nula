//! Typed NIP-47 method payloads.
//!
//! `nula_core::nips::nip47` models requests and responses with
//! `serde_json::Value` bodies so every method round-trips without a
//! per-method patch. This module layers strongly-typed params/results
//! for the common methods on top, so callers of [`crate::NostrWalletConnect`]
//! get compile-checked Lightning operations. Amounts are millisatoshis
//! (`msat`) and timestamps are Unix seconds, per the spec.

use serde::{Deserialize, Serialize};

/// Direction of a wallet [`Transaction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    /// A received payment.
    Incoming,
    /// A sent payment.
    Outgoing,
}

/// `pay_invoice` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayInvoiceRequest {
    /// BOLT-11 invoice to pay.
    pub invoice: String,
    /// Amount in msat. Required only for zero-amount invoices.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub amount: Option<u64>,
}

impl PayInvoiceRequest {
    /// Pay a fixed-amount invoice.
    #[must_use]
    pub fn new(invoice: impl Into<String>) -> Self {
        Self {
            invoice: invoice.into(),
            amount: None,
        }
    }

    /// Set an explicit amount (msat) for a zero-amount invoice.
    #[must_use]
    pub const fn amount(mut self, msat: u64) -> Self {
        self.amount = Some(msat);
        self
    }
}

/// `pay_invoice` / `pay_keysend` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayInvoiceResponse {
    /// Payment preimage proving the payment settled.
    pub preimage: String,
    /// Routing fees paid, in msat.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fees_paid: Option<u64>,
}

/// `get_balance` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBalanceResponse {
    /// Wallet balance in msat.
    pub balance: u64,
}

/// `get_info` result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GetInfoResponse {
    /// Node alias.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alias: Option<String>,
    /// Node color (hex, no `#`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub color: Option<String>,
    /// Node public key (hex).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pubkey: Option<String>,
    /// Lightning network (`mainnet`, `testnet`, `signet`, `regtest`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<String>,
    /// Current block height.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block_height: Option<u64>,
    /// Current best block hash.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block_hash: Option<String>,
    /// Methods the wallet supports.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Notification types the wallet emits.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub notifications: Option<Vec<String>>,
}

/// `make_invoice` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakeInvoiceRequest {
    /// Invoice amount in msat.
    pub amount: u64,
    /// Invoice description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Invoice description hash (hex).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description_hash: Option<String>,
    /// Expiry in seconds from creation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expiry: Option<u64>,
}

impl MakeInvoiceRequest {
    /// Request an invoice for `amount` msat.
    #[must_use]
    pub const fn new(amount: u64) -> Self {
        Self {
            amount,
            description: None,
            description_hash: None,
            expiry: None,
        }
    }

    /// Attach a human-readable description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the invoice expiry (seconds from creation).
    #[must_use]
    pub const fn expiry(mut self, seconds: u64) -> Self {
        self.expiry = Some(seconds);
        self
    }
}

/// `lookup_invoice` params. Exactly one of `payment_hash` / `invoice`
/// should be set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LookupInvoiceRequest {
    /// Payment hash (hex) to look up.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payment_hash: Option<String>,
    /// BOLT-11 invoice to look up.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub invoice: Option<String>,
}

/// A wallet transaction, returned by `make_invoice`, `lookup_invoice`
/// and `list_transactions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Direction of the transaction.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub direction: Option<TransactionType>,
    /// BOLT-11 invoice.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub invoice: Option<String>,
    /// Invoice description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Invoice description hash.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description_hash: Option<String>,
    /// Payment preimage (present once settled).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preimage: Option<String>,
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Amount in msat.
    pub amount: u64,
    /// Fees paid in msat.
    #[serde(default)]
    pub fees_paid: u64,
    /// Creation time (Unix seconds).
    pub created_at: u64,
    /// Expiry time (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<u64>,
    /// Settlement time (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub settled_at: Option<u64>,
    /// Arbitrary wallet-defined metadata.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metadata: Option<serde_json::Value>,
}

/// `list_transactions` params. All fields optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ListTransactionsRequest {
    /// Lower bound (Unix seconds, inclusive).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub from: Option<u64>,
    /// Upper bound (Unix seconds, inclusive).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub until: Option<u64>,
    /// Maximum number of transactions to return.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub limit: Option<u64>,
    /// Number of transactions to skip.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<u64>,
    /// Restrict to unpaid invoices.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unpaid: Option<bool>,
    /// Restrict to a single direction.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub direction: Option<TransactionType>,
}

/// `list_transactions` result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ListTransactionsResponse {
    /// The matching transactions.
    pub transactions: Vec<Transaction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pay_invoice_request_omits_absent_amount() {
        let req = PayInvoiceRequest::new("lnbc1...");
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"invoice":"lnbc1..."}"#);
        let req = req.amount(21_000);
        assert!(
            serde_json::to_string(&req)
                .unwrap()
                .contains(r#""amount":21000"#)
        );
    }

    #[test]
    fn transaction_type_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&TransactionType::Incoming).unwrap(),
            r#""incoming""#
        );
    }

    #[test]
    fn transaction_round_trips() {
        let json = r#"{"type":"incoming","payment_hash":"ab","amount":1000,"fees_paid":0,"created_at":1700000000}"#;
        let tx: Transaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.direction, Some(TransactionType::Incoming));
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.payment_hash, "ab");
    }
}
