//! [NIP-60] Cashu Wallets — typed event bundles.
//!
//! NIP-60 stores a Cashu ecash wallet's state as a small set of
//! encrypted Nostr events so the wallet follows the user across
//! applications. Every kind in this module encrypts its payload to
//! the **author's own** Nostr key (NIP-44 v2 self-encryption), so a
//! relay only ever sees opaque ciphertext.
//!
//! | Kind   | Role                              | Replaceable |
//! |--------|-----------------------------------|-------------|
//! | 17375  | Wallet (mints + P2PK secret)      | ✓           |
//! | 7375   | Unspent-token bundle              | —           |
//! | 7376   | Spending history entry            | —           |
//! | 7374   | Mint quote-id (optional)          | —           |
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships nothing for NIP-60. We model:
//!
//! 1. [`WalletInfo`] — the kind-17375 bundle (`mints` + optional
//!    P2PK [`SecretKey`]), with a `to_event` / `from_event` round
//!    trip that drives the NIP-44 self-encryption.
//! 2. [`TokenContent`] — kind-7375 unspent-proof bundle with the
//!    full Cashu BDHKE [`CashuProof`] shape (preserving the
//!    spec-mandated uppercase `C` field via serde rename) plus the
//!    optional `del` array used for state-transition rollovers.
//! 3. [`HistoryEntry`] — kind-7376 entry with the typed
//!    [`Direction`] (`in` / `out`) and three classes of `e`
//!    references (`created`, `destroyed`, `redeemed`). The
//!    `redeemed` references stay public per spec §"Spending History
//!    Event".
//! 4. [`QuoteState`] — kind-7374 ephemeral state for in-flight
//!    Lightning mint quotes, carrying the spec-required
//!    `expiration` (NIP-40) and `mint` tags in cleartext.
//!
//! Each bundle carries an `encrypt` and `decrypt` helper so callers
//! can drive the NIP-44 round trip with their own key handling, and
//! a matching [`EventBuilder`] method that wires the typed bundle
//! into a signed event.
//!
//! [NIP-60]: https://github.com/nostr-protocol/nips/blob/master/60.md

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventBuilderError, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagError, TagKind, Tags,
};
use crate::key::{Keys, SecretKey, SecretKeyError};
use crate::nips::nip40::EXPIRATION_TAG;
use crate::nips::nip44;
use crate::types::{Timestamp, Url, UrlError};

/// `kind: 7374` — encrypted mint quote-id.
pub const KIND_CASHU_QUOTE: Kind = Kind::CASHU_QUOTE;
/// `kind: 7375` — unspent token bundle.
pub const KIND_CASHU_TOKEN: Kind = Kind::CASHU_TOKEN;
/// `kind: 7376` — spending history entry.
pub const KIND_CASHU_HISTORY: Kind = Kind::CASHU_HISTORY;
/// `kind: 17375` — replaceable wallet event.
pub const KIND_CASHU_WALLET: Kind = Kind::CASHU_WALLET;

mod tag_names {
    pub(super) const PRIVKEY: &str = "privkey";
    pub(super) const MINT: &str = "mint";
    pub(super) const UNIT: &str = "unit";
    pub(super) const AMOUNT: &str = "amount";
    pub(super) const DIRECTION: &str = "direction";
}

mod history_markers {
    pub(super) const CREATED: &str = "created";
    pub(super) const DESTROYED: &str = "destroyed";
    pub(super) const REDEEMED: &str = "redeemed";
}

/// Errors raised by the NIP-60 typed bundles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip60Error {
    /// Event kind did not match the expected NIP-60 kind.
    #[error("expected kind {expected}, got {got}")]
    WrongKind {
        /// Kind the caller asked for.
        expected: Kind,
        /// Kind the event actually carried.
        got: Kind,
    },
    /// Wallet bundle had zero `mint` rows.
    #[error("NIP-60 wallet must declare at least one mint")]
    NoMints,
    /// History entry decoded without a `direction` row.
    #[error("NIP-60 history entry missing `direction` row")]
    MissingDirection,
    /// History entry decoded without an `amount` row.
    #[error("NIP-60 history entry missing `amount` row")]
    MissingAmount,
    /// History `e` row had no event id.
    #[error("NIP-60 history `e` reference missing event id")]
    MissingHistoryReference,
    /// Quote event had no cleartext `mint` tag.
    #[error("NIP-60 quote event missing `mint` tag")]
    MissingMint,
    /// Quote event had no NIP-40 `expiration` tag.
    #[error("NIP-60 quote event missing NIP-40 `expiration` tag")]
    MissingExpiration,
    /// Quote event's `expiration` value was not a unix timestamp.
    #[error("NIP-60 quote event `expiration` value is not a unix timestamp")]
    MalformedExpiration,
    /// JSON serialisation / deserialisation failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// NIP-44 encrypt / decrypt failed.
    #[error(transparent)]
    Nip44(#[from] nip44::Nip44Error),
    /// A `mint` URL was malformed.
    #[error(transparent)]
    Url(#[from] UrlError),
    /// A `privkey` row was malformed hex.
    #[error(transparent)]
    SecretKey(#[from] SecretKeyError),
    /// An `e` row's event id was malformed hex.
    #[error(transparent)]
    EventId(#[from] EventIdError),
    /// A typed [`Tag`] could not be constructed.
    #[error(transparent)]
    Tag(#[from] TagError),
    /// [`EventBuilder`] signing failed.
    #[error(transparent)]
    Builder(#[from] EventBuilderError),
}

// =============================================================================
// Wallet Event (kind 17375)
// =============================================================================

/// Typed bundle for the replaceable `kind: 17375` wallet event.
///
/// `mints` MUST be non-empty per spec; [`Self::encrypt`] enforces
/// the invariant via [`Nip60Error::NoMints`]. The optional `privkey`
/// is the **wallet's own** P2PK secret (NOT the author's Nostr
/// secret) and is only consumed by NIP-61 nutzaps.
#[derive(Debug, Clone)]
pub struct WalletInfo {
    /// Mint URLs the wallet draws proofs from (≥ 1).
    pub mints: Vec<Url>,
    /// Optional P2PK secret used by NIP-61 nutzaps.
    pub privkey: Option<SecretKey>,
}

impl WalletInfo {
    /// Construct a wallet bundle from a non-empty mint list.
    #[must_use]
    pub const fn new(mints: Vec<Url>) -> Self {
        Self {
            mints,
            privkey: None,
        }
    }

    /// Attach a P2PK secret (used by NIP-61 nutzaps).
    #[must_use]
    pub fn with_privkey(mut self, privkey: SecretKey) -> Self {
        self.privkey = Some(privkey);
        self
    }

    fn to_inner_tags(&self) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = Vec::with_capacity(self.mints.len() + 1);
        if let Some(pk) = &self.privkey {
            out.push(vec![tag_names::PRIVKEY.to_owned(), pk.to_hex()]);
        }
        for mint in &self.mints {
            out.push(vec![tag_names::MINT.to_owned(), mint.as_str().to_owned()]);
        }
        out
    }

    /// NIP-44 self-encrypt the bundle into a wire-ready ciphertext
    /// the kind-17375 event will carry in `.content`.
    ///
    /// # Errors
    ///
    /// - [`Nip60Error::NoMints`] when [`Self::mints`] is empty.
    /// - [`Nip60Error::Json`] when the inner tag array fails to
    ///   serialise.
    /// - [`Nip60Error::Nip44`] when the underlying primitive fails.
    pub fn encrypt(&self, owner: &Keys) -> Result<String, Nip60Error> {
        if self.mints.is_empty() {
            return Err(Nip60Error::NoMints);
        }
        let json = serde_json::to_string(&self.to_inner_tags())?;
        Ok(nip44::encrypt(
            owner.secret_key(),
            owner.public_key(),
            &json,
        )?)
    }

    /// Decrypt a kind-17375 `.content` payload back into a typed
    /// bundle.
    ///
    /// # Errors
    ///
    /// Forwards every NIP-44 / JSON / URL / hex parse error.
    pub fn decrypt(payload: &str, owner: &Keys) -> Result<Self, Nip60Error> {
        let json = nip44::decrypt(owner.secret_key(), owner.public_key(), payload)?;
        let raw: Vec<Vec<String>> = serde_json::from_str(&json)?;
        let mut mints: Vec<Url> = Vec::new();
        let mut privkey: Option<SecretKey> = None;
        for row in raw {
            let Some((head, rest)) = row.split_first() else {
                continue;
            };
            let Some(value) = rest.first() else {
                continue;
            };
            match head.as_str() {
                tag_names::MINT => mints.push(Url::parse(value)?),
                tag_names::PRIVKEY => privkey = Some(SecretKey::parse(value)?),
                _ => {}
            }
        }
        if mints.is_empty() {
            return Err(Nip60Error::NoMints);
        }
        Ok(Self { mints, privkey })
    }

    /// Parse a signed kind-17375 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip60Error::WrongKind`] when the event's kind is
    /// not `17375`; otherwise forwards every error from
    /// [`Self::decrypt`].
    pub fn from_event(event: &Event, owner: &Keys) -> Result<Self, Nip60Error> {
        if event.kind != KIND_CASHU_WALLET {
            return Err(Nip60Error::WrongKind {
                expected: KIND_CASHU_WALLET,
                got: event.kind,
            });
        }
        Self::decrypt(&event.content, owner)
    }
}

// =============================================================================
// Cashu BDHKE proof + Token Event (kind 7375)
// =============================================================================

/// A single Cashu proof in the standard BDHKE wire format.
///
/// The `c` field is serialised as the spec-mandated uppercase `C`
/// per the Cashu mint API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuProof {
    /// Keyset id (16-character hex of the mint's keyset).
    pub id: String,
    /// Amount denomination (mint-specific atomic unit).
    pub amount: u64,
    /// Random secret bound to the proof.
    pub secret: String,
    /// Unblinded signature point (uppercase `C` in the wire form).
    #[serde(rename = "C")]
    pub c: String,
}

/// Inner JSON payload of a kind-7375 token event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenContent {
    /// URL of the mint these proofs belong to.
    pub mint: String,
    /// Base unit (`sat`, `usd`, …); spec default is `sat` when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Unspent proofs.
    pub proofs: Vec<CashuProof>,
    /// Token event ids destroyed by the creation of this token (spec
    /// §"Spending token" rollover).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub del: Vec<String>,
}

impl TokenContent {
    /// Build an unencrypted token bundle.
    #[must_use]
    pub fn new(mint: impl Into<String>, proofs: Vec<CashuProof>) -> Self {
        Self {
            mint: mint.into(),
            unit: None,
            proofs,
            del: Vec::new(),
        }
    }

    /// Set the unit field (`sat` / `usd` / `eur` / …).
    #[must_use]
    pub fn unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Mark token-event ids destroyed by this rollover.
    #[must_use]
    pub fn del(mut self, del: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.del = del.into_iter().map(Into::into).collect();
        self
    }

    /// Total amount across [`Self::proofs`].
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.proofs.iter().map(|p| p.amount).sum()
    }

    /// NIP-44 self-encrypt the bundle.
    ///
    /// # Errors
    ///
    /// Forwarded from JSON serialisation and [`crate::nips::nip44::encrypt`].
    pub fn encrypt(&self, owner: &Keys) -> Result<String, Nip60Error> {
        let json = serde_json::to_string(self)?;
        Ok(nip44::encrypt(
            owner.secret_key(),
            owner.public_key(),
            &json,
        )?)
    }

    /// Decrypt a kind-7375 `.content` payload.
    ///
    /// # Errors
    ///
    /// Forwarded from [`crate::nips::nip44::decrypt`] and JSON parse.
    pub fn decrypt(payload: &str, owner: &Keys) -> Result<Self, Nip60Error> {
        let json = nip44::decrypt(owner.secret_key(), owner.public_key(), payload)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Parse a signed kind-7375 event.
    ///
    /// # Errors
    ///
    /// Returns [`Nip60Error::WrongKind`] when the event's kind is
    /// not `7375`; otherwise forwards every error from
    /// [`Self::decrypt`].
    pub fn from_event(event: &Event, owner: &Keys) -> Result<Self, Nip60Error> {
        if event.kind != KIND_CASHU_TOKEN {
            return Err(Nip60Error::WrongKind {
                expected: KIND_CASHU_TOKEN,
                got: event.kind,
            });
        }
        Self::decrypt(&event.content, owner)
    }
}

// =============================================================================
// Spending History Event (kind 7376)
// =============================================================================

/// Direction column of [`HistoryEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// Funds received (`in`).
    In,
    /// Funds sent (`out`).
    Out,
}

impl Direction {
    /// Wire-form string (`in` / `out`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }

    /// Parse the wire-form string. Returns `None` for unknown values.
    #[must_use]
    pub const fn from_wire(s: &str) -> Option<Self> {
        match s.as_bytes() {
            b"in" => Some(Self::In),
            b"out" => Some(Self::Out),
            _ => None,
        }
    }
}

/// Spending-history entry (kind 7376).
///
/// `created` and `destroyed` references SHOULD stay encrypted with
/// the rest of the entry; `redeemed` references SHOULD be left as
/// public tags so wallets can match nutzap redemptions without
/// decrypting every history entry first (spec §"Spending History
/// Event").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// `in` / `out` direction.
    pub direction: Direction,
    /// Amount the wallet's balance changed by.
    pub amount: u64,
    /// Optional unit (`sat` default).
    pub unit: Option<String>,
    /// Token events created in this transaction (encrypted).
    pub created: Vec<EventId>,
    /// Token events destroyed in this transaction (encrypted).
    pub destroyed: Vec<EventId>,
    /// Nutzap events redeemed in this transaction (public).
    pub redeemed: Vec<EventId>,
}

impl HistoryEntry {
    /// Construct a history entry with empty `e`-tag lists.
    #[must_use]
    pub const fn new(direction: Direction, amount: u64) -> Self {
        Self {
            direction,
            amount,
            unit: None,
            created: Vec::new(),
            destroyed: Vec::new(),
            redeemed: Vec::new(),
        }
    }

    /// Set [`Self::unit`].
    #[must_use]
    pub fn unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Append a `created` token reference.
    #[must_use]
    pub fn created(mut self, id: EventId) -> Self {
        self.created.push(id);
        self
    }

    /// Append a `destroyed` token reference.
    #[must_use]
    pub fn destroyed(mut self, id: EventId) -> Self {
        self.destroyed.push(id);
        self
    }

    /// Append a `redeemed` nutzap reference.
    #[must_use]
    pub fn redeemed(mut self, id: EventId) -> Self {
        self.redeemed.push(id);
        self
    }

    fn encrypted_rows(&self) -> Vec<Vec<String>> {
        let mut rows: Vec<Vec<String>> =
            Vec::with_capacity(3 + self.created.len() + self.destroyed.len());
        rows.push(vec![
            tag_names::DIRECTION.to_owned(),
            self.direction.as_str().to_owned(),
        ]);
        rows.push(vec![tag_names::AMOUNT.to_owned(), self.amount.to_string()]);
        if let Some(unit) = &self.unit {
            rows.push(vec![tag_names::UNIT.to_owned(), unit.clone()]);
        }
        for id in &self.created {
            rows.push(vec![
                "e".to_owned(),
                id.to_hex(),
                String::new(),
                history_markers::CREATED.to_owned(),
            ]);
        }
        for id in &self.destroyed {
            rows.push(vec![
                "e".to_owned(),
                id.to_hex(),
                String::new(),
                history_markers::DESTROYED.to_owned(),
            ]);
        }
        rows
    }

    /// Public-half tags (the `redeemed` references plus nothing else).
    #[must_use]
    pub fn public_tags(&self) -> Vec<Tag> {
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let mut out: Vec<Tag> = Vec::with_capacity(self.redeemed.len());
        for id in &self.redeemed {
            out.push(Tag::with(
                &kind,
                [
                    id.to_hex(),
                    String::new(),
                    history_markers::REDEEMED.to_owned(),
                ],
            ));
        }
        out
    }

    /// NIP-44 self-encrypt the encrypted half of the entry.
    ///
    /// # Errors
    ///
    /// Forwarded from JSON serialisation and [`crate::nips::nip44::encrypt`].
    pub fn encrypt(&self, owner: &Keys) -> Result<String, Nip60Error> {
        let json = serde_json::to_string(&self.encrypted_rows())?;
        Ok(nip44::encrypt(
            owner.secret_key(),
            owner.public_key(),
            &json,
        )?)
    }

    /// Reverse [`Self::encrypt`] + the public `redeemed` tags into a
    /// typed entry.
    ///
    /// # Errors
    ///
    /// Forwards every NIP-44 / JSON / event-id parse error.
    pub fn decrypt(
        encrypted_payload: &str,
        public_tags: &Tags,
        owner: &Keys,
    ) -> Result<Self, Nip60Error> {
        let json = nip44::decrypt(owner.secret_key(), owner.public_key(), encrypted_payload)?;
        let rows: Vec<Vec<String>> = serde_json::from_str(&json)?;

        let mut direction: Option<Direction> = None;
        let mut amount: Option<u64> = None;
        let mut unit: Option<String> = None;
        let mut created: Vec<EventId> = Vec::new();
        let mut destroyed: Vec<EventId> = Vec::new();

        for row in rows {
            ingest_encrypted_row(
                &row,
                &mut direction,
                &mut amount,
                &mut unit,
                &mut created,
                &mut destroyed,
            )?;
        }

        let direction = direction.ok_or(Nip60Error::MissingDirection)?;
        let amount = amount.ok_or(Nip60Error::MissingAmount)?;

        let mut redeemed: Vec<EventId> = Vec::new();
        for tag in public_tags {
            if tag.name() != "e" {
                continue;
            }
            // `values()` returns the *full* row (head + args). The
            // marker therefore lives at index 3, the event id at
            // index 1.
            let values = tag.values();
            let marker = values.get(3).map(String::as_str).unwrap_or_default();
            if marker != history_markers::REDEEMED {
                continue;
            }
            let id_hex = values.get(1).ok_or(Nip60Error::MissingHistoryReference)?;
            redeemed.push(EventId::parse(id_hex)?);
        }

        Ok(Self {
            direction,
            amount,
            unit,
            created,
            destroyed,
            redeemed,
        })
    }

    /// Parse a signed kind-7376 event.
    ///
    /// # Errors
    ///
    /// Returns [`Nip60Error::WrongKind`] when the event's kind is
    /// not `7376`; otherwise forwards every error from
    /// [`Self::decrypt`].
    pub fn from_event(event: &Event, owner: &Keys) -> Result<Self, Nip60Error> {
        if event.kind != KIND_CASHU_HISTORY {
            return Err(Nip60Error::WrongKind {
                expected: KIND_CASHU_HISTORY,
                got: event.kind,
            });
        }
        Self::decrypt(&event.content, &event.tags, owner)
    }
}

// =============================================================================
// Quote Event (kind 7374)
// =============================================================================

/// Optional quote-state event (`kind: 7374`).
///
/// Carries an in-flight Lightning mint quote-id encrypted to the
/// author, plus the cleartext `mint` and [NIP-40] `expiration`
/// columns the spec mandates so other clients can prune the event
/// once the quote has settled.
///
/// [NIP-40]: https://github.com/nostr-protocol/nips/blob/master/40.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteState {
    /// Mint URL the quote was opened against.
    pub mint: Url,
    /// Quote id returned by the mint (encrypted in `.content`).
    pub quote_id: String,
    /// NIP-40 expiration timestamp (spec hard-codes ~2 weeks).
    pub expiration: Timestamp,
}

impl QuoteState {
    /// Construct a quote-state bundle.
    #[must_use]
    pub fn new(mint: Url, quote_id: impl Into<String>, expiration: Timestamp) -> Self {
        Self {
            mint,
            quote_id: quote_id.into(),
            expiration,
        }
    }

    /// NIP-44 self-encrypt the [`Self::quote_id`].
    ///
    /// # Errors
    ///
    /// Forwarded from [`crate::nips::nip44::encrypt`].
    pub fn encrypt(&self, owner: &Keys) -> Result<String, Nip60Error> {
        Ok(nip44::encrypt(
            owner.secret_key(),
            owner.public_key(),
            &self.quote_id,
        )?)
    }

    /// Render the cleartext public tags `[expiration, mint]`.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        vec![
            Tag::with(
                &TagKind::from_wire(EXPIRATION_TAG),
                [self.expiration.as_secs().to_string()],
            ),
            Tag::with(
                &TagKind::custom(tag_names::MINT),
                [self.mint.as_str().to_owned()],
            ),
        ]
    }

    /// Parse a signed kind-7374 event.
    ///
    /// # Errors
    ///
    /// - [`Nip60Error::WrongKind`] when the event's kind is not `7374`.
    /// - [`Nip60Error::MissingExpiration`] when no NIP-40 expiration
    ///   tag is present.
    /// - [`Nip60Error::MissingMint`] when no `mint` tag is present.
    /// - Forwarded from [`crate::nips::nip44::decrypt`] for the
    ///   inner quote-id.
    pub fn from_event(event: &Event, owner: &Keys) -> Result<Self, Nip60Error> {
        if event.kind != KIND_CASHU_QUOTE {
            return Err(Nip60Error::WrongKind {
                expected: KIND_CASHU_QUOTE,
                got: event.kind,
            });
        }
        let mut mint: Option<Url> = None;
        let mut expiration: Option<Timestamp> = None;
        for tag in &event.tags {
            // `values()` includes the tag head; the first argument
            // therefore lives at index 1.
            let Some(value) = tag.values().get(1) else {
                continue;
            };
            match tag.name() {
                tag_names::MINT => mint = Some(Url::parse(value)?),
                EXPIRATION_TAG => {
                    let secs: u64 = value.parse().map_err(|_| Nip60Error::MalformedExpiration)?;
                    expiration = Some(Timestamp::from_secs(secs));
                }
                _ => {}
            }
        }
        let mint = mint.ok_or(Nip60Error::MissingMint)?;
        let expiration = expiration.ok_or(Nip60Error::MissingExpiration)?;
        let quote_id = nip44::decrypt(owner.secret_key(), owner.public_key(), &event.content)?;
        Ok(Self {
            mint,
            quote_id,
            expiration,
        })
    }
}

// =============================================================================
// EventBuilder integration
// =============================================================================

impl EventBuilder {
    /// Author a NIP-60 wallet event (`kind: 17375`) from a typed
    /// [`WalletInfo`].
    ///
    /// The bundle is NIP-44 self-encrypted to `owner` before being
    /// stamped on the new event's `.content`.
    ///
    /// # Errors
    ///
    /// Forwards every error from [`WalletInfo::encrypt`].
    pub fn cashu_wallet(info: &WalletInfo, owner: &Keys) -> Result<Self, Nip60Error> {
        let payload = info.encrypt(owner)?;
        Ok(Self::new(KIND_CASHU_WALLET, payload))
    }

    /// Author a NIP-60 token event (`kind: 7375`) from a typed
    /// [`TokenContent`].
    ///
    /// # Errors
    ///
    /// Forwards every error from [`TokenContent::encrypt`].
    pub fn cashu_token(token: &TokenContent, owner: &Keys) -> Result<Self, Nip60Error> {
        let payload = token.encrypt(owner)?;
        Ok(Self::new(KIND_CASHU_TOKEN, payload))
    }

    /// Author a NIP-60 spending-history event (`kind: 7376`) from a
    /// typed [`HistoryEntry`].
    ///
    /// The encrypted half — the direction, amount, unit, and the
    /// created plus destroyed references — goes into `.content`;
    /// the public `redeemed` references are stamped as cleartext
    /// `e` tags so nutzap recipients can match them without
    /// decryption.
    ///
    /// # Errors
    ///
    /// Forwards every error from [`HistoryEntry::encrypt`].
    pub fn cashu_history(entry: &HistoryEntry, owner: &Keys) -> Result<Self, Nip60Error> {
        let payload = entry.encrypt(owner)?;
        let mut builder = Self::new(KIND_CASHU_HISTORY, payload);
        for tag in entry.public_tags() {
            builder = builder.tag(tag);
        }
        Ok(builder)
    }

    /// Author a NIP-60 quote-state event (`kind: 7374`) from a typed
    /// [`QuoteState`].
    ///
    /// The quote id is encrypted into `.content`; the `mint` and
    /// NIP-40 `expiration` tags are stamped in cleartext per spec.
    ///
    /// # Errors
    ///
    /// Forwards every error from [`QuoteState::encrypt`].
    pub fn cashu_quote(quote: &QuoteState, owner: &Keys) -> Result<Self, Nip60Error> {
        let payload = quote.encrypt(owner)?;
        let mut builder = Self::new(KIND_CASHU_QUOTE, payload);
        for tag in quote.to_tags() {
            builder = builder.tag(tag);
        }
        Ok(builder)
    }
}

/// Internal dispatch routine for [`HistoryEntry::decrypt`].
///
/// Pulled out into a freestanding fn so the calling loop body stays
/// flat; clippy's `excessive_nesting` lint flagged the inlined
/// version as too deep.
fn ingest_encrypted_row(
    row: &[String],
    direction: &mut Option<Direction>,
    amount: &mut Option<u64>,
    unit: &mut Option<String>,
    created: &mut Vec<EventId>,
    destroyed: &mut Vec<EventId>,
) -> Result<(), Nip60Error> {
    let Some((head, rest)) = row.split_first() else {
        return Ok(());
    };
    match head.as_str() {
        tag_names::DIRECTION => {
            if let Some(v) = rest.first() {
                *direction = Direction::from_wire(v);
            }
        }
        tag_names::AMOUNT => {
            if let Some(v) = rest.first() {
                *amount = v.parse().ok();
            }
        }
        tag_names::UNIT => {
            *unit = rest.first().cloned();
        }
        "e" => {
            let id_hex = rest.first().ok_or(Nip60Error::MissingHistoryReference)?;
            let id = EventId::parse(id_hex)?;
            let marker = rest.get(2).map(String::as_str).unwrap_or_default();
            match marker {
                history_markers::CREATED => created.push(id),
                history_markers::DESTROYED => destroyed.push(id),
                // `redeemed` markers are expected on public tags
                // rather than the encrypted body; tolerate their
                // presence here for forward compatibility with
                // clients that chose to encrypt them anyway.
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    fn mint() -> Url {
        Url::parse("https://stablenut.umint.cash").unwrap()
    }

    fn second_mint() -> Url {
        Url::parse("https://mint.example/").unwrap()
    }

    fn fixture_proof(amount: u64, secret: &str) -> CashuProof {
        CashuProof {
            id: "005c2502034d4f12".to_owned(),
            amount,
            secret: secret.to_owned(),
            c: "0241d98a8197ef238a192d47edf191a9de78b657308937b4f7dd0aa53beae72c46"
                .to_owned(),
        }
    }

    #[test]
    fn wallet_round_trips_through_encrypt_decrypt() {
        let owner = keys();
        let info = WalletInfo::new(vec![mint(), second_mint()])
            .with_privkey(other_keys().secret_key().clone());
        let payload = info.encrypt(&owner).unwrap();
        let recovered = WalletInfo::decrypt(&payload, &owner).unwrap();
        assert_eq!(recovered.mints, info.mints);
        assert_eq!(
            recovered.privkey.as_ref().map(SecretKey::to_hex),
            info.privkey.as_ref().map(SecretKey::to_hex),
        );
    }

    #[test]
    fn wallet_encrypt_rejects_empty_mints() {
        let owner = keys();
        let info = WalletInfo::new(Vec::new());
        assert!(matches!(info.encrypt(&owner), Err(Nip60Error::NoMints)));
    }

    #[test]
    fn wallet_from_event_rejects_wrong_kind() {
        let owner = keys();
        let info = WalletInfo::new(vec![mint()]);
        let payload = info.encrypt(&owner).unwrap();
        let event = EventBuilder::new(Kind::TEXT_NOTE, payload)
            .sign_with_keys(&owner)
            .unwrap();
        assert!(matches!(
            WalletInfo::from_event(&event, &owner),
            Err(Nip60Error::WrongKind { .. })
        ));
    }

    #[test]
    fn wallet_event_round_trips() {
        let owner = keys();
        let info = WalletInfo::new(vec![mint()]).with_privkey(other_keys().secret_key().clone());
        let event = EventBuilder::cashu_wallet(&info, &owner)
            .unwrap()
            .sign_with_keys(&owner)
            .unwrap();
        assert_eq!(event.kind, KIND_CASHU_WALLET);
        let recovered = WalletInfo::from_event(&event, &owner).unwrap();
        assert_eq!(recovered.mints, info.mints);
    }

    #[test]
    fn token_round_trips_through_encrypt_decrypt() {
        let owner = keys();
        let token = TokenContent::new(
            mint().as_str(),
            vec![
                fixture_proof(1, "z+zyxAVLRqN9lEjxuNPSyRJzEstbl69Jc1vtimvtkPg="),
                fixture_proof(2, "z+zyxAVLRqN9lEjxuNPSyRJzEstbl69Jc1vtimvtkPa="),
            ],
        )
        .unit("sat")
        .del(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
        let payload = token.encrypt(&owner).unwrap();
        let recovered = TokenContent::decrypt(&payload, &owner).unwrap();
        assert_eq!(recovered, token);
        assert_eq!(recovered.amount(), 3);
    }

    #[test]
    fn token_proof_serializes_uppercase_c() {
        let proof = fixture_proof(8, "secret");
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"C\":"), "wire form must use uppercase C");
        assert!(!json.contains("\"c\":"), "lowercase c MUST NOT appear");
    }

    #[test]
    fn token_event_round_trips_via_event_builder() {
        let owner = keys();
        let token = TokenContent::new(mint().as_str(), vec![fixture_proof(4, "abc")]);
        let event = EventBuilder::cashu_token(&token, &owner)
            .unwrap()
            .sign_with_keys(&owner)
            .unwrap();
        assert_eq!(event.kind, KIND_CASHU_TOKEN);
        let recovered = TokenContent::from_event(&event, &owner).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn token_from_event_rejects_wrong_kind() {
        let owner = keys();
        let token = TokenContent::new(mint().as_str(), vec![fixture_proof(1, "x")]);
        let payload = token.encrypt(&owner).unwrap();
        let event = EventBuilder::new(Kind::TEXT_NOTE, payload)
            .sign_with_keys(&owner)
            .unwrap();
        assert!(matches!(
            TokenContent::from_event(&event, &owner),
            Err(Nip60Error::WrongKind { .. })
        ));
    }

    #[test]
    fn direction_round_trips_through_wire_form() {
        assert_eq!(Direction::In.as_str(), "in");
        assert_eq!(Direction::Out.as_str(), "out");
        assert_eq!(Direction::from_wire("in"), Some(Direction::In));
        assert_eq!(Direction::from_wire("out"), Some(Direction::Out));
        assert_eq!(Direction::from_wire("INVALID"), None);
    }

    #[test]
    fn history_round_trips_with_public_redeemed_tag() {
        let owner = keys();
        let created_id = EventId::from_byte_array([0xaa; 32]);
        let destroyed_id = EventId::from_byte_array([0xbb; 32]);
        let redeemed_id = EventId::from_byte_array([0xcc; 32]);
        let entry = HistoryEntry::new(Direction::Out, 4)
            .unit("sat")
            .created(created_id)
            .destroyed(destroyed_id)
            .redeemed(redeemed_id);

        let event = EventBuilder::cashu_history(&entry, &owner)
            .unwrap()
            .sign_with_keys(&owner)
            .unwrap();
        assert_eq!(event.kind, KIND_CASHU_HISTORY);

        // The `redeemed` tag MUST stay in the cleartext public tag
        // set per spec §"Spending History Event". `values()` returns
        // the full row including the head, so the marker lives at
        // index 3.
        let public_redeemed_count = event
            .tags
            .iter()
            .filter(|t| t.name() == "e")
            .filter(|t| t.values().get(3).map(String::as_str) == Some("redeemed"))
            .count();
        assert_eq!(public_redeemed_count, 1);

        let recovered = HistoryEntry::from_event(&event, &owner).unwrap();
        assert_eq!(recovered, entry);
    }

    #[test]
    fn history_from_event_rejects_wrong_kind() {
        let owner = keys();
        let entry = HistoryEntry::new(Direction::In, 1);
        let payload = entry.encrypt(&owner).unwrap();
        let event = EventBuilder::new(Kind::TEXT_NOTE, payload)
            .sign_with_keys(&owner)
            .unwrap();
        assert!(matches!(
            HistoryEntry::from_event(&event, &owner),
            Err(Nip60Error::WrongKind { .. })
        ));
    }

    #[test]
    fn quote_round_trips_through_event_builder() {
        let owner = keys();
        let quote = QuoteState::new(mint(), "abc-quote-id", Timestamp::from_secs(1_700_000_000));

        let event = EventBuilder::cashu_quote(&quote, &owner)
            .unwrap()
            .sign_with_keys(&owner)
            .unwrap();
        assert_eq!(event.kind, KIND_CASHU_QUOTE);

        // Cleartext envelope must carry both the spec-required tags.
        let mint_tag = event.tags.iter().any(|t| t.name() == "mint");
        let expiration_tag = event.tags.iter().any(|t| t.name() == "expiration");
        assert!(mint_tag);
        assert!(expiration_tag);

        let recovered = QuoteState::from_event(&event, &owner).unwrap();
        assert_eq!(recovered, quote);
    }

    #[test]
    fn quote_from_event_requires_mint_and_expiration() {
        let owner = keys();
        let payload = nip44::encrypt(owner.secret_key(), owner.public_key(), "quote").unwrap();
        let no_tags = EventBuilder::new(KIND_CASHU_QUOTE, payload.clone())
            .sign_with_keys(&owner)
            .unwrap();
        assert!(matches!(
            QuoteState::from_event(&no_tags, &owner),
            Err(Nip60Error::MissingMint),
        ));

        let only_mint = EventBuilder::new(KIND_CASHU_QUOTE, payload)
            .tag(Tag::with(
                &TagKind::custom(tag_names::MINT),
                [mint().as_str().to_owned()],
            ))
            .sign_with_keys(&owner)
            .unwrap();
        assert!(matches!(
            QuoteState::from_event(&only_mint, &owner),
            Err(Nip60Error::MissingExpiration),
        ));
    }
}
