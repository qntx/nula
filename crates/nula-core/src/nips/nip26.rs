//! [NIP-26] Delegated Event Signing.
//!
//! NIP-26 lets a *delegator* keypair authorise a *delegatee* keypair to
//! publish events on its behalf, scoped by a `kind=` / `created_at<` /
//! `created_at>` condition string. The delegation lives entirely
//! inside one extra `delegation` tag on each event the delegatee
//! publishes; the event itself is still signed by the delegatee's
//! key, and clients that want to honour the delegation verify the
//! token against the delegator's pubkey.
//!
//! ```jsonc
//! [
//!   "delegation",
//!   "<delegator-pubkey-hex>",
//!   "<conditions-query-string>",
//!   "<delegation-token-hex>"
//! ]
//! ```
//!
//! The token is a 64-byte BIP-340 Schnorr signature of `SHA-256` of
//! the ASCII string
//! `nostr:delegation:<delegatee-pubkey-hex>:<conditions>`.
//!
//! # Status
//!
//! NIP-26 carries an `unrecommended` warning in the spec: relays and
//! clients have largely moved on to NIP-46 remote signers as the
//! preferred way to keep the root key cold. We still ship a complete
//! implementation so existing on-relay corpora remain decodable and
//! so callers can migrate off NIP-26 at their own pace.
//!
//! # Authoring & verifying
//!
//! ```
//! use nula_core::Keys;
//! use nula_core::event::Kind;
//! use nula_core::nips::nip26::{Conditions, sign_delegation, verify_delegation};
//!
//! let delegator = Keys::generate().unwrap();
//! let delegatee = Keys::generate().unwrap();
//! let conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);
//!
//! let token = sign_delegation(&delegator, delegatee.public_key(), &conditions);
//! assert!(verify_delegation(
//!     delegator.public_key(),
//!     delegatee.public_key(),
//!     &conditions,
//!     &token,
//! ));
//! ```
//!
//! [NIP-26]: https://github.com/nostr-protocol/nips/blob/master/26.md

use core::fmt;

use secp256k1::schnorr::Signature;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::event::{Event, Kind, Tag, TagKind, Tags};
use crate::key::{Keys, PublicKey};
use crate::types::Timestamp;

/// Tag head for the delegation tag.
pub const DELEGATION_TAG_KEY: &str = "delegation";

/// One condition in the NIP-26 query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Condition {
    /// `kind=<u16>` — the delegatee may sign only this kind.
    Kind(Kind),
    /// `created_at>=<ts>` (rendered as `created_at><ts>` per NIP-26)
    /// — the event's `created_at` MUST be strictly after `ts`.
    CreatedAfter(Timestamp),
    /// `created_at<<ts>` — the event's `created_at` MUST be strictly
    /// before `ts`.
    CreatedBefore(Timestamp),
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kind(k) => write!(f, "kind={}", k.as_u16()),
            Self::CreatedAfter(ts) => write!(f, "created_at>{}", ts.as_secs()),
            Self::CreatedBefore(ts) => write!(f, "created_at<{}", ts.as_secs()),
        }
    }
}

/// A list of [`Condition`]s.
///
/// Order is preserved through `parse` / `render` so a parsed-then-
/// rendered string is byte-identical to its input — required to keep
/// the delegation token verifiable.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Conditions {
    items: Vec<Condition>,
}

impl Conditions {
    /// Construct an empty (unconditional) list.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Append a `kind=` condition.
    #[must_use]
    pub fn allow_kind(mut self, kind: Kind) -> Self {
        self.items.push(Condition::Kind(kind));
        self
    }

    /// Append a `created_at>` condition (the event's `created_at`
    /// must be strictly after `ts`).
    #[must_use]
    pub fn after(mut self, ts: Timestamp) -> Self {
        self.items.push(Condition::CreatedAfter(ts));
        self
    }

    /// Append a `created_at<` condition (the event's `created_at`
    /// must be strictly before `ts`).
    #[must_use]
    pub fn before(mut self, ts: Timestamp) -> Self {
        self.items.push(Condition::CreatedBefore(ts));
        self
    }

    /// Iterate the inner conditions in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = &Condition> {
        self.items.iter()
    }

    /// `true` when no condition is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Render the canonical wire form (`kind=1&created_at>123`).
    ///
    /// An empty [`Conditions`] renders to `""`. Order matches the
    /// order in which conditions were appended.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (i, c) in self.items.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            out.push_str(&c.to_string());
        }
        out
    }

    /// Parse a NIP-26 conditions query string.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionsError`] for any malformed clause — empty
    /// segment, unsupported field, missing operator, non-numeric
    /// value, etc.
    pub fn parse(s: &str) -> Result<Self, ConditionsError> {
        if s.is_empty() {
            return Ok(Self::new());
        }
        let mut items = Vec::with_capacity(s.matches('&').count() + 1);
        for raw in s.split('&') {
            items.push(parse_one(raw)?);
        }
        Ok(Self { items })
    }

    /// `true` when an event with the given `(kind, created_at)`
    /// satisfies *every* condition in the list. An empty
    /// [`Conditions`] always matches.
    #[must_use]
    pub fn matches(&self, kind: Kind, created_at: Timestamp) -> bool {
        self.items.iter().all(|c| match c {
            Condition::Kind(k) => *k == kind,
            Condition::CreatedAfter(ts) => created_at.as_secs() > ts.as_secs(),
            Condition::CreatedBefore(ts) => created_at.as_secs() < ts.as_secs(),
        })
    }
}

fn parse_one(raw: &str) -> Result<Condition, ConditionsError> {
    if let Some(rest) = raw.strip_prefix("kind=") {
        let n: u16 = rest
            .parse()
            .map_err(|_| ConditionsError::InvalidValue(raw.to_owned()))?;
        return Ok(Condition::Kind(Kind::new(n)));
    }
    if let Some(rest) = raw.strip_prefix("created_at>") {
        let n: u64 = rest
            .parse()
            .map_err(|_| ConditionsError::InvalidValue(raw.to_owned()))?;
        return Ok(Condition::CreatedAfter(Timestamp::from_secs(n)));
    }
    if let Some(rest) = raw.strip_prefix("created_at<") {
        let n: u64 = rest
            .parse()
            .map_err(|_| ConditionsError::InvalidValue(raw.to_owned()))?;
        return Ok(Condition::CreatedBefore(Timestamp::from_secs(n)));
    }
    Err(ConditionsError::UnsupportedClause(raw.to_owned()))
}

/// Errors produced by [`Conditions::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConditionsError {
    /// A clause did not match any of the supported NIP-26 fields.
    #[error("unsupported delegation clause `{0}`")]
    UnsupportedClause(String),
    /// A clause's value could not be parsed as `u16` / `u64`.
    #[error("invalid value in delegation clause `{0}`")]
    InvalidValue(String),
}

/// Compute the canonical delegation message that gets hashed and
/// signed.
///
/// Public for callers that need to integrate with an external signer
/// (NIP-07 browser extension, hardware wallet, NIP-46 bunker) where
/// the signing happens out-of-process.
#[must_use]
pub fn delegation_message(delegatee: &PublicKey, conditions: &Conditions) -> String {
    format!(
        "nostr:delegation:{}:{}",
        delegatee.to_hex(),
        conditions.render()
    )
}

/// 32-byte hash that the delegator signs to mint a delegation token.
#[must_use]
pub fn delegation_hash(delegatee: &PublicKey, conditions: &Conditions) -> [u8; 32] {
    let msg = delegation_message(delegatee, conditions);
    let digest = Sha256::digest(msg.as_bytes());
    digest.into()
}

/// 64-byte BIP-340 Schnorr signature on the delegation hash.
pub type DelegationToken = Signature;

/// Sign a delegation as the *delegator*.
#[must_use]
pub fn sign_delegation(
    delegator: &Keys,
    delegatee: &PublicKey,
    conditions: &Conditions,
) -> DelegationToken {
    let h = delegation_hash(delegatee, conditions);
    delegator.sign_schnorr(&h)
}

/// Verify a delegation token.
#[must_use]
pub fn verify_delegation(
    delegator: &PublicKey,
    delegatee: &PublicKey,
    conditions: &Conditions,
    token: &DelegationToken,
) -> bool {
    let h = delegation_hash(delegatee, conditions);
    delegator.verify_schnorr(&h, token)
}

impl Tag {
    /// Build a NIP-26 `delegation` tag.
    ///
    /// Wire form: `["delegation", <delegator-hex>, <conditions>, <token-hex>]`.
    #[must_use]
    pub fn delegation(
        delegator: PublicKey,
        conditions: &Conditions,
        token: &DelegationToken,
    ) -> Self {
        Self::with(
            &TagKind::Custom(DELEGATION_TAG_KEY.to_owned()),
            [delegator.to_hex(), conditions.render(), token.to_string()],
        )
    }
}

/// A parsed `delegation` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Delegator's public key.
    pub delegator: PublicKey,
    /// Conditions on the delegated authority.
    pub conditions: Conditions,
    /// 64-byte Schnorr token signed by `delegator`.
    pub token: DelegationToken,
}

/// Errors produced when reading a `delegation` tag off the wire.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DelegationError {
    /// The `delegation` tag was missing or malformed.
    #[error("event has no well-formed `delegation` tag")]
    Missing,
    /// The delegator pubkey hex was malformed.
    #[error(transparent)]
    Pubkey(#[from] crate::key::PublicKeyError),
    /// The conditions string did not parse.
    #[error(transparent)]
    Conditions(#[from] ConditionsError),
    /// The token hex did not decode into a 64-byte Schnorr signature.
    #[error("invalid delegation token: {0}")]
    Token(String),
    /// The token signature did not verify against the delegator key.
    #[error("delegation token does not verify against the declared delegator")]
    InvalidSignature,
    /// The event's `(kind, created_at)` does not satisfy the
    /// declared conditions.
    #[error("event does not satisfy the delegation conditions")]
    ConditionsViolated,
}

/// Extract the `delegation` tag from an [`Event`] or [`Tags`] list,
/// if present and well-formed.
///
/// This does **not** verify the cryptographic token; use
/// [`verify_event_delegation`] for that.
///
/// # Errors
///
/// - [`DelegationError::Missing`] when no `delegation` tag is present
///   or it is shorter than the four wire-form values.
/// - [`DelegationError::Pubkey`] / [`DelegationError::Conditions`] /
///   [`DelegationError::Token`] for individually malformed pieces.
pub fn parse_delegation(tags: &Tags) -> Result<Delegation, DelegationError> {
    for tag in tags {
        if !is_delegation_tag(&tag.kind()) {
            continue;
        }
        let values = tag.values();
        let (Some(d), Some(c), Some(t)) = (values.get(1), values.get(2), values.get(3)) else {
            return Err(DelegationError::Missing);
        };
        let delegator = PublicKey::parse(d)?;
        let conditions = Conditions::parse(c)?;
        let token = t
            .parse::<Signature>()
            .map_err(|e| DelegationError::Token(e.to_string()))?;
        return Ok(Delegation {
            delegator,
            conditions,
            token,
        });
    }
    Err(DelegationError::Missing)
}

fn is_delegation_tag(kind: &TagKind) -> bool {
    matches!(kind, TagKind::Custom(s) if s == DELEGATION_TAG_KEY)
}

/// End-to-end verifier: an event is *delegation-valid* iff
///
/// 1. it carries a well-formed `delegation` tag,
/// 2. the embedded token verifies as a Schnorr signature by
///    `delegator` over `nostr:delegation:<event.pubkey>:<conditions>`,
/// 3. the event's `(kind, created_at)` satisfies the conditions.
///
/// The event's own NIP-01 signature is **not** re-checked here:
/// callers should call [`Event::verify`] independently. Splitting the
/// two checks keeps the cost composable when verifying a batch.
///
/// # Errors
///
/// Returns the corresponding [`DelegationError`] on the first failed
/// step.
pub fn verify_event_delegation(event: &Event) -> Result<Delegation, DelegationError> {
    let delegation = parse_delegation(&event.tags)?;
    if !verify_delegation(
        &delegation.delegator,
        &event.pubkey,
        &delegation.conditions,
        &delegation.token,
    ) {
        return Err(DelegationError::InvalidSignature);
    }
    if !delegation.conditions.matches(event.kind, event.created_at) {
        return Err(DelegationError::ConditionsViolated);
    }
    Ok(delegation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventBuilder;
    use crate::event::Kind;

    fn fixture_keys(byte: u8) -> Keys {
        let hex: String = format!("{byte:064x}");
        Keys::parse(&hex).unwrap()
    }

    #[test]
    fn conditions_render_and_parse_round_trip() {
        let c = Conditions::new()
            .allow_kind(Kind::TEXT_NOTE)
            .after(Timestamp::from_secs(1_700_000_000))
            .before(Timestamp::from_secs(1_800_000_000));
        let rendered = c.render();
        assert_eq!(
            rendered,
            "kind=1&created_at>1700000000&created_at<1800000000"
        );
        assert_eq!(Conditions::parse(&rendered).unwrap(), c);
    }

    #[test]
    fn empty_conditions_render_to_empty_string() {
        let empty = Conditions::new();
        assert_eq!(empty.render(), "");
        assert_eq!(Conditions::parse("").unwrap(), empty);
        // An empty conditions list always matches.
        assert!(empty.matches(Kind::TEXT_NOTE, Timestamp::from_secs(1)));
    }

    #[test]
    fn parse_rejects_malformed_clauses() {
        assert!(matches!(
            Conditions::parse("foobar=1"),
            Err(ConditionsError::UnsupportedClause(s)) if s == "foobar=1"
        ));
        assert!(matches!(
            Conditions::parse("kind=abc"),
            Err(ConditionsError::InvalidValue(s)) if s == "kind=abc"
        ));
    }

    #[test]
    fn matches_enforces_strict_inequalities() {
        let c = Conditions::new()
            .after(Timestamp::from_secs(100))
            .before(Timestamp::from_secs(200));
        assert!(c.matches(Kind::TEXT_NOTE, Timestamp::from_secs(150)));
        // Boundary: NIP-26 uses strict `<` / `>`.
        assert!(!c.matches(Kind::TEXT_NOTE, Timestamp::from_secs(100)));
        assert!(!c.matches(Kind::TEXT_NOTE, Timestamp::from_secs(200)));
    }

    #[test]
    fn delegation_token_verifies_with_correct_inputs() {
        let delegator = fixture_keys(1);
        let delegatee = fixture_keys(2);
        let conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);

        let token = sign_delegation(&delegator, delegatee.public_key(), &conditions);
        assert!(verify_delegation(
            delegator.public_key(),
            delegatee.public_key(),
            &conditions,
            &token,
        ));
    }

    #[test]
    fn delegation_token_fails_when_delegatee_changes() {
        let delegator = fixture_keys(1);
        let delegatee_a = fixture_keys(2);
        let delegatee_b = fixture_keys(3);
        let conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);

        let token = sign_delegation(&delegator, delegatee_a.public_key(), &conditions);
        assert!(!verify_delegation(
            delegator.public_key(),
            delegatee_b.public_key(),
            &conditions,
            &token,
        ));
    }

    #[test]
    fn delegation_token_fails_when_conditions_change() {
        let delegator = fixture_keys(1);
        let delegatee = fixture_keys(2);
        let signed_conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);
        let mutated_conditions = Conditions::new().allow_kind(Kind::REACTION);

        let token = sign_delegation(&delegator, delegatee.public_key(), &signed_conditions);
        assert!(!verify_delegation(
            delegator.public_key(),
            delegatee.public_key(),
            &mutated_conditions,
            &token,
        ));
    }

    #[test]
    fn parse_delegation_round_trips_through_a_built_event() {
        let delegator = fixture_keys(1);
        let delegatee = fixture_keys(2);
        let conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);
        let token = sign_delegation(&delegator, delegatee.public_key(), &conditions);

        let event = EventBuilder::text_note("delegated note")
            .tag(Tag::delegation(
                *delegator.public_key(),
                &conditions,
                &token,
            ))
            .sign_with_keys(&delegatee)
            .unwrap();

        let parsed = parse_delegation(&event.tags).unwrap();
        assert_eq!(&parsed.delegator, delegator.public_key());
        assert_eq!(parsed.conditions, conditions);

        let verified = verify_event_delegation(&event).expect("delegation must verify");
        assert_eq!(&verified.delegator, delegator.public_key());
    }

    #[test]
    fn verify_event_delegation_rejects_violated_conditions() {
        let delegator = fixture_keys(1);
        let delegatee = fixture_keys(2);
        // Allow only TEXT_NOTE — but build a REACTION event.
        let conditions = Conditions::new().allow_kind(Kind::TEXT_NOTE);
        let token = sign_delegation(&delegator, delegatee.public_key(), &conditions);

        let event = EventBuilder::new(Kind::REACTION, "+")
            .tag(Tag::delegation(
                *delegator.public_key(),
                &conditions,
                &token,
            ))
            .sign_with_keys(&delegatee)
            .unwrap();

        assert!(matches!(
            verify_event_delegation(&event),
            Err(DelegationError::ConditionsViolated)
        ));
    }

    #[test]
    fn verify_event_delegation_detects_token_tampering() {
        let delegator = fixture_keys(1);
        let delegatee = fixture_keys(2);
        let real = Conditions::new().allow_kind(Kind::TEXT_NOTE);
        let real_token = sign_delegation(&delegator, delegatee.public_key(), &real);

        // Build the event with mutated conditions but the token from
        // the original conditions.
        let mutated = Conditions::new().allow_kind(Kind::REACTION);
        let event = EventBuilder::new(Kind::REACTION, "+")
            .tag(Tag::delegation(
                *delegator.public_key(),
                &mutated,
                &real_token,
            ))
            .sign_with_keys(&delegatee)
            .unwrap();

        assert!(matches!(
            verify_event_delegation(&event),
            Err(DelegationError::InvalidSignature)
        ));
    }
}
