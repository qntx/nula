//! Address of a parameterized replaceable event.
//!
//! NIP-01 specifies that the triple `(kind, author, identifier)` uniquely
//! identifies a *parameterized replaceable* event, i.e. an event whose
//! `kind` is in `30000..=39999` and whose `d` tag carries the identifier.
//!
//! The on-the-wire encoding is the colon-separated form used by `a` tags
//! (NIP-01 §addressable events) and shared with NIP-19 `naddr`:
//!
//! ```text
//! <kind>:<author-pubkey-hex>:<identifier>
//! ```
//!
//! [`Coordinate`] models that triple, exposes `Display`/`FromStr` for the
//! wire form, and is reused by NIP-09 (`a` tag in deletion events), NIP-19
//! (`naddr`), and any future NIP that addresses replaceable events.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::kind::Kind;
use crate::key::{PublicKey, PublicKeyError};

/// Errors raised when parsing a [`Coordinate`] from its wire form.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum CoordinateError {
    /// The wire form did not contain exactly two `:` separators.
    #[error("expected `<kind>:<author>:<identifier>`, got `{0}`")]
    Malformed(String),
    /// The `kind` segment did not parse as an unsigned 16-bit integer.
    #[error("invalid kind segment `{0}`")]
    InvalidKind(String),
    /// The `author` segment did not parse as a 32-byte public key.
    #[error(transparent)]
    InvalidAuthor(#[from] PublicKeyError),
}

/// Address of a parameterized replaceable event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Coordinate {
    /// Event kind.
    pub kind: Kind,
    /// Author's public key.
    pub author: PublicKey,
    /// `d`-tag identifier.
    pub identifier: String,
}

impl Coordinate {
    /// Construct a coordinate.
    #[must_use]
    pub fn new(kind: Kind, author: PublicKey, identifier: impl Into<String>) -> Self {
        Self {
            kind,
            author,
            identifier: identifier.into(),
        }
    }

    /// Parse the colon-separated wire form `<kind>:<author>:<identifier>`.
    ///
    /// Equivalent to `s.parse::<Coordinate>()` but matches the
    /// `Type::parse` naming convention used elsewhere in the crate
    /// ([`PublicKey::parse`], [`crate::types::RelayUrl::parse`],
    /// [`crate::nips::nip46::Uri::parse`]).
    ///
    /// # Errors
    ///
    /// See [`CoordinateError`].
    pub fn parse(input: impl AsRef<str>) -> Result<Self, CoordinateError> {
        input.as_ref().parse()
    }

    /// Render the colon-separated wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_u16(),
            self.author.to_hex(),
            self.identifier
        )
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl FromStr for Coordinate {
    type Err = CoordinateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');
        let kind_str = parts.next();
        let author_str = parts.next();
        let identifier = parts.next();
        match (kind_str, author_str, identifier) {
            (Some(k), Some(a), Some(id)) => {
                let kind: u16 = k
                    .parse()
                    .map_err(|_| CoordinateError::InvalidKind(k.to_owned()))?;
                let author = PublicKey::parse(a)?;
                Ok(Self::new(Kind::from(kind), author, id))
            }
            _ => Err(CoordinateError::Malformed(s.to_owned())),
        }
    }
}

impl Serialize for Coordinate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for Coordinate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn pk() -> PublicKey {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
        *keys.public_key()
    }

    #[test]
    fn display_round_trip() {
        let coord = Coordinate::new(Kind::from(30_023_u16), pk(), "long-form-1");
        let wire = coord.to_string();
        let parsed: Coordinate = wire.parse().unwrap();
        assert_eq!(parsed, coord);
    }

    #[test]
    fn allows_colon_in_identifier() {
        // Identifiers may contain `:` (NIP-01 doesn't forbid it); nula's
        // `splitn(3, ':')` keeps everything after the second colon in the
        // third segment, so a multi-colon identifier round-trips intact.
        //
        // Interop note: `rust-nostr` 0.45 parses coordinates with
        // `coordinate.split(':')` and takes only the first three segments
        // (`nip01/mod.rs::from_kpi_format`), which *truncates* this
        // identifier to `"weird"` and silently drops `:id:with:colons`.
        // nula's behaviour is the spec-faithful one; this test pins the
        // divergence so it stays intentional and visible.
        let coord = Coordinate::new(Kind::from(30_023_u16), pk(), "weird:id:with:colons");
        let wire = coord.to_string();
        let parsed: Coordinate = wire.parse().unwrap();
        assert_eq!(parsed, coord);
        assert_eq!(parsed.identifier, "weird:id:with:colons");

        // Pin the exact divergence point: parsing a hand-built wire string
        // keeps the full colon-bearing tail as the identifier rather than
        // truncating at the first colon (what `split(':')` would do).
        let tail_wire = format!("30023:{}:a:b:c", pk().to_hex());
        let tail_parsed: Coordinate = tail_wire.parse().unwrap();
        assert_eq!(tail_parsed.identifier, "a:b:c");
    }

    #[test]
    fn rejects_missing_components() {
        let err1 = "30023".parse::<Coordinate>().unwrap_err();
        assert!(matches!(err1, CoordinateError::Malformed(_)));
        let err2 = "30023:not-hex".parse::<Coordinate>().unwrap_err();
        assert!(matches!(err2, CoordinateError::Malformed(_)));
    }

    #[test]
    fn rejects_bad_kind() {
        let value = format!("not-a-number:{}:foo", pk().to_hex());
        let err: CoordinateError = value.parse::<Coordinate>().unwrap_err();
        assert!(matches!(err, CoordinateError::InvalidKind(_)));
    }

    #[test]
    fn parse_method_matches_fromstr() {
        // Inherent `parse` and the FromStr impl must produce identical
        // results — they share the same code path, but pin the
        // contract with a regression test to guard future refactors.
        let coord = Coordinate::new(Kind::from(30_023_u16), pk(), "alpha");
        let wire = coord.to_string();
        let via_inherent = Coordinate::parse(&wire).unwrap();
        let via_fromstr: Coordinate = wire.parse().unwrap();
        assert_eq!(via_inherent, via_fromstr);
        assert_eq!(via_inherent, coord);
    }

    #[test]
    fn serde_uses_wire_form() {
        let coord = Coordinate::new(Kind::from(30_023_u16), pk(), "alpha");
        let json = serde_json::to_string(&coord).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.contains(":alpha\""));
        let parsed: Coordinate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, coord);
    }
}
