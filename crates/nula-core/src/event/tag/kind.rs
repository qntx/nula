//! Tag head identifier.
//!
//! Every Nostr tag is an array of strings whose first entry names the tag.
//! NIP-01 calls out that names which are *exactly* one ASCII letter long are
//! treated specially by relay storage and filters; everything else is a
//! free-form custom name.
//!
//! [`TagKind`] is the strongly-typed representation of that head. It is
//! constructed directly via [`TagKind::single_letter`] /
//! [`TagKind::custom`], parsed from a string via [`TagKind::from_str`], or
//! borrowed from a serialised tag through [`TagKind::from_wire`].

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::single_letter::{Alphabet, SingleLetterTag};

/// Errors raised when parsing a [`TagKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TagKindError {
    /// The tag head was empty.
    #[error("tag head must not be empty")]
    Empty,
}

/// Tag head identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TagKind {
    /// A single ASCII-letter tag (`a`–`z`, `A`–`Z`).
    ///
    /// Single-letter lowercase tags are queryable through the NIP-01
    /// `#a`/`#e`/`#p` filter keys; uppercase variants are not.
    SingleLetter(SingleLetterTag),
    /// A custom multi-character or non-ASCII tag head (e.g. `alt`, `client`,
    /// `expiration`, …).
    Custom(String),
}

impl TagKind {
    /// Construct from a [`SingleLetterTag`].
    #[must_use]
    pub const fn single_letter(tag: SingleLetterTag) -> Self {
        Self::SingleLetter(tag)
    }

    /// Construct a custom tag head.
    pub fn custom<S>(name: S) -> Self
    where
        S: Into<String>,
    {
        Self::Custom(name.into())
    }

    /// Return the wire form (a single-character string for single-letter
    /// tags, otherwise the custom string).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleLetter(tag) => single_letter_str(*tag),
            Self::Custom(name) => name,
        }
    }

    /// Convert from a borrowed wire string without owning it when the head is
    /// a single ASCII letter.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        Self::parse(value).unwrap_or_else(|_err| Self::Custom(value.to_owned()))
    }

    /// Parse from a wire string.
    ///
    /// # Errors
    ///
    /// Returns [`TagKindError::Empty`] if `value` is empty. A non-empty
    /// non-single-letter input becomes [`TagKind::Custom`] without further
    /// validation.
    pub fn parse(value: &str) -> Result<Self, TagKindError> {
        if value.is_empty() {
            return Err(TagKindError::Empty);
        }

        if let Some(letter) = single_letter_from_str(value) {
            return Ok(Self::SingleLetter(letter));
        }

        Ok(Self::Custom(value.to_owned()))
    }
}

/// Try to parse `value` as a single-letter tag head, returning `None` if
/// `value` is not exactly one ASCII letter.
fn single_letter_from_str(value: &str) -> Option<SingleLetterTag> {
    let mut chars = value.chars();
    let first = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    SingleLetterTag::from_char(first).ok()
}

/// Render a single-letter tag head as a `&'static str` for the 52 valid
/// values, avoiding any allocation on the hot path.
const fn single_letter_str(tag: SingleLetterTag) -> &'static str {
    if tag.uppercase {
        match tag.character {
            Alphabet::A => "A",
            Alphabet::B => "B",
            Alphabet::C => "C",
            Alphabet::D => "D",
            Alphabet::E => "E",
            Alphabet::F => "F",
            Alphabet::G => "G",
            Alphabet::H => "H",
            Alphabet::I => "I",
            Alphabet::J => "J",
            Alphabet::K => "K",
            Alphabet::L => "L",
            Alphabet::M => "M",
            Alphabet::N => "N",
            Alphabet::O => "O",
            Alphabet::P => "P",
            Alphabet::Q => "Q",
            Alphabet::R => "R",
            Alphabet::S => "S",
            Alphabet::T => "T",
            Alphabet::U => "U",
            Alphabet::V => "V",
            Alphabet::W => "W",
            Alphabet::X => "X",
            Alphabet::Y => "Y",
            Alphabet::Z => "Z",
        }
    } else {
        match tag.character {
            Alphabet::A => "a",
            Alphabet::B => "b",
            Alphabet::C => "c",
            Alphabet::D => "d",
            Alphabet::E => "e",
            Alphabet::F => "f",
            Alphabet::G => "g",
            Alphabet::H => "h",
            Alphabet::I => "i",
            Alphabet::J => "j",
            Alphabet::K => "k",
            Alphabet::L => "l",
            Alphabet::M => "m",
            Alphabet::N => "n",
            Alphabet::O => "o",
            Alphabet::P => "p",
            Alphabet::Q => "q",
            Alphabet::R => "r",
            Alphabet::S => "s",
            Alphabet::T => "t",
            Alphabet::U => "u",
            Alphabet::V => "v",
            Alphabet::W => "w",
            Alphabet::X => "x",
            Alphabet::Y => "y",
            Alphabet::Z => "z",
        }
    }
}

impl fmt::Display for TagKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TagKind {
    type Err = TagKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Borrow<str> for TagKind {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for TagKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for TagKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TagKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = <&str>::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_letter_round_trip() {
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        assert_eq!(kind.as_str(), "e");
        assert_eq!(TagKind::parse("e").unwrap(), kind);
    }

    #[test]
    fn custom_passes_through() {
        let kind = TagKind::custom("expiration");
        assert_eq!(kind.as_str(), "expiration");
        assert_eq!(TagKind::parse("expiration").unwrap(), kind);
    }

    #[test]
    fn empty_input_is_error() {
        assert_eq!(TagKind::parse("").unwrap_err(), TagKindError::Empty);
    }

    #[test]
    fn non_letter_one_char_is_custom() {
        let kind = TagKind::parse("1").unwrap();
        assert_eq!(kind, TagKind::custom("1"));
    }

    #[test]
    fn from_wire_never_panics() {
        let kind = TagKind::from_wire("");
        assert_eq!(kind, TagKind::custom(""));
    }

    #[test]
    fn display_matches_as_str() {
        let kind = TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::P));
        assert_eq!(kind.to_string(), "P");
    }

    #[test]
    fn serde_string_form() {
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let single_letter_json = serde_json::to_string(&kind).unwrap();
        assert_eq!(single_letter_json, r#""e""#);

        let custom = TagKind::custom("client");
        let custom_json = serde_json::to_string(&custom).unwrap();
        assert_eq!(custom_json, r#""client""#);

        let parsed: TagKind = serde_json::from_str(r#""client""#).unwrap();
        assert_eq!(parsed, custom);
    }

    #[test]
    fn parses_single_letter_uppercase() {
        let kind = TagKind::parse("E").unwrap();
        assert_eq!(
            kind,
            TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::E))
        );
    }
}
