// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Single-letter tag identifier (`a`–`z`, `A`–`Z`).
//!
//! NIP-01 splits tags into two camps:
//!
//! - lowercase single-letter tags (`a`, `e`, `p`, …) — *queryable* through
//!   filter `#a`, `#e`, `#p` keys, and
//! - uppercase single-letter tags (`A`, `E`, `P`, …) — same data, but
//!   excluded from the queryable filter index.
//!
//! [`SingleLetterTag`] models the discriminator without conflating it with the
//! free-form custom tag names (which live in [`super::TagKind::Custom`]).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// An ASCII letter `a`–`z` (case-folded). Combine with the case bit to obtain
/// a [`SingleLetterTag`].
#[allow(
    missing_docs,
    reason = "26 self-evident variants, one per ASCII letter"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Alphabet {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
}

/// Errors raised when constructing an [`Alphabet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AlphabetError {
    /// The character was not an ASCII letter.
    #[error("expected an ASCII letter, got `{0}`")]
    NotAsciiLetter(char),
}

impl Alphabet {
    /// Construct from a `char`, accepting both upper- and lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`AlphabetError::NotAsciiLetter`] if `c` is not an ASCII
    /// letter.
    pub const fn from_char(c: char) -> Result<Self, AlphabetError> {
        let value = match c {
            'a' | 'A' => Self::A,
            'b' | 'B' => Self::B,
            'c' | 'C' => Self::C,
            'd' | 'D' => Self::D,
            'e' | 'E' => Self::E,
            'f' | 'F' => Self::F,
            'g' | 'G' => Self::G,
            'h' | 'H' => Self::H,
            'i' | 'I' => Self::I,
            'j' | 'J' => Self::J,
            'k' | 'K' => Self::K,
            'l' | 'L' => Self::L,
            'm' | 'M' => Self::M,
            'n' | 'N' => Self::N,
            'o' | 'O' => Self::O,
            'p' | 'P' => Self::P,
            'q' | 'Q' => Self::Q,
            'r' | 'R' => Self::R,
            's' | 'S' => Self::S,
            't' | 'T' => Self::T,
            'u' | 'U' => Self::U,
            'v' | 'V' => Self::V,
            'w' | 'W' => Self::W,
            'x' | 'X' => Self::X,
            'y' | 'Y' => Self::Y,
            'z' | 'Z' => Self::Z,
            _ => return Err(AlphabetError::NotAsciiLetter(c)),
        };
        Ok(value)
    }

    /// Render as a lowercase ASCII letter.
    #[must_use]
    pub const fn as_lower_char(self) -> char {
        match self {
            Self::A => 'a',
            Self::B => 'b',
            Self::C => 'c',
            Self::D => 'd',
            Self::E => 'e',
            Self::F => 'f',
            Self::G => 'g',
            Self::H => 'h',
            Self::I => 'i',
            Self::J => 'j',
            Self::K => 'k',
            Self::L => 'l',
            Self::M => 'm',
            Self::N => 'n',
            Self::O => 'o',
            Self::P => 'p',
            Self::Q => 'q',
            Self::R => 'r',
            Self::S => 's',
            Self::T => 't',
            Self::U => 'u',
            Self::V => 'v',
            Self::W => 'w',
            Self::X => 'x',
            Self::Y => 'y',
            Self::Z => 'z',
        }
    }

    /// Render as an uppercase ASCII letter.
    #[must_use]
    pub const fn as_upper_char(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
            Self::E => 'E',
            Self::F => 'F',
            Self::G => 'G',
            Self::H => 'H',
            Self::I => 'I',
            Self::J => 'J',
            Self::K => 'K',
            Self::L => 'L',
            Self::M => 'M',
            Self::N => 'N',
            Self::O => 'O',
            Self::P => 'P',
            Self::Q => 'Q',
            Self::R => 'R',
            Self::S => 'S',
            Self::T => 'T',
            Self::U => 'U',
            Self::V => 'V',
            Self::W => 'W',
            Self::X => 'X',
            Self::Y => 'Y',
            Self::Z => 'Z',
        }
    }
}

/// A single-letter tag identifier (`a`–`z`, `A`–`Z`).
///
/// Equal to [`Alphabet`] paired with a single bit identifying the case.
/// `Display` and `serde` write the result as a one-character string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SingleLetterTag {
    /// The letter, case-folded.
    pub character: Alphabet,
    /// `true` if the on-the-wire form is uppercase.
    pub uppercase: bool,
}

/// Errors raised when constructing a [`SingleLetterTag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SingleLetterTagError {
    /// The input could not be mapped to an ASCII letter.
    #[error(transparent)]
    Alphabet(#[from] AlphabetError),
    /// The input was not exactly one character long.
    #[error("expected a one-character tag, got {0} characters")]
    NotSingleChar(usize),
}

impl SingleLetterTag {
    /// Construct a lowercase tag.
    #[must_use]
    pub const fn lowercase(character: Alphabet) -> Self {
        Self {
            character,
            uppercase: false,
        }
    }

    /// Construct an uppercase tag.
    #[must_use]
    pub const fn uppercase(character: Alphabet) -> Self {
        Self {
            character,
            uppercase: true,
        }
    }

    /// Construct from a `char`, preserving its case.
    ///
    /// # Errors
    ///
    /// Returns [`SingleLetterTagError::Alphabet`] when the character is not
    /// an ASCII letter.
    pub const fn from_char(c: char) -> Result<Self, SingleLetterTagError> {
        let character = match Alphabet::from_char(c) {
            Ok(a) => a,
            Err(e) => return Err(SingleLetterTagError::Alphabet(e)),
        };
        let uppercase = c.is_ascii_uppercase();
        Ok(Self {
            character,
            uppercase,
        })
    }

    /// Render to a `char` preserving case.
    #[must_use]
    pub const fn as_char(self) -> char {
        if self.uppercase {
            self.character.as_upper_char()
        } else {
            self.character.as_lower_char()
        }
    }

    /// True if the lowercase form is queried by NIP-01 single-letter filter
    /// keys (`#a`, `#e`, `#p`, …).
    #[must_use]
    pub const fn is_lowercase(self) -> bool {
        !self.uppercase
    }
}

impl fmt::Display for SingleLetterTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_char().encode_utf8(&mut [0_u8; 1]))
    }
}

impl FromStr for SingleLetterTag {
    type Err = SingleLetterTagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(SingleLetterTagError::NotSingleChar(0));
        };
        if chars.next().is_some() {
            return Err(SingleLetterTagError::NotSingleChar(s.chars().count()));
        }
        Self::from_char(first)
    }
}

impl Serialize for SingleLetterTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SingleLetterTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = <&str>::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_round_trip() {
        for c in 'a'..='z' {
            let lower = Alphabet::from_char(c).unwrap();
            let upper = Alphabet::from_char(c.to_ascii_uppercase()).unwrap();
            assert_eq!(lower, upper);
            assert_eq!(lower.as_lower_char(), c);
            assert_eq!(lower.as_upper_char(), c.to_ascii_uppercase());
        }
    }

    #[test]
    fn alphabet_rejects_non_letter() {
        let err = Alphabet::from_char('1').unwrap_err();
        assert_eq!(err, AlphabetError::NotAsciiLetter('1'));
    }

    #[test]
    fn single_letter_lowercase() {
        let p = SingleLetterTag::lowercase(Alphabet::P);
        assert_eq!(p.as_char(), 'p');
        assert!(p.is_lowercase());
    }

    #[test]
    fn single_letter_uppercase() {
        let p = SingleLetterTag::uppercase(Alphabet::P);
        assert_eq!(p.as_char(), 'P');
        assert!(!p.is_lowercase());
    }

    #[test]
    fn single_letter_from_char_preserves_case() {
        let lower = SingleLetterTag::from_char('e').unwrap();
        let upper = SingleLetterTag::from_char('E').unwrap();
        assert!(lower.is_lowercase());
        assert!(!upper.is_lowercase());
        assert_eq!(lower.character, upper.character);
    }

    #[test]
    fn single_letter_from_str_validates_length() {
        assert!(matches!(
            "ee".parse::<SingleLetterTag>().unwrap_err(),
            SingleLetterTagError::NotSingleChar(2)
        ));
        assert!(matches!(
            "".parse::<SingleLetterTag>().unwrap_err(),
            SingleLetterTagError::NotSingleChar(0)
        ));
        assert!(matches!(
            "1".parse::<SingleLetterTag>().unwrap_err(),
            SingleLetterTagError::Alphabet(_)
        ));
    }

    #[test]
    fn display_renders_one_char() {
        assert_eq!(SingleLetterTag::lowercase(Alphabet::A).to_string(), "a");
        assert_eq!(SingleLetterTag::uppercase(Alphabet::Z).to_string(), "Z");
    }

    #[test]
    fn serde_round_trip() {
        let tag = SingleLetterTag::lowercase(Alphabet::E);
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, r#""e""#);
        let parsed: SingleLetterTag = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tag);
    }

    #[test]
    fn ordering_uppercase_after_lowercase() {
        let lower_e = SingleLetterTag::lowercase(Alphabet::E);
        let upper_e = SingleLetterTag::uppercase(Alphabet::E);
        // `Alphabet` is identical, so order is determined by the `uppercase` flag.
        assert!(lower_e < upper_e);
    }
}
