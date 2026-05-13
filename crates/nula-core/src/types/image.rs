//! Image dimensions, encoded as `WIDTHxHEIGHT`.
//!
//! Used by NIP-92 (media attachments), NIP-94 (file metadata), and the
//! `picture` field in NIP-01 metadata. The wire format is a single string
//! with a lowercase `x` separator, e.g. `"800x600"`.

use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Errors raised when parsing [`ImageDimensions`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ImageError {
    /// The input did not contain exactly one `x` separator.
    #[error("invalid image dimensions format, expected `WIDTHxHEIGHT`, got `{0}`")]
    InvalidFormat(String),
    /// One of the components could not be parsed as a non-negative integer.
    #[error("invalid image dimension component: {0}")]
    ParseInt(#[from] ParseIntError),
    /// One of the components was zero.
    #[error("image dimension cannot be zero")]
    Zero,
}

/// Image dimensions in pixels.
///
/// `width` and `height` are guaranteed to be non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImageDimensions {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
}

impl ImageDimensions {
    /// Construct dimensions, rejecting zero values.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::Zero`] if either dimension is zero.
    pub const fn new(width: u32, height: u32) -> Result<Self, ImageError> {
        if width == 0 || height == 0 {
            return Err(ImageError::Zero);
        }
        Ok(Self { width, height })
    }
}

impl fmt::Display for ImageDimensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{}", self.width, self.height)
    }
}

impl FromStr for ImageDimensions {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lhs, rhs) = s
            .split_once('x')
            .ok_or_else(|| ImageError::InvalidFormat(s.to_owned()))?;

        if lhs.is_empty() || rhs.is_empty() {
            return Err(ImageError::InvalidFormat(s.to_owned()));
        }

        let width: u32 = lhs.parse()?;
        let height: u32 = rhs.parse()?;
        Self::new(width, height)
    }
}

impl Serialize for ImageDimensions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ImageDimensions {
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
    fn round_trip() {
        let dim = ImageDimensions::new(800, 600).unwrap();
        let s = dim.to_string();
        assert_eq!(s, "800x600");
        let parsed: ImageDimensions = s.parse().unwrap();
        assert_eq!(parsed, dim);
    }

    #[test]
    fn rejects_zero() {
        assert!(matches!(
            ImageDimensions::new(0, 100),
            Err(ImageError::Zero)
        ));
        assert!(matches!(
            ImageDimensions::new(100, 0),
            Err(ImageError::Zero)
        ));
    }

    #[test]
    fn rejects_missing_separator() {
        let err = "800600".parse::<ImageDimensions>().unwrap_err();
        assert!(matches!(err, ImageError::InvalidFormat(_)));
    }

    #[test]
    fn rejects_empty_components() {
        let leading = "x600".parse::<ImageDimensions>().unwrap_err();
        let trailing = "800x".parse::<ImageDimensions>().unwrap_err();
        assert!(matches!(leading, ImageError::InvalidFormat(_)));
        assert!(matches!(trailing, ImageError::InvalidFormat(_)));
    }

    #[test]
    fn rejects_negative() {
        let err = "-1x100".parse::<ImageDimensions>().unwrap_err();
        assert!(matches!(err, ImageError::ParseInt(_)));
    }

    #[test]
    fn serde_round_trip() {
        let dim = ImageDimensions::new(1920, 1080).unwrap();
        let json = serde_json::to_string(&dim).unwrap();
        assert_eq!(json, r#""1920x1080""#);
        let parsed: ImageDimensions = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dim);
    }
}
