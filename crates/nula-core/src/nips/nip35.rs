//! [NIP-35] Torrents.
//!
//! NIP-35 defines `kind: 2003`, a lightweight `BitTorrent` *index*: enough
//! metadata to search for content and reconstruct a magnet link, without
//! shipping the `.torrent` file itself. A companion `kind: 2004` event is a
//! comment that "works exactly like a `kind: 1`" and follows NIP-10 tagging.
//!
//! Wire shape of a `kind: 2003` event:
//!
//! ```json
//! {
//!   "kind": 2003,
//!   "content": "<free-form description>",
//!   "tags": [
//!     ["title", "<name>"],
//!     ["x", "<v1 btih, 40 hex>"],
//!     ["file", "<path>", "<size-bytes>"],
//!     ["tracker", "udp://tracker.example:1337"],
//!     ["i", "tcat:video,movie,4k"],
//!     ["i", "imdb:tt15239678"],
//!     ["t", "movie"]
//!   ]
//! }
//! ```
//!
//! Compared with the upstream `rust-nostr` implementation, this module
//! additionally provides [`Torrent::from_event`] (a strict parser; upstream
//! ships only the builder) and preserves non-`tcat:` external references
//! (`imdb:`, `tmdb:`, …) in [`Torrent::external_ids`] so they survive a
//! round trip instead of being dropped.
//!
//! [NIP-35]: https://github.com/nostr-protocol/nips/blob/master/35.md
//!
//! # Example
//!
//! ```
//! use nula_core::nips::nip35::{Torrent, TorrentFile, TorrentInfoHash};
//! use nula_core::Keys;
//!
//! let torrent = Torrent {
//!     title: "Example".to_owned(),
//!     description: "An example torrent".to_owned(),
//!     info_hash: TorrentInfoHash::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap(),
//!     files: vec![TorrentFile { name: "info/example.txt".to_owned(), size: 1024 }],
//!     trackers: vec!["udp://tracker.example:1337".parse().unwrap()],
//!     categories: vec!["video".to_owned(), "movie".to_owned()],
//!     external_ids: vec!["imdb:tt15239678".to_owned()],
//!     hashtags: vec!["movie".to_owned()],
//! };
//!
//! let keys = Keys::generate().unwrap();
//! let event = torrent.to_event_builder().sign_with_keys(&keys).unwrap();
//! let parsed = Torrent::from_event(&event).unwrap();
//! assert_eq!(parsed, torrent);
//! ```

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags};
use crate::types::{Url, UrlError};
use crate::util::hex::{self, HexError};

/// Length in bytes of a V1 (SHA-1) `BitTorrent` info hash.
const INFO_HASH_LEN: usize = 20;

/// `tcat:` prefix used by NIP-35 for the comma-separated category path.
const TCAT_PREFIX: &str = "tcat:";

/// A V1 `BitTorrent` info hash (the `btih` of a magnet link).
///
/// NIP-35 pins the `x` tag to the **V1** info hash, which is a 20-byte
/// SHA-1 digest rendered as 40 lowercase hex characters. Modelling it as a
/// fixed-size newtype (rather than a free-form `String`) rejects malformed
/// hashes at the boundary and keeps comparisons/`Hash` cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TorrentInfoHash([u8; INFO_HASH_LEN]);

impl TorrentInfoHash {
    /// Wrap a raw 20-byte digest.
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; INFO_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 20-byte digest.
    #[must_use]
    pub const fn as_byte_array(&self) -> &[u8; INFO_HASH_LEN] {
        &self.0
    }

    /// Copy out the raw 20-byte digest.
    #[must_use]
    pub const fn to_byte_array(self) -> [u8; INFO_HASH_LEN] {
        self.0
    }

    /// Parse from a 40-character lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns [`HexError`] if the input is not exactly 40 hex characters.
    pub fn from_hex<S>(input: S) -> Result<Self, HexError>
    where
        S: AsRef<str>,
    {
        let mut bytes = [0_u8; INFO_HASH_LEN];
        hex::decode_to_slice(input.as_ref(), &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Render as a 40-character lowercase hex string.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for TorrentInfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::fmt_lower(self.0, f)
    }
}

impl FromStr for TorrentInfoHash {
    type Err = HexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// A single file entry within a torrent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TorrentFile {
    /// Full path inside the torrent (e.g. `info/example.txt`).
    pub name: String,
    /// File size in bytes.
    pub size: u64,
}

/// Torrent index metadata (`kind: 2003`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Torrent {
    /// Human-readable title (`title` tag).
    pub title: String,
    /// Free-form description carried in the event `content`.
    pub description: String,
    /// V1 `BitTorrent` info hash (`x` tag).
    pub info_hash: TorrentInfoHash,
    /// Files included in the torrent (`file` tags).
    pub files: Vec<TorrentFile>,
    /// Tracker URLs (`tracker` tags).
    pub trackers: Vec<Url>,
    /// Category path segments encoded as a single `["i", "tcat:a,b,c"]` tag.
    pub categories: Vec<String>,
    /// Other `i` external references verbatim (`imdb:…`, `tmdb:…`, …).
    pub external_ids: Vec<String>,
    /// Additional hashtags (`t` tags).
    pub hashtags: Vec<String>,
}

impl Torrent {
    /// Build the `kind: 2003` [`EventBuilder`] for this torrent.
    #[must_use]
    pub fn to_event_builder(&self) -> EventBuilder {
        let mut tags: Vec<Tag> = Vec::with_capacity(
            2 + self.files.len()
                + self.trackers.len()
                + usize::from(!self.categories.is_empty())
                + self.external_ids.len()
                + self.hashtags.len(),
        );

        tags.push(Tag::title(self.title.as_str()));
        tags.push(Tag::with(&info_hash_kind(), [self.info_hash.to_hex()]));

        for file in &self.files {
            tags.push(Tag::with(
                &file_kind(),
                [file.name.clone(), file.size.to_string()],
            ));
        }
        for tracker in &self.trackers {
            tags.push(Tag::with(&tracker_kind(), [tracker.as_str().to_owned()]));
        }
        if !self.categories.is_empty() {
            tags.push(Tag::i(format!(
                "{TCAT_PREFIX}{}",
                self.categories.join(",")
            )));
        }
        for external in &self.external_ids {
            tags.push(Tag::i(external.clone()));
        }
        for hashtag in &self.hashtags {
            tags.push(Tag::t(hashtag));
        }

        EventBuilder::new(Kind::TORRENT, self.description.as_str()).tags(Tags::from_vec(tags))
    }

    /// Reconstruct a [`Torrent`] from a `kind: 2003` [`Event`].
    ///
    /// Unknown tags are ignored (forward-compatible). Repeated `i` tags whose
    /// value starts with `tcat:` are flattened across commas into
    /// [`Torrent::categories`]; every other `i` tag is preserved verbatim in
    /// [`Torrent::external_ids`].
    ///
    /// # Errors
    ///
    /// Returns [`TorrentError`] if the kind is not `2003`, a mandatory field
    /// (`title`, `x`) is missing, or a `file` / `tracker` / `x` value is
    /// malformed.
    pub fn from_event(event: &Event) -> Result<Self, TorrentError> {
        if event.kind != Kind::TORRENT {
            return Err(TorrentError::UnexpectedKind {
                expected: Kind::TORRENT.as_u16(),
                got: event.kind.as_u16(),
            });
        }

        let title = event
            .tags
            .find_first(&TagKind::custom("title"))
            .and_then(Tag::content)
            .ok_or(TorrentError::MissingTitle)?
            .to_owned();

        let info_hash = event
            .tags
            .find_first(&info_hash_kind())
            .and_then(Tag::content)
            .ok_or(TorrentError::MissingInfoHash)
            .and_then(|hex| {
                TorrentInfoHash::from_hex(hex).map_err(TorrentError::InvalidInfoHash)
            })?;

        let mut files = Vec::new();
        for tag in event.tags.find_all(&file_kind()) {
            let name = tag.get(1).ok_or(TorrentError::MissingFileName)?.to_owned();
            let size = tag
                .get(2)
                .ok_or(TorrentError::MissingFileSize)?
                .parse::<u64>()
                .map_err(|_err| TorrentError::InvalidFileSize)?;
            files.push(TorrentFile { name, size });
        }

        let mut trackers = Vec::new();
        for tag in event.tags.find_all(&tracker_kind()) {
            let url = tag.content().ok_or(TorrentError::MissingTrackerUrl)?;
            trackers.push(Url::parse(url)?);
        }

        let mut categories = Vec::new();
        let mut external_ids = Vec::new();
        for tag in event.tags.find_letter(Alphabet::I) {
            let Some(value) = tag.content() else {
                continue;
            };
            if let Some(path) = value.strip_prefix(TCAT_PREFIX) {
                categories.extend(
                    path.split(',')
                        .filter(|segment| !segment.is_empty())
                        .map(str::to_owned),
                );
            } else {
                external_ids.push(value.to_owned());
            }
        }

        let hashtags = event
            .tags
            .find_letter(Alphabet::T)
            .filter_map(Tag::content)
            .map(str::to_owned)
            .collect();

        Ok(Self {
            title,
            description: event.content.clone(),
            info_hash,
            files,
            trackers,
            categories,
            external_ids,
            hashtags,
        })
    }
}

impl EventBuilder {
    /// Build a NIP-35 torrent comment (`kind: 2004`) replying to `torrent`.
    ///
    /// Per the spec a torrent comment "works exactly like a `kind: 1`" and
    /// follows NIP-10, so this attaches a root `e` marker pointing at the
    /// torrent and a `p` tag crediting its author.
    #[must_use]
    pub fn torrent_comment<S>(content: S, torrent: &Event) -> Self
    where
        S: Into<String>,
    {
        Self::new(Kind::TORRENT_COMMENT, content)
            .tag(Tag::e_marker(torrent.id, "", "root"))
            .tag(Tag::p(torrent.pubkey))
    }
}

const fn info_hash_kind() -> TagKind {
    // `x` is a single-letter tag head, so it must be constructed (and
    // matched) as `SingleLetter`, not `Custom`, to round-trip.
    TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::X))
}

fn file_kind() -> TagKind {
    TagKind::custom("file")
}

fn tracker_kind() -> TagKind {
    TagKind::custom("tracker")
}

/// Errors raised when parsing a [`Torrent`] from an [`Event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TorrentError {
    /// The event's kind was not `2003`.
    #[error("expected kind {expected}, got {got}")]
    UnexpectedKind {
        /// `Kind::TORRENT.as_u16()`.
        expected: u16,
        /// What the event actually advertised.
        got: u16,
    },
    /// The mandatory `title` tag was absent.
    #[error("torrent event is missing the `title` tag")]
    MissingTitle,
    /// The mandatory `x` (info hash) tag was absent.
    #[error("torrent event is missing the `x` info-hash tag")]
    MissingInfoHash,
    /// The `x` tag did not decode as a 20-byte hex digest.
    #[error("invalid torrent info hash: {0}")]
    InvalidInfoHash(#[source] HexError),
    /// A `file` tag had no path element.
    #[error("`file` tag is missing the file name")]
    MissingFileName,
    /// A `file` tag had no size element.
    #[error("`file` tag is missing the file size")]
    MissingFileSize,
    /// A `file` tag's size did not parse as an unsigned integer.
    #[error("`file` tag size is not a valid byte count")]
    InvalidFileSize,
    /// A `tracker` tag had no URL element.
    #[error("`tracker` tag is missing the URL")]
    MissingTrackerUrl,
    /// A `tracker` tag's URL did not parse.
    #[error(transparent)]
    InvalidTracker(#[from] UrlError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample() -> Torrent {
        Torrent {
            title: "Example Release".to_owned(),
            description: "A description body".to_owned(),
            info_hash: TorrentInfoHash::from_hex("0123456789abcdef0123456789abcdef01234567")
                .unwrap(),
            files: vec![
                TorrentFile {
                    name: "info/a.mkv".to_owned(),
                    size: 1_048_576,
                },
                TorrentFile {
                    name: "info/b.nfo".to_owned(),
                    size: 512,
                },
            ],
            trackers: vec![
                "udp://tracker.example:1337".parse().unwrap(),
                "http://tracker.example/announce".parse().unwrap(),
            ],
            categories: vec!["video".to_owned(), "movie".to_owned(), "4k".to_owned()],
            external_ids: vec!["imdb:tt15239678".to_owned(), "tmdb:movie:693134".to_owned()],
            hashtags: vec!["movie".to_owned(), "4k".to_owned()],
        }
    }

    #[test]
    fn info_hash_hex_round_trip() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let hash = TorrentInfoHash::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
        assert_eq!(hash.to_string(), hex);
        assert_eq!(hex.parse::<TorrentInfoHash>().unwrap(), hash);
    }

    #[test]
    fn info_hash_rejects_wrong_length() {
        assert!(TorrentInfoHash::from_hex("abcd").is_err());
        assert!(TorrentInfoHash::from_hex("zz").is_err());
    }

    #[test]
    fn round_trip_through_event() {
        let torrent = sample();
        let event = torrent.to_event_builder().sign_with_keys(&keys()).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::TORRENT);

        let parsed = Torrent::from_event(&event).unwrap();
        assert_eq!(parsed, torrent);
    }

    #[test]
    fn categories_emitted_as_single_tcat_tag() {
        let event = sample().to_event_builder().sign_with_keys(&keys()).unwrap();
        let tcat: Vec<&str> = event
            .tags
            .find_letter(Alphabet::I)
            .filter_map(Tag::content)
            .filter(|v| v.starts_with(TCAT_PREFIX))
            .collect();
        assert_eq!(tcat, ["tcat:video,movie,4k"]);
    }

    #[test]
    fn parses_multiple_tcat_tags_flattened() {
        // An upstream encoder might emit one `i tcat:<x>` per category;
        // the parser must flatten them just the same.
        let event = EventBuilder::new(Kind::TORRENT, "body")
            .tags(Tags::from_vec(vec![
                Tag::title("T"),
                Tag::with(
                    &info_hash_kind(),
                    ["0123456789abcdef0123456789abcdef01234567"],
                ),
                Tag::i("tcat:video"),
                Tag::i("tcat:movie"),
            ]))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Torrent::from_event(&event).unwrap();
        assert_eq!(parsed.categories, ["video", "movie"]);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        let err = Torrent::from_event(&event).unwrap_err();
        assert!(matches!(
            err,
            TorrentError::UnexpectedKind {
                expected: 2_003,
                got: 1
            }
        ));
    }

    #[test]
    fn missing_title_is_rejected() {
        let event = EventBuilder::new(Kind::TORRENT, "body")
            .tag(Tag::with(
                &info_hash_kind(),
                ["0123456789abcdef0123456789abcdef01234567"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Torrent::from_event(&event).unwrap_err(),
            TorrentError::MissingTitle
        ));
    }

    #[test]
    fn missing_info_hash_is_rejected() {
        let event = EventBuilder::new(Kind::TORRENT, "body")
            .tag(Tag::title("T"))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Torrent::from_event(&event).unwrap_err(),
            TorrentError::MissingInfoHash
        ));
    }

    #[test]
    fn invalid_file_size_is_rejected() {
        let event = EventBuilder::new(Kind::TORRENT, "body")
            .tags(Tags::from_vec(vec![
                Tag::title("T"),
                Tag::with(
                    &info_hash_kind(),
                    ["0123456789abcdef0123456789abcdef01234567"],
                ),
                Tag::with(&file_kind(), ["info/a.mkv", "not-a-number"]),
            ]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Torrent::from_event(&event).unwrap_err(),
            TorrentError::InvalidFileSize
        ));
    }

    #[test]
    fn torrent_comment_follows_nip10() {
        let torrent_event = sample().to_event_builder().sign_with_keys(&keys()).unwrap();
        let comment = EventBuilder::torrent_comment("nice release", &torrent_event)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(comment.kind, Kind::TORRENT_COMMENT);

        let e_tag = comment.tags.find_letter(Alphabet::E).next().unwrap();
        assert_eq!(e_tag.get(1), Some(torrent_event.id.to_hex().as_str()));
        assert_eq!(e_tag.get(3), Some("root"));

        let p_tag = comment.tags.find_letter(Alphabet::P).next().unwrap();
        assert_eq!(
            p_tag.content(),
            Some(torrent_event.pubkey.to_hex().as_str())
        );
    }
}
