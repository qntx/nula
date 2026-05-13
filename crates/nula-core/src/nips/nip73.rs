//! [NIP-73] External Content IDs.
//!
//! Maps the spec's external-ID table to typed Rust variants. Every
//! variant pairs an [`ExternalContentId`] (rendered to the `i` tag)
//! with an [`ExternalContentKind`] (rendered to the matching `k`
//! tag). The full coverage tracks the spec table verbatim:
//!
//! | Type                   | `i` tag                                                    | `k` tag                  |
//! | ---                    | ---                                                        | ---                      |
//! | URLs                   | "`<URL, normalized, no fragment>`"                         | "web"                    |
//! | Books                  | "isbn:`<id, without hyphens>`"                             | "isbn"                   |
//! | Geohashes              | "geo:`<geohash, lowercase>`"                               | "geo"                    |
//! | Countries              | "iso3166:`<code, uppercase>`"                              | "iso3166"                |
//! | Movies                 | "isan:`<id, without version part>`"                        | "isan"                   |
//! | Papers                 | "doi:`<id, lowercase>`"                                    | "doi"                    |
//! | Hashtags               | "#`<topic, lowercase>`"                                    | "#"                      |
//! | Podcast Feeds          | "podcast:guid:`<guid>`"                                    | "podcast:guid"           |
//! | Podcast Episodes       | "podcast:item:guid:`<guid>`"                               | "podcast:item:guid"      |
//! | Podcast Publishers     | "podcast:publisher:guid:`<guid>`"                          | "podcast:publisher:guid" |
//! | Blockchain Transaction | "`<blockchain>`:\[`<chainId>`:\]tx:`<txid, hex, lowercase>`" | "`<blockchain>`:tx"      |
//! | Blockchain Address     | "`<blockchain>`:\[`<chainId>`:\]address:`<address>`"         | "`<blockchain>`:address" |
//!
//! [`ExternalContentRef`] groups the parsed `i` tag with its
//! optional URL hint (per spec §"Optional URL Hints"). The reader
//! [`refs_from_tags`] walks any event's tag list and emits a typed
//! list, while the writer extension on [`Tag`] makes the right
//! `i`/`k` tag pair in one call.
//!
//! [NIP-73]: https://github.com/nostr-protocol/nips/blob/master/73.md

use core::fmt;

use thiserror::Error;

use crate::event::{Alphabet, SingleLetterTag, Tag, TagKind, Tags};
use crate::types::{Url, UrlError};

const HASHTAG: &str = "#";
const GEOHASH: &str = "geo:";
const BOOK: &str = "isbn:";
const COUNTRY: &str = "iso3166:";
const MOVIE: &str = "isan:";
const PAPER: &str = "doi:";
const PODCAST_FEED: &str = "podcast:guid:";
const PODCAST_EPISODE: &str = "podcast:item:guid:";
const PODCAST_PUBLISHER: &str = "podcast:publisher:guid:";
const TX_SEP: &str = ":tx:";
const ADDR_SEP: &str = ":address:";

/// Typed external-ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternalContentId {
    /// `web` — normalised URL.
    Url(Url),
    /// `isbn:<id>` — book ISBN without hyphens.
    Book(String),
    /// `geo:<geohash>` — lowercase geohash.
    Geohash(String),
    /// `iso3166:<code>` — uppercase ISO 3166-1/2 country/subdivision.
    Country(String),
    /// `isan:<id>` — ISAN without the version part.
    Movie(String),
    /// `doi:<id>` — lowercase DOI.
    Paper(String),
    /// `#<topic>` — lowercase hashtag.
    Hashtag(String),
    /// `podcast:guid:<guid>`.
    PodcastFeed(String),
    /// `podcast:item:guid:<guid>`.
    PodcastEpisode(String),
    /// `podcast:publisher:guid:<guid>`.
    PodcastPublisher(String),
    /// `<chain>:[<chain_id>:]tx:<txid>`.
    BlockchainTransaction {
        /// Blockchain name, e.g. `bitcoin`, `ethereum`.
        chain: String,
        /// Optional chain id, e.g. `1` for Ethereum mainnet.
        chain_id: Option<String>,
        /// Lowercase hex transaction id (spec mandates lowercase but
        /// the parser does not enforce it — callers may want to).
        txid: String,
    },
    /// `<chain>:[<chain_id>:]address:<address>`.
    BlockchainAddress {
        /// Blockchain name.
        chain: String,
        /// Optional chain id.
        chain_id: Option<String>,
        /// On-chain address (chain-specific case rules apply).
        address: String,
    },
}

impl fmt::Display for ExternalContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(url) => f.write_str(url.as_str()),
            Self::Book(id) => write!(f, "{BOOK}{id}"),
            Self::Geohash(id) => write!(f, "{GEOHASH}{id}"),
            Self::Country(code) => write!(f, "{COUNTRY}{code}"),
            Self::Movie(id) => write!(f, "{MOVIE}{id}"),
            Self::Paper(id) => write!(f, "{PAPER}{id}"),
            Self::Hashtag(t) => write!(f, "{HASHTAG}{t}"),
            Self::PodcastFeed(guid) => write!(f, "{PODCAST_FEED}{guid}"),
            Self::PodcastEpisode(guid) => write!(f, "{PODCAST_EPISODE}{guid}"),
            Self::PodcastPublisher(guid) => write!(f, "{PODCAST_PUBLISHER}{guid}"),
            Self::BlockchainTransaction {
                chain,
                chain_id,
                txid,
            } => match chain_id {
                Some(id) => write!(f, "{chain}:{id}{TX_SEP}{txid}"),
                None => write!(f, "{chain}{TX_SEP}{txid}"),
            },
            Self::BlockchainAddress {
                chain,
                chain_id,
                address,
            } => match chain_id {
                Some(id) => write!(f, "{chain}:{id}{ADDR_SEP}{address}"),
                None => write!(f, "{chain}{ADDR_SEP}{address}"),
            },
        }
    }
}

impl ExternalContentId {
    /// Parse a wire-form external content id.
    ///
    /// Falls back to [`Self::Url`] only for inputs that successfully
    /// parse as a `Url` to avoid accidentally swallowing garbage.
    ///
    /// # Errors
    ///
    /// Returns [`ExternalContentError::Unrecognised`] when no known
    /// prefix matches and the input is not a valid URL.
    pub fn parse(input: &str) -> Result<Self, ExternalContentError> {
        if let Some(rest) = input.strip_prefix(HASHTAG) {
            return Ok(Self::Hashtag(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(GEOHASH) {
            return Ok(Self::Geohash(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(BOOK) {
            return Ok(Self::Book(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(COUNTRY) {
            return Ok(Self::Country(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(MOVIE) {
            return Ok(Self::Movie(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(PAPER) {
            return Ok(Self::Paper(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(PODCAST_PUBLISHER) {
            return Ok(Self::PodcastPublisher(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(PODCAST_EPISODE) {
            return Ok(Self::PodcastEpisode(rest.to_owned()));
        }
        if let Some(rest) = input.strip_prefix(PODCAST_FEED) {
            return Ok(Self::PodcastFeed(rest.to_owned()));
        }
        if let Some((head, txid)) = input.split_once(TX_SEP) {
            let (chain, chain_id) = split_chain(head);
            return Ok(Self::BlockchainTransaction {
                chain,
                chain_id,
                txid: txid.to_owned(),
            });
        }
        if let Some((head, address)) = input.split_once(ADDR_SEP) {
            let (chain, chain_id) = split_chain(head);
            return Ok(Self::BlockchainAddress {
                chain,
                chain_id,
                address: address.to_owned(),
            });
        }
        Url::parse(input).map_or_else(
            |_| Err(ExternalContentError::Unrecognised(input.to_owned())),
            |url| Ok(Self::Url(url)),
        )
    }

    /// Return the matching [`ExternalContentKind`] for this id.
    #[must_use]
    pub fn kind(&self) -> ExternalContentKind {
        match self {
            Self::Url(_) => ExternalContentKind::Url,
            Self::Book(_) => ExternalContentKind::Book,
            Self::Geohash(_) => ExternalContentKind::Geohash,
            Self::Country(_) => ExternalContentKind::Country,
            Self::Movie(_) => ExternalContentKind::Movie,
            Self::Paper(_) => ExternalContentKind::Paper,
            Self::Hashtag(_) => ExternalContentKind::Hashtag,
            Self::PodcastFeed(_) => ExternalContentKind::PodcastFeed,
            Self::PodcastEpisode(_) => ExternalContentKind::PodcastEpisode,
            Self::PodcastPublisher(_) => ExternalContentKind::PodcastPublisher,
            Self::BlockchainTransaction { chain, .. } => {
                ExternalContentKind::BlockchainTransaction(chain.clone())
            }
            Self::BlockchainAddress { chain, .. } => {
                ExternalContentKind::BlockchainAddress(chain.clone())
            }
        }
    }
}

fn split_chain(head: &str) -> (String, Option<String>) {
    match head.split_once(':') {
        None => (head.to_owned(), None),
        Some((chain, "")) => (chain.to_owned(), None),
        Some((chain, chain_id)) => (chain.to_owned(), Some(chain_id.to_owned())),
    }
}

/// Companion enum for the `k` tag value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternalContentKind {
    /// `web`.
    Url,
    /// `isbn`.
    Book,
    /// `geo`.
    Geohash,
    /// `iso3166`.
    Country,
    /// `isan`.
    Movie,
    /// `doi`.
    Paper,
    /// `#`.
    Hashtag,
    /// `podcast:guid`.
    PodcastFeed,
    /// `podcast:item:guid`.
    PodcastEpisode,
    /// `podcast:publisher:guid`.
    PodcastPublisher,
    /// `<chain>:tx`.
    BlockchainTransaction(String),
    /// `<chain>:address`.
    BlockchainAddress(String),
}

impl fmt::Display for ExternalContentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => f.write_str("web"),
            Self::Book => f.write_str("isbn"),
            Self::Geohash => f.write_str("geo"),
            Self::Country => f.write_str("iso3166"),
            Self::Movie => f.write_str("isan"),
            Self::Paper => f.write_str("doi"),
            Self::Hashtag => f.write_str("#"),
            Self::PodcastFeed => f.write_str("podcast:guid"),
            Self::PodcastEpisode => f.write_str("podcast:item:guid"),
            Self::PodcastPublisher => f.write_str("podcast:publisher:guid"),
            Self::BlockchainTransaction(chain) => write!(f, "{chain}:tx"),
            Self::BlockchainAddress(chain) => write!(f, "{chain}:address"),
        }
    }
}

impl ExternalContentKind {
    /// Parse a wire-form `k` value.
    ///
    /// # Errors
    ///
    /// Returns [`ExternalContentError::UnknownKind`] when the token
    /// does not match any documented kind.
    pub fn parse(input: &str) -> Result<Self, ExternalContentError> {
        match input {
            "web" => Ok(Self::Url),
            "isbn" => Ok(Self::Book),
            "geo" => Ok(Self::Geohash),
            "iso3166" => Ok(Self::Country),
            "isan" => Ok(Self::Movie),
            "doi" => Ok(Self::Paper),
            "#" => Ok(Self::Hashtag),
            "podcast:guid" => Ok(Self::PodcastFeed),
            "podcast:item:guid" => Ok(Self::PodcastEpisode),
            "podcast:publisher:guid" => Ok(Self::PodcastPublisher),
            other => other
                .strip_suffix(":tx")
                .map(|chain| Self::BlockchainTransaction(chain.to_owned()))
                .or_else(|| {
                    other
                        .strip_suffix(":address")
                        .map(|chain| Self::BlockchainAddress(chain.to_owned()))
                })
                .ok_or_else(|| ExternalContentError::UnknownKind(other.to_owned())),
        }
    }
}

/// An `i` tag pair: the typed id plus its optional URL hint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalContentRef {
    /// Parsed external-id payload.
    pub id: ExternalContentId,
    /// Optional URL hint (spec §"Optional URL Hints").
    pub url_hint: Option<Url>,
}

impl ExternalContentRef {
    /// Construct a reference without a URL hint.
    #[must_use]
    pub const fn new(id: ExternalContentId) -> Self {
        Self { id, url_hint: None }
    }

    /// Attach a URL hint.
    #[must_use]
    pub fn with_url_hint(mut self, hint: Url) -> Self {
        self.url_hint = Some(hint);
        self
    }
}

/// Read all NIP-73 external-id pairs out of `tags`.
///
/// Walks the tag list once and pairs every `i` tag with the
/// *first* compatible `k` tag that has not yet been consumed. If
/// an `i` tag has no companion `k` tag the entry is still surfaced
/// (its kind is derivable via [`ExternalContentId::kind`]).
///
/// # Errors
///
/// Bubbles up parser errors from individual tags.
pub fn refs_from_tags(tags: &Tags) -> Result<Vec<ExternalContentRef>, ExternalContentError> {
    let mut out: Vec<ExternalContentRef> = Vec::new();
    for tag in tags {
        let TagKind::SingleLetter(letter) = tag.kind() else {
            continue;
        };
        if letter.uppercase || letter.character != Alphabet::I {
            continue;
        }
        let raw = tag.get(1).ok_or(ExternalContentError::MalformedTag)?;
        let id = ExternalContentId::parse(raw)?;
        let url_hint = match tag.get(2) {
            Some(hint) if !hint.is_empty() => Some(Url::parse(hint)?),
            _ => None,
        };
        out.push(ExternalContentRef { id, url_hint });
    }
    Ok(out)
}

/// Build the canonical `["i", ...]` + `["k", ...]` tag pair for a
/// reference.
#[must_use]
pub fn ref_to_tags(reference: &ExternalContentRef) -> [Tag; 2] {
    let kind = reference.id.kind();
    let head_i = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::I));
    let head_k = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::K));
    let i_tag = reference.url_hint.as_ref().map_or_else(
        || Tag::with(&head_i, [reference.id.to_string()]),
        |url| Tag::with(&head_i, [reference.id.to_string(), url.as_str().to_owned()]),
    );
    let k_tag = Tag::with(&head_k, [kind.to_string()]);
    [i_tag, k_tag]
}

/// Errors raised by [`ExternalContentId::parse`] / [`refs_from_tags`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExternalContentError {
    /// The `i` tag had no payload column.
    #[error("`i` tag missing payload column")]
    MalformedTag,
    /// The wire-form id matched no known prefix and was not a valid URL.
    #[error("unrecognised external content id: `{0}`")]
    Unrecognised(String),
    /// The `k` tag value did not match any known kind.
    #[error("unknown NIP-73 kind: `{0}`")]
    UnknownKind(String),
    /// A URL hint failed to parse.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_round_trip() {
        let id = ExternalContentId::parse("https://example.com/post").unwrap();
        assert!(matches!(id, ExternalContentId::Url(_)));
        assert_eq!(id.kind().to_string(), "web");
    }

    #[test]
    fn book_round_trip() {
        let id = ExternalContentId::parse("isbn:9780765382030").unwrap();
        assert_eq!(id, ExternalContentId::Book("9780765382030".to_owned()));
        assert_eq!(id.to_string(), "isbn:9780765382030");
        assert_eq!(id.kind(), ExternalContentKind::Book);
    }

    #[test]
    fn country_round_trip() {
        let id = ExternalContentId::parse("iso3166:US-CA").unwrap();
        assert_eq!(id, ExternalContentId::Country("US-CA".to_owned()));
        assert_eq!(id.kind(), ExternalContentKind::Country);
    }

    #[test]
    fn geohash_round_trip() {
        let id = ExternalContentId::parse("geo:u4pruydqqvj").unwrap();
        assert_eq!(id, ExternalContentId::Geohash("u4pruydqqvj".to_owned()));
    }

    #[test]
    fn hashtag_round_trip() {
        let id = ExternalContentId::parse("#rust").unwrap();
        assert_eq!(id, ExternalContentId::Hashtag("rust".to_owned()));
        assert_eq!(id.kind(), ExternalContentKind::Hashtag);
    }

    #[test]
    fn podcast_publisher_takes_precedence_over_episode_and_feed() {
        let publisher = ExternalContentId::parse("podcast:publisher:guid:abc").unwrap();
        assert_eq!(
            publisher,
            ExternalContentId::PodcastPublisher("abc".to_owned()),
        );
        let episode = ExternalContentId::parse("podcast:item:guid:abc").unwrap();
        assert_eq!(episode, ExternalContentId::PodcastEpisode("abc".to_owned()));
        let feed = ExternalContentId::parse("podcast:guid:abc").unwrap();
        assert_eq!(feed, ExternalContentId::PodcastFeed("abc".to_owned()));
    }

    #[test]
    fn blockchain_tx_without_chain_id() {
        let id = ExternalContentId::parse("bitcoin:tx:abcd").unwrap();
        assert_eq!(
            id,
            ExternalContentId::BlockchainTransaction {
                chain: "bitcoin".to_owned(),
                chain_id: None,
                txid: "abcd".to_owned(),
            },
        );
        assert_eq!(id.to_string(), "bitcoin:tx:abcd");
        assert_eq!(
            id.kind(),
            ExternalContentKind::BlockchainTransaction("bitcoin".to_owned()),
        );
    }

    #[test]
    fn blockchain_tx_with_chain_id() {
        let id = ExternalContentId::parse("ethereum:1:tx:0xabc").unwrap();
        assert_eq!(
            id,
            ExternalContentId::BlockchainTransaction {
                chain: "ethereum".to_owned(),
                chain_id: Some("1".to_owned()),
                txid: "0xabc".to_owned(),
            },
        );
        assert_eq!(id.to_string(), "ethereum:1:tx:0xabc");
    }

    #[test]
    fn blockchain_address_round_trip() {
        let id = ExternalContentId::parse(
            "ethereum:100:address:0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
        )
        .unwrap();
        assert_eq!(
            id,
            ExternalContentId::BlockchainAddress {
                chain: "ethereum".to_owned(),
                chain_id: Some("100".to_owned()),
                address: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045".to_owned(),
            },
        );
    }

    #[test]
    fn kind_parse_round_trip() {
        for k in [
            "web",
            "isbn",
            "geo",
            "iso3166",
            "isan",
            "doi",
            "#",
            "podcast:guid",
            "podcast:item:guid",
            "podcast:publisher:guid",
        ] {
            assert_eq!(ExternalContentKind::parse(k).unwrap().to_string(), k);
        }
        assert_eq!(
            ExternalContentKind::parse("bitcoin:tx").unwrap(),
            ExternalContentKind::BlockchainTransaction("bitcoin".to_owned()),
        );
        assert_eq!(
            ExternalContentKind::parse("ethereum:address").unwrap(),
            ExternalContentKind::BlockchainAddress("ethereum".to_owned()),
        );
    }

    #[test]
    fn unrecognised_kind_errors() {
        assert!(matches!(
            ExternalContentKind::parse("unknown"),
            Err(ExternalContentError::UnknownKind(_)),
        ));
    }

    #[test]
    fn ref_to_tags_emits_i_and_k_pair() {
        let r = ExternalContentRef::new(ExternalContentId::Book("9780306406157".to_owned()))
            .with_url_hint(Url::parse("https://openlibrary.org/").unwrap());
        let [i_tag, k_tag] = ref_to_tags(&r);
        assert_eq!(i_tag.get(0), Some("i"));
        assert_eq!(i_tag.get(1), Some("isbn:9780306406157"));
        assert_eq!(i_tag.get(2), Some("https://openlibrary.org/"));
        assert_eq!(k_tag.get(0), Some("k"));
        assert_eq!(k_tag.get(1), Some("isbn"));
    }

    #[test]
    fn refs_from_tags_reads_event_tags() {
        use crate::EventBuilder;
        use crate::Keys;

        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
        let r = ExternalContentRef::new(ExternalContentId::Hashtag("rust".to_owned()));
        let [i_tag, k_tag] = ref_to_tags(&r);
        let event = EventBuilder::text_note("hi")
            .tag(i_tag)
            .tag(k_tag)
            .sign_with_keys(&keys)
            .unwrap();
        let refs = refs_from_tags(&event.tags).unwrap();
        assert_eq!(refs, vec![r]);
    }

    #[test]
    fn unrecognised_input_errors() {
        assert!(matches!(
            ExternalContentId::parse("not-a-url-or-prefix"),
            Err(ExternalContentError::Unrecognised(_)),
        ));
    }
}
