//! [NIP-39] External Identities in Profiles.
//!
//! NIP-39 lets a Nostr user attest control over an account on another
//! platform (GitHub, Twitter, Mastodon, Telegram, …) via an `i` tag:
//!
//! ```jsonc
//! ["i", "<platform>:<identity>", "<proof>"]
//! ```
//!
//! Spec 32§"Clients SHOULD process any `i` tags with more than 2
//! values for future extensibility" forces a *forward-compatible*
//! decoder: an unknown platform name MUST round-trip through this
//! crate without erroring out, otherwise a client running an older
//! `nula-core` would silently drop new identities authored by a
//! newer client. This module models the openness via
//! [`ExternalPlatform::Other`].
//!
//! # Authoring vs reading
//!
//! - Author with [`Tag::external_identity`] (added by this module on
//!   the [`Tag`] type) which canonicalises the
//!   `<platform>:<identity>` join.
//! - Read with [`identities_from_tags`] which yields every
//!   well-formed `i` tag while ignoring NIP-73 external content
//!   identifiers (the same `i` head is shared but those carry only
//!   one value vs NIP-39's two-or-more).
//!
//! # Differentiation from upstream
//!
//! `rust-nostr/nostr@master` closes [`ExternalPlatform`] as an enum
//! that returns `Err(InvalidIdentity)` for any platform it doesn't
//! know. That is incorrect per the NIP-39 forward-compat rule. We
//! keep the well-known variants as constants but accept arbitrary
//! platform names through [`ExternalPlatform::Other`] and let
//! callers match on the variant when they care.
//!
//! [NIP-39]: https://github.com/nostr-protocol/nips/blob/master/39.md

use thiserror::Error;

use crate::event::{Alphabet, SingleLetterTag, Tag, TagKind, Tags};

/// External identity provider.
///
/// Well-known platforms have dedicated variants so pattern-matching
/// is concise; unknown ones are preserved verbatim through
/// [`Self::Other`] to honour NIP-39's "SHOULD process any i tags
/// with more than 2 values for future extensibility".
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ExternalPlatform {
    /// `github` — proof is a Gist id under the same username.
    GitHub,
    /// `twitter` — proof is a tweet id under the same handle.
    Twitter,
    /// `mastodon` — identity carries `<instance>/@<username>`; proof
    /// is a status id on that instance.
    Mastodon,
    /// `telegram` — proof is `<channel>/<message-id>`.
    Telegram,
    /// Any other platform name. Per NIP-39 §31 the name MAY contain
    /// `a-z`, `0-9`, and `._-/` and MUST NOT contain `:`. The
    /// constructor [`ExternalPlatform::parse`] enforces that.
    Other(String),
}

/// Errors raised when constructing external identities.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Nip39Error {
    /// The platform identifier was empty.
    #[error("platform name must not be empty")]
    EmptyPlatform,
    /// The platform identifier contained the `:` separator.
    #[error("platform name must not contain ':' ; got `{0}`")]
    PlatformContainsColon(String),
    /// The full `platform:identity` value did not contain a `:`.
    #[error("expected `<platform>:<identity>`, got `{0}`")]
    MissingSeparator(String),
    /// The identity portion was empty.
    #[error("identity portion of the `i` tag must not be empty")]
    EmptyIdentity,
}

impl ExternalPlatform {
    /// Parse a platform name (the part before the colon in
    /// `<platform>:<identity>`).
    ///
    /// # Errors
    ///
    /// - [`Nip39Error::EmptyPlatform`] for `""`.
    /// - [`Nip39Error::PlatformContainsColon`] when the name contains
    ///   the `:` separator (which would conflate the platform name
    ///   with the identity).
    pub fn parse(name: &str) -> Result<Self, Nip39Error> {
        if name.is_empty() {
            return Err(Nip39Error::EmptyPlatform);
        }
        if name.contains(':') {
            return Err(Nip39Error::PlatformContainsColon(name.to_owned()));
        }
        Ok(match name {
            "github" => Self::GitHub,
            "twitter" => Self::Twitter,
            "mastodon" => Self::Mastodon,
            "telegram" => Self::Telegram,
            other => Self::Other(other.to_owned()),
        })
    }

    /// Render the platform back to its canonical wire string.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::GitHub => "github",
            Self::Twitter => "twitter",
            Self::Mastodon => "mastodon",
            Self::Telegram => "telegram",
            Self::Other(name) => name.as_str(),
        }
    }
}

impl std::fmt::Display for ExternalPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single declared external identity.
///
/// Build new ones with [`Self::new`] or
/// [`Self::parse_tag_values`]; render to a [`Tag`] with
/// [`Tag::external_identity`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    /// The platform on which the user holds an account.
    pub platform: ExternalPlatform,
    /// The user's handle / id on that platform. For `mastodon`,
    /// this includes the instance host (e.g. `bitcoinhackers.org/@semisol`).
    pub ident: String,
    /// Platform-specific proof string. The shape is documented per
    /// platform in NIP-39 §"Claim types".
    pub proof: String,
}

impl Identity {
    /// Construct an identity from the canonical pieces.
    ///
    /// # Errors
    ///
    /// Returns [`Nip39Error::EmptyIdentity`] when `ident` is empty
    /// after trimming.
    pub fn new(
        platform: ExternalPlatform,
        ident: impl Into<String>,
        proof: impl Into<String>,
    ) -> Result<Self, Nip39Error> {
        let ident = ident.into();
        if ident.is_empty() {
            return Err(Nip39Error::EmptyIdentity);
        }
        Ok(Self {
            platform,
            ident,
            proof: proof.into(),
        })
    }

    /// Parse the on-the-wire pair `(platform_identity, proof)` of an
    /// `i` tag's positional arguments.
    ///
    /// `platform_identity` is the second element of the tag (the
    /// concatenated `platform:identity` form). `proof` is the third
    /// element.
    ///
    /// # Errors
    ///
    /// - [`Nip39Error::MissingSeparator`] for a `platform_identity`
    ///   without a `:`.
    /// - [`Nip39Error::PlatformContainsColon`] propagated from the
    ///   platform parser.
    /// - [`Nip39Error::EmptyIdentity`] if the part after `:` is empty.
    pub fn parse_tag_values(
        platform_identity: &str,
        proof: impl Into<String>,
    ) -> Result<Self, Nip39Error> {
        let (platform, ident) = platform_identity
            .split_once(':')
            .ok_or_else(|| Nip39Error::MissingSeparator(platform_identity.to_owned()))?;
        let platform = ExternalPlatform::parse(platform)?;
        Self::new(platform, ident, proof)
    }

    /// The canonical `platform:identity` join used in the second slot
    /// of the `i` tag.
    #[must_use]
    pub fn platform_identity(&self) -> String {
        format!("{}:{}", self.platform.as_str(), self.ident)
    }
}

impl Tag {
    /// Build a NIP-39 `i` external-identity tag.
    ///
    /// Wire form: `["i", "<platform>:<identity>", "<proof>"]`.
    ///
    /// `Tag::i` (the NIP-24 / NIP-73 external content tag) and this
    /// constructor share the same head letter on purpose — NIP-39
    /// piggybacks on NIP-24's `i` semantics. The two are
    /// distinguished by their value count: NIP-39 has at least 3
    /// (head + platform-identity + proof), NIP-24 / NIP-73 has 2 or
    /// 3 (head + external-id + optional context).
    #[must_use]
    pub fn external_identity(identity: &Identity) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::I));
        Self::with(
            &head,
            [identity.platform_identity(), identity.proof.clone()],
        )
    }
}

/// Iterate over every NIP-39 identity carried by `tags`.
///
/// Returns an iterator that:
///
/// - skips non-`i` tags;
/// - skips `i` tags that look like NIP-73 external content (only one
///   value, or no embedded `:` in the second slot);
/// - skips malformed entries (empty platform, empty identity) so
///   downstream filters keep working.
///
/// Spec-required forward compat: tags with **more than** three
/// values are still yielded — the platform / identity / proof
/// pieces are extracted and the trailing values are dropped. A
/// future NIP that tacks extra columns on the same `i` shape will
/// not regress under this reader.
pub fn identities_from_tags(tags: &Tags) -> impl Iterator<Item = Identity> + use<'_> {
    tags.iter().filter_map(|tag| {
        let TagKind::SingleLetter(s) = tag.kind() else {
            return None;
        };
        if s.character != Alphabet::I || s.uppercase {
            return None;
        }
        let values = tag.values();
        let raw_pi = values.get(1)?;
        let proof = values.get(2)?;
        Identity::parse_tag_values(raw_pi.as_str(), proof.clone()).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tag;

    #[test]
    fn well_known_platforms_round_trip_through_parse_and_display() {
        for (name, expected) in [
            ("github", ExternalPlatform::GitHub),
            ("twitter", ExternalPlatform::Twitter),
            ("mastodon", ExternalPlatform::Mastodon),
            ("telegram", ExternalPlatform::Telegram),
        ] {
            let parsed = ExternalPlatform::parse(name).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.to_string(), name);
        }
    }

    #[test]
    fn unknown_platforms_are_preserved_verbatim() {
        let exotic = ExternalPlatform::parse("matrix").unwrap();
        assert_eq!(exotic, ExternalPlatform::Other("matrix".into()));
        assert_eq!(exotic.as_str(), "matrix");
    }

    #[test]
    fn platform_parser_rejects_empty_or_colon_bearing_names() {
        assert_eq!(ExternalPlatform::parse(""), Err(Nip39Error::EmptyPlatform),);
        assert!(matches!(
            ExternalPlatform::parse("inva:lid"),
            Err(Nip39Error::PlatformContainsColon(s)) if s == "inva:lid"
        ));
    }

    #[test]
    fn identity_round_trips_through_a_tag() {
        let id = Identity::new(ExternalPlatform::GitHub, "semisol", "9721ce4ee4f").unwrap();
        let tag = Tag::external_identity(&id);
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("i"));
        assert_eq!(tag.get(1), Some("github:semisol"));
        assert_eq!(tag.get(2), Some("9721ce4ee4f"));
    }

    #[test]
    fn parse_tag_values_handles_mastodon_compound_identity() {
        // Mastodon's identity portion contains `/` and `@`, but no `:`.
        let id = Identity::parse_tag_values(
            "mastodon:bitcoinhackers.org/@semisol",
            "109775066355589974",
        )
        .unwrap();
        assert_eq!(id.platform, ExternalPlatform::Mastodon);
        assert_eq!(id.ident, "bitcoinhackers.org/@semisol");
        assert_eq!(
            id.platform_identity(),
            "mastodon:bitcoinhackers.org/@semisol"
        );
    }

    #[test]
    fn parse_tag_values_rejects_empty_identity_and_missing_separator() {
        assert!(matches!(
            Identity::parse_tag_values("github:", "proof"),
            Err(Nip39Error::EmptyIdentity)
        ));
        assert!(matches!(
            Identity::parse_tag_values("github", "proof"),
            Err(Nip39Error::MissingSeparator(s)) if s == "github"
        ));
    }

    #[test]
    fn identities_from_tags_yields_every_well_formed_entry() {
        let mut tags = Tags::new();
        tags.push(Tag::external_identity(
            &Identity::new(ExternalPlatform::GitHub, "alice", "g1").unwrap(),
        ));
        tags.push(Tag::external_identity(
            &Identity::new(ExternalPlatform::Other("matrix".into()), "@a:m.org", "p1").unwrap(),
        ));
        // NIP-73-style `i` (only 2 values) — must be ignored.
        tags.push(Tag::i("isbn:9780306406157"));
        // Malformed (no separator) — must be skipped, not crash.
        tags.push(Tag::new(["i", "no-sep-here", "proof"]).unwrap());

        let parsed: Vec<_> = identities_from_tags(&tags).collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].platform, ExternalPlatform::GitHub);
        assert_eq!(parsed[0].ident, "alice");
        assert_eq!(parsed[1].platform, ExternalPlatform::Other("matrix".into()));
    }

    #[test]
    fn forward_compat_preserves_extra_tag_columns() {
        // A future NIP could append a 4th column to `i`; our reader
        // must still extract the three known pieces.
        let mut tags = Tags::new();
        tags.push(Tag::new(["i", "github:bob", "g1", "future-extra"]).unwrap());
        let parsed: Vec<_> = identities_from_tags(&tags).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ident, "bob");
        assert_eq!(parsed[0].proof, "g1");
    }
}
