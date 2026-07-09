//! [NIP-64] Chess (Portable Game Notation).
//!
//! `kind: 64` notes carry a chess game (or a whole PGN database) as
//! plain [PGN] text in `.content`. Clients SHOULD publish in strict
//! *export format* but accept lax *import format*; a full PGN parser
//! is application territory, so this module only enforces the shape
//! the NIP itself pins down: a non-empty PGN payload on the right
//! kind, plus the recommended NIP-31 `alt` fallback for
//! non-supporting clients.
//!
//! [NIP-64]: https://github.com/nostr-protocol/nips/blob/master/64.md
//! [PGN]: https://github.com/mliebelt/pgn-spec-commented/blob/main/pgn-specification.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag};
use crate::nips::nip31;

/// `kind: 64` — chess game (PGN).
pub const KIND_CHESS: Kind = Kind::CHESS;

/// Typed bundle for a `kind: 64` chess-game event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChessGame {
    /// PGN payload mirrored from `.content`.
    pub pgn: String,
    /// Optional NIP-31 `alt` description for non-supporting clients.
    pub alt: Option<String>,
}

/// Errors raised while parsing a NIP-64 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChessError {
    /// Event kind is not `64`.
    #[error("unexpected kind for NIP-64 chess game: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `.content` is empty — even an unknown game is `*` in PGN.
    #[error("NIP-64 content is empty")]
    EmptyPgn,
}

impl ChessGame {
    /// Construct a chess game from PGN text.
    ///
    /// # Errors
    ///
    /// Returns [`ChessError::EmptyPgn`] when `pgn` is empty or
    /// whitespace-only.
    pub fn new(pgn: impl Into<String>) -> Result<Self, ChessError> {
        let pgn = pgn.into();
        if pgn.trim().is_empty() {
            return Err(ChessError::EmptyPgn);
        }
        Ok(Self { pgn, alt: None })
    }

    /// Attach an `alt` description (NIP-31).
    #[must_use]
    pub fn with_alt(mut self, alt: impl Into<String>) -> Self {
        self.alt = Some(alt.into());
        self
    }

    /// Parse a `kind: 64` chess-game event.
    ///
    /// # Errors
    ///
    /// See [`ChessError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, ChessError> {
        if event.kind != KIND_CHESS {
            return Err(ChessError::WrongKind(event.kind));
        }
        if event.content.trim().is_empty() {
            return Err(ChessError::EmptyPgn);
        }
        Ok(Self {
            pgn: event.content.clone(),
            alt: nip31::alt_description(&event.tags).map(str::to_owned),
        })
    }
}

impl EventBuilder {
    /// Author a NIP-64 `kind: 64` chess-game event.
    #[must_use]
    pub fn chess_game(game: &ChessGame) -> Self {
        let mut builder = Self::new(KIND_CHESS, game.pgn.clone());
        if let Some(alt) = &game.alt {
            builder = builder.tag(Tag::alt(alt.clone()));
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn round_trip() {
        let game = ChessGame::new("1. e4 *")
            .unwrap()
            .with_alt("A game that opens with e4");
        let event = EventBuilder::chess_game(&game)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ChessGame::from_event(&event).unwrap();
        assert_eq!(parsed, game);
    }

    #[test]
    fn full_pgn_round_trip() {
        let pgn = "[White \"Fischer, Robert J.\"]\n[Black \"Spassky, Boris V.\"]\n\n1. e4 e5 *";
        let game = ChessGame::new(pgn).unwrap();
        let event = EventBuilder::chess_game(&game)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(ChessGame::from_event(&event).unwrap().pgn, pgn);
    }

    #[test]
    fn empty_pgn_is_rejected() {
        assert!(matches!(ChessGame::new("  "), Err(ChessError::EmptyPgn)));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("1. e4 *")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ChessGame::from_event(&event),
            Err(ChessError::WrongKind(_))
        ));
    }
}
