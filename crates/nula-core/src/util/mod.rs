// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Utility helpers shared by every other `nula-core` module.
//!
//! The submodules are deliberately minimal and stateless. They form the very
//! bottom of the protocol stack: every higher level depends on them, but they
//! depend on nothing internal to `nula-core`.

pub mod hex;
pub mod json;
pub mod rng;

pub use self::hex::HexError;
pub use self::json::JsonUtil;
pub use self::rng::RngError;
