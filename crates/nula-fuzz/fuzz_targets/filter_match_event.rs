//! Filter parsing + matching fuzz target.
//!
//! Two properties under test:
//!
//! 1. `Filter` JSON parsing is round-trip stable. A successfully-parsed
//!    filter must serialise back to JSON that re-parses to the same
//!    value (and the second serialisation must be byte-identical).
//!
//! 2. `Filter::match_event` MUST NOT panic on any (filter, event) combo
//!    \u2014 a relay or client matcher must always return a `bool`, never
//!    overflow / index-OOB / underflow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::event::Event;
use nula_core::filter::{Filter, MatchEventOptions};

fuzz_target!(|data: &[u8]| {
    // Split the corpus into two halves: one for the filter, one for
    // the candidate event. Splitting on the first 0xFF byte keeps the
    // boundary easy for libFuzzer to mutate around.
    let split = data.iter().position(|&b| b == 0xff).unwrap_or(data.len());
    let (filter_bytes, event_bytes) = data.split_at(split);
    let event_bytes = event_bytes.get(1..).unwrap_or(&[]);

    if let Ok(filter) = serde_json::from_slice::<Filter>(filter_bytes) {
        // Round-trip: serialise, re-parse, assert equality, and verify
        // that the second serialisation is byte-identical to the first
        // (catches non-deterministic IndexMap ordering bugs).
        let json_a = serde_json::to_vec(&filter).expect("Filter must always serialise");
        let parsed = serde_json::from_slice::<Filter>(&json_a)
            .expect("Filter serialisation must round-trip");
        assert_eq!(filter, parsed, "Filter round-trip diverged");
        let json_b = serde_json::to_vec(&parsed).expect("Filter must always re-serialise");
        assert_eq!(json_a, json_b, "Filter serialisation is non-deterministic");

        if let Ok(event) = serde_json::from_slice::<Event>(event_bytes) {
            // The matcher must never panic, regardless of the input.
            let _ = filter.match_event(&event, MatchEventOptions::default());
        }
    }
});
