//! Fuzz target: SIR deserialization from arbitrary bytes.
//!
//! Accepts arbitrary bytes, attempts SIR deserialization via
//! `vsel_sir::deserialize::deserialize_program_from_bytes`.
//! Must not panic — either succeeds or returns an error.
//!
//! Requirements: 6.1(g), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use vsel_sir::deserialize_program_from_bytes;

fuzz_target!(|data: &[u8]| {
    // Attempt deserialization — must never panic.
    // Valid JSON that parses into a SirProgram is fine.
    // Invalid bytes should return Err, not panic.
    let _ = deserialize_program_from_bytes(data);
});
