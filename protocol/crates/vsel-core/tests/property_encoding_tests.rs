//! Integration test harness for property-based encoding tests.
//!
//! The canonical test source lives at `protocol/tests/property/encoding_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-core` picks it up.

#[path = "../../../tests/property/encoding_tests.rs"]
mod encoding_tests;
