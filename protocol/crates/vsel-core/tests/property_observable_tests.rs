//! Integration test harness for property-based Observable model tests.
//!
//! The canonical test source lives at `protocol/tests/property/observable_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-core` picks it up.

#[path = "../../../tests/property/observable_tests.rs"]
mod observable_tests;
