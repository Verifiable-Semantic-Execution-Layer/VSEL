//! Integration test harness for property-based State model tests.
//!
//! The canonical test source lives at `protocol/tests/property/state_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-core` picks it up.

#[path = "../../../tests/property/state_tests.rs"]
mod state_tests;
