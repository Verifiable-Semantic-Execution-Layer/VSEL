//! Integration test harness for property-based Invariant system tests.
//!
//! The canonical test source lives at `protocol/tests/property/invariant_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-invariants` picks it up.

#[path = "../../../tests/property/invariant_tests.rs"]
mod invariant_tests;
