//! Integration test harness for property-based Verifier tests.
//!
//! The canonical test source lives at `protocol/tests/property/verifier_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof` picks it up.

#[path = "../../../tests/property/verifier_tests.rs"]
mod verifier_tests;
