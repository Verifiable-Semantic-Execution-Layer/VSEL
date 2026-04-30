//! Integration test harness for LEM-4/LEM-5 constraint soundness/completeness tests.
//!
//! The canonical test source lives at `protocol/tests/property/constraint_soundness_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-constraints` picks it up.

#[path = "../../../tests/property/constraint_soundness_tests.rs"]
mod constraint_soundness_tests;
