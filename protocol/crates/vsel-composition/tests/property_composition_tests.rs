//! Integration test harness for property-based composition tests.
//!
//! The canonical test source lives at `protocol/tests/property/composition_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-composition` picks it up.

#[path = "../../../tests/property/composition_tests.rs"]
mod composition_tests;
