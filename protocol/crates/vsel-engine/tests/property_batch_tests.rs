//! Integration test harness for property-based batch processing tests.
//!
//! The canonical test source lives at `protocol/tests/property/batch_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-engine` picks it up.

#[path = "../../../tests/property/batch_tests.rs"]
mod batch_tests;
