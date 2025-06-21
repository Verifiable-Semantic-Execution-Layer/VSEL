//! Integration test harness for property-based Pipeline tests.
//!
//! The canonical test source lives at `protocol/tests/property/pipeline_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-engine` picks it up.

#[path = "../../../tests/property/pipeline_tests.rs"]
mod pipeline_tests;
