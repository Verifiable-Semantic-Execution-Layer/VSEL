//! Integration test harness for property-based Execution Engine tests.
//!
//! The canonical test source lives at `protocol/tests/property/engine_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-engine` picks it up.

#[path = "../../../tests/property/engine_tests.rs"]
mod engine_tests;
