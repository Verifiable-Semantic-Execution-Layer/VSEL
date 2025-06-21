//! Integration test harness for property-based Guard System tests.
//!
//! The canonical test source lives at `protocol/tests/property/guard_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-engine` picks it up.

#[path = "../../../tests/property/guard_tests.rs"]
mod guard_tests;
