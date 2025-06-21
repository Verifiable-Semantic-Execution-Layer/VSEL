//! Integration test harness for property-based Trace Engine tests.
//!
//! The canonical test source lives at `protocol/tests/property/trace_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-trace` picks it up.

#[path = "../../../tests/property/trace_tests.rs"]
mod trace_tests;
