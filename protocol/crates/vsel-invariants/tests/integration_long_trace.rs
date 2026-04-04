//! Integration test harness for long trace simulation.
//!
//! The canonical test source lives at `protocol/tests/integration/long_trace.rs`.
//! This file includes it as a module so `cargo test -p vsel-invariants --test integration_long_trace` picks it up.

#[path = "../../../tests/integration/long_trace.rs"]
mod long_trace;
