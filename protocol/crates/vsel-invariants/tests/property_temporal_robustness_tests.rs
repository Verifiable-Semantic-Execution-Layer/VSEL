//! Integration test harness for property-based Temporal Robustness tests.
//!
//! The canonical test source lives at `protocol/tests/property/temporal_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-invariants --test property_temporal_robustness_tests` picks it up.

#[path = "../../../tests/property/temporal_tests.rs"]
mod temporal_tests;
