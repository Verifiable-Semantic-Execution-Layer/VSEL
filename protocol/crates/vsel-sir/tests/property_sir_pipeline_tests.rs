//! Integration test harness for property-based SIR pipeline tests.
//!
//! The canonical test source lives at `protocol/tests/property/sir_pipeline_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-sir` picks it up.

#[path = "../../../tests/property/sir_pipeline_tests.rs"]
mod sir_pipeline_tests;
