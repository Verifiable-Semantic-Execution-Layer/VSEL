//! Integration test harness for property-based Semantic Mapping tests.
//!
//! The canonical test source lives at `protocol/tests/property/mapping_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-mapping` picks it up.

#[path = "../../../tests/property/mapping_tests.rs"]
mod mapping_tests;
