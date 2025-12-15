//! Integration test harness for property-based Constraint Compiler tests.
//!
//! The canonical test source lives at `protocol/tests/property/constraint_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-constraints` picks it up.

#[path = "../../../tests/property/constraint_tests.rs"]
mod constraint_tests;
