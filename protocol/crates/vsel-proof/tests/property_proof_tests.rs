//! Integration test harness for property-based Proof System tests.
//!
//! The canonical test source lives at `protocol/tests/property/proof_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof` picks it up.

#[path = "../../../tests/property/proof_tests.rs"]
mod proof_tests;
