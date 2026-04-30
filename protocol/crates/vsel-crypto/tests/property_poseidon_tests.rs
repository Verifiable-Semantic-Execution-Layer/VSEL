//! Integration test harness for property-based Poseidon domain separation tests.
//!
//! The canonical test source lives at `protocol/tests/property/poseidon_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-crypto` picks it up.

#[path = "../../../tests/property/poseidon_tests.rs"]
mod poseidon_tests;
