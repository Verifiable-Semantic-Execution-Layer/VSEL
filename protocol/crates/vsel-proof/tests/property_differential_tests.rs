//! Integration test harness for differential backend property tests.
//!
//! The canonical test source lives at `protocol/tests/property/differential_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof` picks it up.
//!
//! Requires `plonky3-backend` feature: both HashBackend and Plonky3Backend
//! must be available for differential comparison.

#[path = "../../../tests/property/differential_tests.rs"]
mod differential_tests;
