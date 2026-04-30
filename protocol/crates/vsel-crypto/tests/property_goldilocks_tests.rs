//! Integration test harness for property-based Goldilocks field arithmetic tests.
//!
//! The canonical test source lives at `protocol/tests/property/goldilocks_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-crypto` picks it up.

#[path = "../../../tests/property/goldilocks_tests.rs"]
mod goldilocks_tests;
