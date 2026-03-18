//! Integration test harness for property-based cryptographic tests.
//!
//! The canonical test source lives at `protocol/tests/property/crypto_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-crypto` picks it up.

#[path = "../../../tests/property/crypto_tests.rs"]
mod crypto_tests;
