//! Integration test harness for property-based adversarial resilience tests.
//!
//! The canonical test source lives at `protocol/tests/property/adversarial_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-invariants` picks it up.

#[path = "../../../tests/property/adversarial_tests.rs"]
mod adversarial_tests;
