//! Integration test harness for property-based HashBackend equivalence tests.
//!
//! The canonical test source lives at `protocol/tests/property/backend_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof` picks it up.

#[path = "../../../tests/property/backend_tests.rs"]
mod backend_tests;
