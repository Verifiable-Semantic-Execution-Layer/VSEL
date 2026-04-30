//! Integration test harness for property-based circuit-constraint equivalence tests.
//!
//! The canonical test source lives at `protocol/tests/property/circuit_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof --features plonky3-backend`
//! picks it up.
//!
//! Gated behind `plonky3-backend` because the Plonky3CircuitBuilder is only
//! available with that feature.

#[cfg(feature = "plonky3-backend")]
#[path = "../../../tests/property/circuit_tests.rs"]
mod circuit_tests;
