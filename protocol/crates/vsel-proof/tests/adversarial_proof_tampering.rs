//! Integration test harness for adversarial proof tampering test suite.
//!
//! The canonical test source lives at `protocol/tests/adversarial/proof_tampering.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof` picks it up.

#[path = "../../../tests/adversarial/proof_tampering.rs"]
mod proof_tampering;
