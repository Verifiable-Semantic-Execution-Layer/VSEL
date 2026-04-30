//! Integration test harness for constraint inversion attack suite.
//!
//! The canonical test source lives at `protocol/tests/adversarial/constraint_inversion.rs`.
//! This file includes it as a module so `cargo test -p vsel-constraints` picks it up.

#[path = "../../../tests/adversarial/constraint_inversion.rs"]
mod constraint_inversion;
