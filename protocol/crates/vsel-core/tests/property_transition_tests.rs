//! Integration test harness for property-based Transition model tests.
//!
//! The canonical test source lives at `protocol/tests/property/transition_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-core` picks it up.

#[path = "../../../tests/property/transition_tests.rs"]
mod transition_tests;
