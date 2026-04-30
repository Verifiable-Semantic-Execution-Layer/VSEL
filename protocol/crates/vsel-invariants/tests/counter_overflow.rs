//! Integration test harness for counter overflow boundary tests (L-004).
//!
//! The canonical test source lives at `protocol/tests/unit/counter_overflow.rs`.
//! This file includes it as a module so `cargo test -p vsel-invariants` picks it up.

#[path = "../../../tests/unit/counter_overflow.rs"]
mod counter_overflow;
