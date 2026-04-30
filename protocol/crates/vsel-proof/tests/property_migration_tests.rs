//! Integration test harness for property-based legacy Poseidon migration tests.
//!
//! The canonical test source lives at `protocol/tests/property/migration_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof --test property_migration_tests`
//! picks it up.

#[path = "../../../tests/property/migration_tests.rs"]
mod migration_tests;
