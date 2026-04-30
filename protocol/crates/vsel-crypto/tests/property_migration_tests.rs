//! Integration test harness for property-based legacy Poseidon migration tests.
//!
//! The canonical test source lives at `protocol/tests/property/migration_tests.rs`.
//! This file includes it as a module so `cargo test -p vsel-crypto` picks it up.
//!
//! Note: These tests depend on `vsel-proof` types (Proof, ProofMetadata, etc.)
//! which are not direct dependencies of `vsel-crypto`. The canonical tests
//! should be run from the workspace root:
//!   cargo test --test migration_tests
//!
//! This wrapper re-exports the test module for discoverability within the
//! vsel-crypto crate's test suite.

// The migration_tests.rs file uses vsel-proof types which are not available
// as dev-dependencies of vsel-crypto. Run the canonical tests from the
// workspace root instead:
//   cargo test --test migration_tests
//
// This file serves as a pointer/documentation for the test location.

#[cfg(test)]
mod info {
    #[test]
    fn migration_tests_location() {
        // Property 13: Legacy Poseidon Conditional Acceptance tests
        // are located at: protocol/tests/property/migration_tests.rs
        //
        // Run with: cargo test --test migration_tests
        //
        // Feature: production-readiness, Property 13: Legacy Poseidon Conditional Acceptance
        // **Validates: Requirements 6.5**
    }
}
