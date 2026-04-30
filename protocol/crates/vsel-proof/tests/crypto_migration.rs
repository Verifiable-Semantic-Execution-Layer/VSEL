//! Integration test harness for end-to-end cryptographic migration.
//!
//! The canonical test source lives at `protocol/tests/integration/crypto_migration.rs`.
//! This file includes it as a module so `cargo test -p vsel-proof --test crypto_migration` picks it up.

#[path = "../../../tests/integration/crypto_migration.rs"]
mod crypto_migration;
