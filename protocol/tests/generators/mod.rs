//! Boundary-focused generators for VSEL property tests.
//!
//! Provides reusable proptest strategies that maximize coverage per iteration
//! by weighting boundary values (zero, dust threshold, max, modulus boundaries)
//! alongside uniformly random values.
//!
//! Requirements: 7.3, 7.4
//!
//! Usage from any integration test file:
//! ```ignore
//! #[path = "../generators/mod.rs"]
//! mod generators;
//! use generators::*;
//! ```

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_core::input::{Authorization, Input};
use vsel_core::state::*;
use vsel_core::types::*;
use vsel_crypto::GoldilocksField;

// ---------------------------------------------------------------------------
// Balance generators
// ---------------------------------------------------------------------------

/// Default dust threshold used in boundary generation.
/// Matches the common test configuration value.
pub const DEFAULT_DUST_THRESHOLD: u128 = 100;

/// Boundary-focused generator for balance values (u128).
///
/// Weights special boundary values to maximize coverage:
/// - Zero balance (empty account)
/// - Dust threshold ±1 (boundary of minimum meaningful value)
/// - Maximum u128 value
/// - Random values across the full range
pub fn arb_balance() -> impl Strategy<Value = u128> {
    prop_oneof![
        3 => Just(0u128),                                  // zero balance
        2 => Just(1u128),                                  // minimum non-zero
        2 => Just(DEFAULT_DUST_THRESHOLD - 1),              // below dust threshold
        3 => Just(DEFAULT_DUST_THRESHOLD),                  // exact dust threshold
        2 => Just(DEFAULT_DUST_THRESHOLD + 1),              // above dust threshold
        2 => Just(u128::MAX),                               // maximum balance
        2 => Just(u64::MAX as u128),                        // u64 boundary
        84 => any::<u128>(),                                // random
    ]
}

/// Boundary-focused generator for u64 balance values.
///
/// Useful for tests operating on u64-sized balances.
pub fn arb_balance_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => Just(0u64),                                    // zero
        2 => Just(1u64),                                    // dust threshold (minimal)
        2 => Just(99u64),                                   // below default dust
        3 => Just(100u64),                                  // exact default dust
        2 => Just(101u64),                                  // above default dust
        2 => Just(u64::MAX),                                // maximum
        86 => any::<u64>(),                                 // random
    ]
}

// ---------------------------------------------------------------------------
// Goldilocks field generators
// ---------------------------------------------------------------------------

const MODULUS: u64 = GoldilocksField::MODULUS;

/// Boundary-focused generator for GoldilocksField elements.
///
/// Weights algebraically significant values:
/// - ZERO: additive identity
/// - ONE: multiplicative identity
/// - MODULUS-1: largest field element (additive inverse of 1)
/// - MODULUS-2: used in Fermat inversion (a^(p-2))
/// - Random values in [0, MODULUS-1]
pub fn arb_goldilocks() -> impl Strategy<Value = GoldilocksField> {
    prop_oneof![
        3 => Just(GoldilocksField::ZERO),
        3 => Just(GoldilocksField::ONE),
        3 => Just(GoldilocksField(MODULUS - 1)),            // p-1
        3 => Just(GoldilocksField(MODULUS - 2)),            // p-2
        88 => any::<u64>().prop_map(|v| GoldilocksField(v % MODULUS)),
    ]
}

/// Generator for non-zero GoldilocksField elements (for inversion tests).
pub fn arb_goldilocks_nonzero() -> impl Strategy<Value = GoldilocksField> {
    prop_oneof![
        3 => Just(GoldilocksField::ONE),
        3 => Just(GoldilocksField(MODULUS - 1)),
        3 => Just(GoldilocksField(MODULUS - 2)),
        91 => (1u64..MODULUS).prop_map(GoldilocksField),
    ]
}

// ---------------------------------------------------------------------------
// Trace generators
// ---------------------------------------------------------------------------

/// Generate a random 32-byte array.
pub fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random AccountId.
pub fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

/// Generate a random AccountData with boundary-focused balance.
pub fn arb_account_data() -> impl Strategy<Value = AccountData> {
    (
        arb_balance(),
        0u64..=1_000_000u64,
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(balance, nonce, data)| AccountData {
            balance,
            nonce,
            data,
        })
}

/// Generate a non-zero DomainTag.
pub fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

/// Generate a random ProtocolVersion.
pub fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

/// Generate a random CanonicalState with consistent total_supply.
pub fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    (
        proptest::collection::btree_map(arb_account_id(), arb_account_data(), 0..5),
        arb_protocol_version(),
    )
        .prop_map(|(accounts, protocol_version)| {
            let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
            CanonicalState {
                accounts,
                storage: BTreeMap::new(),
                system_data: SystemData {
                    protocol_version,
                    total_supply,
                    parameters: BTreeMap::new(),
                },
            }
        })
}

/// Generate a valid Environment.
pub fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=1_000_000u64, 1u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

/// Build a valid State at a given sequence index.
pub fn build_state_at_seq(c: CanonicalState, seq: u64, env: Environment) -> State {
    let d = derive(&c);
    let econ = derive_economic(&c, &env);
    let commitment = if seq == 0 {
        Hash([0u8; 32])
    } else {
        Hash([0xABu8; 32])
    };
    let meta = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch: 0,
        timestamp: env.timestamp,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
    }
}

fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
}

fn valid_auth() -> Authorization {
    Authorization {
        classical_sig: vec![1, 2, 3],
        pqc_sig: vec![4, 5, 6],
        public_key: HybridPublicKey {
            classical: vec![10, 11],
            pqc: vec![20, 21],
        },
        nonce: 42,
        domain: test_domain_tag(),
    }
}

fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
    Input {
        payload: Payload {
            payload_type: payload_type.to_string(),
            data,
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Boundary-focused trace generator.
///
/// Generates traces of varying shapes:
/// - Empty trace (0 entries)
/// - Single-entry trace
/// - Multi-entry trace (2-10 entries)
/// - Error traces (with invalid operations)
///
/// Each variant is weighted to ensure boundary coverage.
pub fn arb_trace_entries(
) -> impl Strategy<Value = (CanonicalState, Environment, Vec<Input>)> {
    let empty = (arb_canonical_state(), arb_environment()).prop_map(|(c, e)| (c, e, vec![]));

    let single = (arb_canonical_state(), arb_environment()).prop_map(|(c, e)| {
        let mut data = Vec::new();
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&500u128.to_le_bytes());
        let input = make_input("deposit", data);
        (c, e, vec![input])
    });

    let multi = (
        arb_canonical_state(),
        arb_environment(),
        2usize..=10,
    )
        .prop_flat_map(|(c, e, count)| {
            let inputs = prop::collection::vec(
                (arb_bytes32(), 1u128..=10_000u128).prop_map(|(account, amount)| {
                    let mut data = Vec::new();
                    data.extend_from_slice(&account);
                    data.extend_from_slice(&amount.to_le_bytes());
                    make_input("deposit", data)
                }),
                count..=count,
            );
            inputs.prop_map(move |inputs| (c.clone(), e.clone(), inputs))
        });

    let error_trace = (arb_canonical_state(), arb_environment()).prop_map(|(c, e)| {
        // Withdrawal from empty account triggers error path
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFFu8; 32]); // non-existent account
        data.extend_from_slice(&999_999u128.to_le_bytes());
        let input = make_input("withdraw", data);
        (c, e, vec![input])
    });

    prop_oneof![
        5 => empty,
        15 => single,
        65 => multi,
        15 => error_trace,
    ]
}
