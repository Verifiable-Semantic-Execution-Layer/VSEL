//! Property-based tests for VSEL batch processing (`vsel-engine::batch`).
//!
//! Uses `proptest` to verify correctness properties derived from
//! STATE_MACHINE.md §5, FORMAL_SPECIFICATION.md §3.
//!
//! **Property 6: Batch Equivalence to Sequential Application** —
//! batch result equals sequential application (LEM-9, THM-12).
//! **Validates: Requirements 2.5**

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::state::*;
use vsel_core::types::*;
use vsel_engine::batch::execute_batch;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine};

// ---------------------------------------------------------------------------
// Arbitrary strategies — reused patterns from engine_tests.rs
// ---------------------------------------------------------------------------

fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

fn arb_account_data() -> impl Strategy<Value = AccountData> {
    (
        0u128..=1_000_000u128,
        0u64..=1_000_000u64,
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(balance, nonce, data)| AccountData {
            balance,
            nonce,
            data,
        })
}

fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
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

fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=u64::MAX, 0u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

fn arb_trace_metadata_nongenesis() -> impl Strategy<Value = TraceMetadata> {
    (
        1u64..=1_000_000u64,
        arb_bytes32().prop_filter("non-zero commitment", |b| b.iter().any(|&x| x != 0)),
        0u64..=1_000_000u64,
        0u64..=100u64,
    )
        .prop_map(|(seq, prev, timestamp, epoch)| TraceMetadata {
            sequence_index: seq,
            previous_commitment: Hash(prev),
            epoch,
            timestamp,
        })
}

/// Generate a valid state at a non-genesis sequence index.
/// Non-genesis avoids the Init guard taking priority over Update.
fn arb_valid_state_nongenesis() -> impl Strategy<Value = State> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_trace_metadata_nongenesis(),
    )
        .prop_map(|(canonical, environment, metadata)| {
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            }
        })
}

fn arb_valid_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(|(classical_sig, pqc_sig, classical_pk, pqc_pk, nonce, domain)| {
            Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: classical_pk,
                    pqc: pqc_pk,
                },
                nonce,
                domain,
            }
        })
}

/// Generate a deposit input for a given account ID and amount.
/// Deposits always succeed on valid states (no precondition on existing accounts).
fn make_deposit_input(account_id: [u8; 32], amount: u128, auth: Authorization) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data,
        },
        auth,
        aux: AuxiliaryData { data: vec![] },
    }
}

/// Strategy for a small batch of deposit inputs (1-3 deposits).
/// Deposits are chosen because they always succeed on valid states,
/// ensuring both batch and sequential execution complete without errors.
fn arb_deposit_batch(
) -> impl Strategy<Value = (Vec<[u8; 32]>, Vec<u128>, Vec<Authorization>)> {
    let size = 1usize..=3;
    size.prop_flat_map(|n| {
        (
            prop::collection::vec(arb_bytes32(), n),
            prop::collection::vec(1u128..=10_000u128, n),
            prop::collection::vec(arb_valid_authorization(), n),
        )
    })
}

// ---------------------------------------------------------------------------
// Property 6a: Sequential Equivalence (LEM-9)
//
// For any valid state and sequence of valid inputs,
// `execute_batch(s, [σ₁, ..., σₙ])` produces the same final canonical
// state as applying each input sequentially via `DefaultExecutionEngine::execute`.
//
// We use deposit operations because they always succeed on valid states,
// guaranteeing both batch and sequential paths complete without error.
//
// **Validates: Requirements 2.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_batch_sequential_equivalence(
        s in arb_valid_state_nongenesis(),
        (account_ids, amounts, auths) in arb_deposit_batch(),
    ) {
        // Build the input vector from generated components.
        let inputs: Vec<Input> = account_ids
            .iter()
            .zip(amounts.iter())
            .zip(auths.iter())
            .map(|((id, amount), auth)| make_deposit_input(*id, *amount, auth.clone()))
            .collect();

        // --- Batch execution ---
        let batch_result = execute_batch(&s, &inputs);
        prop_assert!(
            batch_result.is_ok(),
            "execute_batch should succeed for deposit-only batches on valid state"
        );
        let batch_result = batch_result.unwrap();

        // --- Sequential execution via engine ---
        let engine = DefaultExecutionEngine;
        let mut current_state = s.clone();
        for input in &inputs {
            let result = engine.execute(&current_state, input);
            prop_assert!(
                result.is_ok(),
                "Sequential engine.execute should succeed for deposits on valid state"
            );
            current_state = result.unwrap().post_state;
        }

        // The final canonical states must be identical (LEM-9).
        prop_assert_eq!(
            batch_result.post_state.canonical,
            current_state.canonical,
            "Batch execution must produce the same canonical state as sequential application (LEM-9)"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 6b: Batch Determinism
//
// For any (state, inputs) pair, `execute_batch` called twice produces
// identical results. This extends AX-1 (determinism) to batch execution.
//
// **Validates: Requirements 2.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_batch_determinism(
        s in arb_valid_state_nongenesis(),
        (account_ids, amounts, auths) in arb_deposit_batch(),
    ) {
        let inputs: Vec<Input> = account_ids
            .iter()
            .zip(amounts.iter())
            .zip(auths.iter())
            .map(|((id, amount), auth)| make_deposit_input(*id, *amount, auth.clone()))
            .collect();

        let r1 = execute_batch(&s, &inputs);
        let r2 = execute_batch(&s, &inputs);

        // Both calls must agree on success/failure.
        prop_assert_eq!(
            r1.is_ok(),
            r2.is_ok(),
            "execute_batch must be deterministic: both calls must succeed or both must fail"
        );

        match (r1, r2) {
            (Ok(b1), Ok(b2)) => {
                prop_assert_eq!(
                    b1, b2,
                    "execute_batch must produce identical BatchResult for identical inputs (AX-1)"
                );
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(
                    e1, e2,
                    "execute_batch must produce identical errors for identical inputs"
                );
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Property 6c: Ordering Sensitivity
//
// For any state and two distinct deposit inputs where both orderings
// succeed, the batch result may differ — proving ordering is preserved
// and batch execution is not commutative in general.
//
// We verify that execute_batch([σ₁, σ₂]) and execute_batch([σ₂, σ₁])
// produce results that differ in at least the intermediate_results
// (since the intermediate states will differ even if the final canonical
// state happens to be the same for deposits to different accounts).
//
// **Validates: Requirements 2.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_batch_ordering_sensitivity(
        s in arb_valid_state_nongenesis(),
        id1 in arb_bytes32(),
        id2 in arb_bytes32(),
        amount1 in 1u128..=10_000u128,
        amount2 in 1u128..=10_000u128,
        auth1 in arb_valid_authorization(),
        auth2 in arb_valid_authorization(),
    ) {
        let input1 = make_deposit_input(id1, amount1, auth1);
        let input2 = make_deposit_input(id2, amount2, auth2);

        let forward = execute_batch(&s, &[input1.clone(), input2.clone()]);
        let reversed = execute_batch(&s, &[input2.clone(), input1.clone()]);

        prop_assert!(forward.is_ok(), "Forward batch should succeed");
        prop_assert!(reversed.is_ok(), "Reversed batch should succeed");

        let forward = forward.unwrap();
        let reversed = reversed.unwrap();

        // The intermediate results must differ because the intermediate
        // states (and thus trace metadata, commitments, etc.) depend on
        // the order of application. Even if the final canonical state
        // is the same, the intermediate_results capture the per-step
        // state which includes metadata that differs by ordering.
        if input1 != input2 {
            prop_assert_ne!(
                forward.intermediate_results,
                reversed.intermediate_results,
                "Different input orderings must produce different intermediate results, \
                 proving ordering is preserved (not commutative)"
            );
        }
    }
}
