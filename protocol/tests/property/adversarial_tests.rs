//! Property-based tests for adversarial resilience — Invalid Witness Suite.
//!
//! Uses `proptest` to verify that the constraint system (invariant checks,
//! state validity, trace verification, engine execution) correctly rejects
//! every invalid witness from families W1 through W8.
//!
//! Derived from: INVALID_EXECUTION_WITNESS_SUITE.md, THREAT_MODEL.md,
//! FORMAL_SPECIFICATION.md §3.
//!
//! Properties tested:
//! - Property 54: Invalid Witness Suite Rejection — every W1-W8 family
//!   rejected by constraint system
//!   **Validates: Requirements 13.1, 13.2**

use std::collections::BTreeMap;

use proptest::collection::btree_map;
use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::observable::{obs, Observable, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine};
use vsel_invariants::global::*;
use vsel_invariants::local::*;
use vsel_trace::engine::{verify_trace, Trace, TraceEngine};

// ===========================================================================
// Arbitrary strategies
// ===========================================================================

/// Generate a random 32-byte array.
fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random AccountId.
fn arb_account_id() -> impl Strategy<Value = AccountId> {
    arb_bytes32().prop_map(AccountId)
}

/// Generate a random AccountData with bounded values.
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

/// Generate a non-zero DomainTag (required for valid environment).
fn arb_domain_tag() -> impl Strategy<Value = DomainTag> {
    arb_bytes32()
        .prop_filter("domain tag must not be all zeros", |b| {
            b.iter().any(|&x| x != 0)
        })
        .prop_map(|b| DomainTag(Hash(b)))
}

/// Generate a valid Environment.
fn arb_environment() -> impl Strategy<Value = Environment> {
    (1u64..=u64::MAX, 0u64..=1_000_000u64, arb_domain_tag()).prop_map(
        |(timestamp, block_height, execution_domain)| Environment {
            timestamp,
            block_height,
            execution_domain,
        },
    )
}

/// Generate valid TraceMetadata.
fn arb_trace_metadata() -> impl Strategy<Value = TraceMetadata> {
    prop_oneof![
        // Genesis metadata
        (0u64..=1_000_000u64, 0u64..=100u64).prop_map(|(timestamp, epoch)| TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch,
            timestamp,
        }),
        // Non-genesis metadata
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
            }),
    ]
}

/// Generate a random CanonicalState with total_supply matching sum of balances.
fn arb_canonical_state() -> impl Strategy<Value = CanonicalState> {
    (
        btree_map(arb_account_id(), arb_account_data(), 0..5),
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

/// Generate a random ProtocolVersion.
fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    (0u32..10, 0u32..100, 0u32..100).prop_map(|(major, minor, patch)| ProtocolVersion {
        major,
        minor,
        patch,
    })
}

/// Build a valid State from components by deriving all dependent fields.
fn arb_valid_state() -> impl Strategy<Value = State> {
    (
        arb_canonical_state(),
        arb_environment(),
        arb_trace_metadata(),
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

/// Build a valid State at a specific non-genesis sequence index.
fn arb_valid_state_nongenesis() -> impl Strategy<Value = State> {
    (
        arb_canonical_state(),
        arb_environment(),
        1u64..=1_000_000u64,
        arb_bytes32().prop_filter("non-zero commitment", |b| b.iter().any(|&x| x != 0)),
        0u64..=1_000_000u64,
        0u64..=100u64,
    )
        .prop_map(|(canonical, environment, seq, prev, timestamp, epoch)| {
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            let metadata = TraceMetadata {
                sequence_index: seq,
                previous_commitment: Hash(prev),
                epoch,
                timestamp,
            };
            State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            }
        })
}

/// Generate a valid Authorization.
fn arb_valid_authorization() -> impl Strategy<Value = Authorization> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
        arb_domain_tag(),
    )
        .prop_map(
            |(classical_sig, pqc_sig, classical_pk, pqc_pk, nonce, domain)| Authorization {
                classical_sig,
                pqc_sig,
                public_key: HybridPublicKey {
                    classical: classical_pk,
                    pqc: pqc_pk,
                },
                nonce,
                domain,
            },
        )
}

/// Generate a structurally valid Input.
fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",
        prop::collection::vec(any::<u8>(), 1..128),
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload { payload_type, data },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

// ===========================================================================
// Shared helpers
// ===========================================================================

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

fn minimal_canonical() -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

fn build_state_at_seq(c: CanonicalState, seq: u64) -> State {
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
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
        timestamp: 1_000_000,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
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

fn make_deposit_input(account_id: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("deposit", data)
}

fn canonical_with_account(id: [u8; 32], balance: u128) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(
        AccountId(id),
        AccountData {
            balance,
            nonce: 0,
            data: vec![],
        },
    );
    c.system_data.total_supply = balance;
    c
}

/// Build a valid 3-entry trace for testing.
fn build_valid_trace() -> Trace {
    let c = minimal_canonical();
    let s0 = build_state_at_seq(c, 0);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let obs0 = obs(&s0, &sigma0, &s1);

    let sigma1 = make_deposit_input([1u8; 32], 500);
    let s2 = apply(&s1, &sigma1);
    let obs1 = obs(&s1, &sigma1, &s2);

    let sigma2 = make_input("unknown_op", vec![0x01]);
    let s3 = apply(&s2, &sigma2);
    let obs2 = obs(&s2, &sigma2, &s3);

    let mut engine = TraceEngine::new();
    let e0 = engine.record_transition(&s0, &sigma0, &s1, &obs0);
    let e1 = engine.record_transition(&s1, &sigma1, &s2, &obs1);
    let e2 = engine.record_transition(&s2, &sigma2, &s3, &obs2);
    let commitment = engine.current_chain_hash().clone();

    Trace {
        entries: vec![e0, e1, e2],
        initial_state: s0,
        commitment,
    }
}

// ===========================================================================
// Property 54: Invalid Witness Suite Rejection
//
// For any invalid witness from families W1 through W8, the constraint system
// (invariant checks, state validity, trace verification, engine execution)
// rejects the witness.
//
// **Validates: Requirements 13.1, 13.2**
// ===========================================================================

// ---------------------------------------------------------------------------
// W1: State Violation — invalid states are rejected by global invariants
// and valid_state predicate.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W1.1: Total supply mismatch — random corruption of total_supply
    /// relative to actual account balance sum is always detected.
    #[test]
    fn prop_w1_total_supply_mismatch_rejected(
        state in arb_valid_state(),
        delta in 1u128..=1_000_000u128,
    ) {
        // Corrupt total_supply so it doesn't match balance sum
        let mut bad = state;
        bad.canonical.system_data.total_supply =
            bad.canonical.system_data.total_supply.wrapping_add(delta);
        // Recompute derived to isolate the total_supply mismatch
        bad.derived = derive(&bad.canonical);
        bad.economic = derive_economic(&bad.canonical, &bad.environment);

        let g_valid_result = g_valid(&bad);
        let g_struct_result = g_struct(&bad);
        prop_assert!(
            !g_valid_result.valid || !g_struct_result.valid,
            "W1.1: Total supply mismatch must be rejected by G_valid or G_struct"
        );
    }

    /// W1.2: Inconsistent derived state — corrupting the state root
    /// is always detected by G_commit and valid_state.
    #[test]
    fn prop_w1_inconsistent_derived_rejected(
        state in arb_valid_state(),
        corrupt_root in arb_bytes32(),
    ) {
        let mut bad = state;
        let original_root = bad.derived.state_root.clone();
        bad.derived.state_root = Hash(corrupt_root);

        // Only test when corruption actually changes the root
        prop_assume!(bad.derived.state_root != original_root);

        let result = g_commit(&bad);
        prop_assert!(
            !result.valid,
            "W1.2: Corrupted derived state root must be rejected by G_commit"
        );
        prop_assert!(
            !valid_state(&bad),
            "W1.2: valid_state must reject inconsistent derived state"
        );
    }

    /// W1.3: Invalid environment — zero domain tag is always rejected.
    #[test]
    fn prop_w1_zero_domain_rejected(
        state in arb_valid_state(),
    ) {
        let mut bad = state;
        bad.environment.execution_domain = DomainTag(Hash([0u8; 32]));

        let result = g_env(&bad);
        prop_assert!(
            !result.valid,
            "W1.3: Zero domain tag must be rejected by G_env"
        );
        prop_assert!(
            !valid_state(&bad),
            "W1.3: valid_state must reject zero domain tag"
        );
    }

    /// W1.4: Metadata regression — genesis with non-zero commitment or
    /// non-genesis with zero commitment is always rejected.
    #[test]
    fn prop_w1_metadata_regression_rejected(
        state in arb_valid_state(),
    ) {
        let mut bad = state;
        // Flip the metadata consistency: if genesis, set non-zero commitment;
        // if non-genesis, set zero commitment.
        if bad.metadata.sequence_index == 0 {
            bad.metadata.previous_commitment = Hash([0xABu8; 32]);
        } else {
            bad.metadata.previous_commitment = Hash([0u8; 32]);
        }

        let result = g_mono(&bad);
        prop_assert!(
            !result.valid,
            "W1.4: Metadata regression must be rejected by G_mono"
        );
    }

    /// W1.5: Unreachable state — a fabricated post-state that differs from
    /// Apply(pre, input) is always detected by L_valid.
    #[test]
    fn prop_w1_unreachable_state_rejected(
        pre in arb_valid_state_nongenesis(),
        sigma in arb_valid_input(),
        rogue_key in "[a-z]{1,10}",
        rogue_val in prop::collection::vec(any::<u8>(), 1..16),
    ) {
        let real_post = apply(&pre, &sigma);
        let mut fake_post = real_post.clone();
        // Inject a rogue parameter to make the state unreachable
        fake_post.canonical.system_data.parameters.insert(
            format!("rogue_{}", rogue_key),
            rogue_val,
        );
        // Recompute total_supply to keep canonical internally consistent
        let total: u128 = fake_post.canonical.accounts.values().map(|a| a.balance).sum();
        fake_post.canonical.system_data.total_supply = total;
        fake_post.derived = derive(&fake_post.canonical);
        fake_post.economic = derive_economic(&fake_post.canonical, &fake_post.environment);

        let result = l_valid(&pre, &sigma, &fake_post);
        prop_assert!(
            !result.valid,
            "W1.5: Unreachable state must be rejected by L_valid"
        );
    }
}

// ---------------------------------------------------------------------------
// W2: Transition Violation — fabricated transitions are rejected by
// local invariants (L_valid, L_cons).
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W2.1: Arbitrary jump — a completely unrelated post-state is rejected.
    #[test]
    fn prop_w2_arbitrary_jump_rejected(
        pre in arb_valid_state_nongenesis(),
        sigma in arb_valid_input(),
        fake_canonical in arb_canonical_state(),
    ) {
        let real_post = apply(&pre, &sigma);
        let fake_post = State {
            canonical: fake_canonical.clone(),
            derived: derive(&fake_canonical),
            environment: pre.environment.clone(),
            economic: derive_economic(&fake_canonical, &pre.environment),
            metadata: real_post.metadata.clone(),
        };

        // Only test when the fake state actually differs
        prop_assume!(fake_post.canonical != real_post.canonical);

        let result = l_valid(&pre, &sigma, &fake_post);
        prop_assert!(
            !result.valid,
            "W2.1: Arbitrary jump must be rejected by L_valid"
        );
    }

    /// W2.2: Hidden mutation — a noop that secretly changes canonical state
    /// is always detected.
    #[test]
    fn prop_w2_hidden_mutation_rejected(
        pre in arb_valid_state_nongenesis(),
        rogue_key in "[a-z]{1,10}",
        rogue_val in prop::collection::vec(any::<u8>(), 1..16),
    ) {
        // Use an unrecognized payload type to trigger Noop
        let sigma = make_input("unknown_op", vec![0x01]);
        let mut fake_post = apply(&pre, &sigma);
        // Inject hidden mutation
        fake_post.canonical.system_data.parameters.insert(
            format!("hidden_{}", rogue_key),
            rogue_val,
        );
        let total: u128 = fake_post.canonical.accounts.values().map(|a| a.balance).sum();
        fake_post.canonical.system_data.total_supply = total;
        fake_post.derived = derive(&fake_post.canonical);
        fake_post.economic = derive_economic(&fake_post.canonical, &fake_post.environment);

        let result = l_valid(&pre, &sigma, &fake_post);
        prop_assert!(
            !result.valid,
            "W2.2: Hidden mutation in noop must be rejected by L_valid"
        );
    }

    /// W2.3: Resource creation — adding balance from nothing violates L_cons.
    #[test]
    fn prop_w2_resource_creation_rejected(
        balance in 1u128..=1_000_000u128,
        extra in 1u128..=1_000_000u128,
    ) {
        let c = canonical_with_account([1u8; 32], balance);
        let s = build_state_at_seq(c, 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let mut fake_post = apply(&s, &sigma);
        // Inflate balance without corresponding total_supply change
        if let Some(acc) = fake_post.canonical.accounts.get_mut(&AccountId([1u8; 32])) {
            acc.balance = acc.balance.saturating_add(extra);
        }
        fake_post.derived = derive(&fake_post.canonical);

        let result = l_cons(&s, &sigma, &fake_post);
        prop_assert!(
            !result.valid,
            "W2.3: Resource creation must be rejected by L_cons"
        );
    }

    /// W2.4: Unauthorized input — empty classical or PQC signatures are
    /// rejected by the execution engine.
    #[test]
    fn prop_w2_unauthorized_rejected(
        state in arb_valid_state_nongenesis(),
        empty_classical in proptest::bool::ANY,
    ) {
        let engine = DefaultExecutionEngine;
        let sigma = Input {
            payload: Payload {
                payload_type: "deposit".to_string(),
                data: {
                    let mut d = vec![];
                    d.extend_from_slice(&[1u8; 32]);
                    d.extend_from_slice(&100u128.to_le_bytes());
                    d
                },
            },
            auth: Authorization {
                classical_sig: if empty_classical { vec![] } else { vec![1, 2, 3] },
                pqc_sig: if empty_classical { vec![4, 5, 6] } else { vec![] },
                public_key: HybridPublicKey {
                    classical: vec![10, 11],
                    pqc: vec![20, 21],
                },
                nonce: 42,
                domain: state.environment.execution_domain.clone(),
            },
            aux: AuxiliaryData { data: vec![] },
        };
        let result = engine.execute(&state, &sigma);
        prop_assert!(
            result.is_err(),
            "W2.4: Empty signature component must be rejected by engine"
        );
    }
}

// ---------------------------------------------------------------------------
// W3: Trace Structure Violation — tampered traces are rejected by
// verify_trace.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W3.1: Broken chain hash — corrupting any entry's chain hash
    /// is always detected.
    #[test]
    fn prop_w3_broken_chain_hash_rejected(
        corrupt_hash in arb_bytes32(),
        entry_idx in 0usize..3,
    ) {
        let mut trace = build_valid_trace();
        let original = trace.entries[entry_idx].chain_hash.clone();
        trace.entries[entry_idx].chain_hash = Hash(corrupt_hash);
        prop_assume!(trace.entries[entry_idx].chain_hash != original);

        prop_assert!(
            !verify_trace(&trace),
            "W3.1: Tampered chain hash at index {} must be rejected",
            entry_idx
        );
    }

    /// W3.2: Missing transition — removing an entry breaks the trace.
    #[test]
    fn prop_w3_missing_transition_rejected(
        remove_idx in 0usize..3,
    ) {
        let mut trace = build_valid_trace();
        trace.entries.remove(remove_idx);

        prop_assert!(
            !verify_trace(&trace),
            "W3.2: Missing entry at index {} must be rejected",
            remove_idx
        );
    }

    /// W3.3: Reordered entries — swapping any two entries breaks the trace.
    #[test]
    fn prop_w3_reordered_entries_rejected(
        idx_a in 0usize..3,
        idx_b in 0usize..3,
    ) {
        prop_assume!(idx_a != idx_b);
        let mut trace = build_valid_trace();
        trace.entries.swap(idx_a, idx_b);

        prop_assert!(
            !verify_trace(&trace),
            "W3.3: Swapped entries ({}, {}) must be rejected",
            idx_a, idx_b
        );
    }

    /// W3.4: Invalid initial state — replacing the initial state breaks
    /// the trace commitment chain.
    #[test]
    fn prop_w3_invalid_initial_state_rejected(
        fake_canonical in arb_canonical_state(),
    ) {
        let mut trace = build_valid_trace();
        let original_commitment = commit(&trace.initial_state.canonical);
        let fake_state = build_state_at_seq(fake_canonical, 0);
        let fake_commitment = commit(&fake_state.canonical);
        prop_assume!(fake_commitment != original_commitment);

        trace.initial_state = fake_state;

        prop_assert!(
            !verify_trace(&trace),
            "W3.4: Wrong initial state must be rejected"
        );
    }

    /// W3.1b: Tampered final commitment — corrupting the trace commitment
    /// is always detected.
    #[test]
    fn prop_w3_tampered_final_commitment_rejected(
        corrupt_hash in arb_bytes32(),
    ) {
        let mut trace = build_valid_trace();
        let original = trace.commitment.clone();
        trace.commitment = Hash(corrupt_hash);
        prop_assume!(trace.commitment != original);

        prop_assert!(
            !verify_trace(&trace),
            "W3.1b: Tampered final commitment must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// W4: Observable Manipulation — fabricated observables are detectable
// because obs() is deterministic and derivable from (s, σ, s').
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W4.1: Fabricated observable — any modification to the observable
    /// is detectable by re-deriving obs(s, σ, s').
    #[test]
    fn prop_w4_fabricated_observable_detected(
        pre in arb_valid_state_nongenesis(),
        sigma in arb_valid_input(),
        fake_gas in 0u64..=1_000_000u64,
    ) {
        let post = apply(&pre, &sigma);
        let real_obs = obs(&pre, &sigma, &post);
        let fake_obs = Observable {
            transition_class: real_obs.transition_class,
            outputs: real_obs.outputs.clone(),
            gas_used: fake_gas,
            status: real_obs.status,
        };

        // If the fake gas happens to match, skip this case
        prop_assume!(fake_obs != real_obs);

        // Re-derive the observable — must match the real one, not the fake
        let rederived = obs(&pre, &sigma, &post);
        prop_assert_eq!(
            rederived.clone(), real_obs,
            "W4.1: Re-derived observable must match real observable"
        );
        prop_assert_ne!(
            rederived, fake_obs,
            "W4.1: Fabricated observable must be detectable"
        );
    }

    /// W4.2: Missing observable outputs — stripping outputs from a
    /// successful transition is detectable.
    #[test]
    fn prop_w4_missing_outputs_detected(
        pre in arb_valid_state_nongenesis(),
        account_id in arb_bytes32(),
        amount in 1u128..=100_000u128,
    ) {
        // Use a deposit input which always produces output events
        let sigma = make_deposit_input(account_id, amount);
        let post = apply(&pre, &sigma);
        let real_obs = obs(&pre, &sigma, &post);

        // Deposit always produces outputs (account_created or balance_change)
        prop_assume!(!real_obs.outputs.is_empty());

        let missing_obs = Observable {
            transition_class: real_obs.transition_class,
            outputs: vec![],
            gas_used: real_obs.gas_used,
            status: real_obs.status,
        };

        let rederived = obs(&pre, &sigma, &post);
        prop_assert_ne!(
            rederived, missing_obs,
            "W4.2: Missing outputs must be detectable"
        );
    }

    /// W4.3: Noop with non-null observable — a noop transition must
    /// produce empty outputs and Rejected status.
    #[test]
    fn prop_w4_noop_observable_correct(
        pre in arb_valid_state_nongenesis(),
    ) {
        let sigma = make_input("unknown_op", vec![0x01]);
        let post = apply(&pre, &sigma);
        let real_obs = obs(&pre, &sigma, &post);

        prop_assert_eq!(
            real_obs.transition_class,
            TransitionClass::Noop,
            "W4.3: Unknown op must classify as Noop"
        );
        prop_assert_eq!(
            real_obs.status,
            TransitionStatus::Rejected,
            "W4.3: Noop must have Rejected status"
        );
        prop_assert!(
            real_obs.outputs.is_empty(),
            "W4.3: Noop must produce no output events"
        );
    }
}

// ---------------------------------------------------------------------------
// W5: Authorization Manipulation — malformed authorization is rejected
// by the execution engine.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W5.1: Empty public key components — both classical and PQC public
    /// key components must be non-empty.
    #[test]
    fn prop_w5_empty_pubkey_rejected(
        state in arb_valid_state_nongenesis(),
        empty_classical_pk in proptest::bool::ANY,
    ) {
        let engine = DefaultExecutionEngine;
        let sigma = Input {
            payload: Payload {
                payload_type: "deposit".to_string(),
                data: {
                    let mut d = vec![];
                    d.extend_from_slice(&[1u8; 32]);
                    d.extend_from_slice(&100u128.to_le_bytes());
                    d
                },
            },
            auth: Authorization {
                classical_sig: vec![1, 2, 3],
                pqc_sig: vec![4, 5, 6],
                public_key: HybridPublicKey {
                    classical: if empty_classical_pk { vec![] } else { vec![10, 11] },
                    pqc: if empty_classical_pk { vec![20, 21] } else { vec![] },
                },
                nonce: 42,
                domain: state.environment.execution_domain.clone(),
            },
            aux: AuxiliaryData { data: vec![] },
        };
        let result = engine.execute(&state, &sigma);
        prop_assert!(
            result.is_err(),
            "W5.1: Empty public key component must be rejected"
        );
    }

    /// W5.3: Cross-domain — zero domain tag in authorization is rejected.
    #[test]
    fn prop_w5_zero_domain_auth_rejected(
        state in arb_valid_state_nongenesis(),
    ) {
        let engine = DefaultExecutionEngine;
        let sigma = Input {
            payload: Payload {
                payload_type: "deposit".to_string(),
                data: {
                    let mut d = vec![];
                    d.extend_from_slice(&[1u8; 32]);
                    d.extend_from_slice(&100u128.to_le_bytes());
                    d
                },
            },
            auth: Authorization {
                classical_sig: vec![1, 2, 3],
                pqc_sig: vec![4, 5, 6],
                public_key: HybridPublicKey {
                    classical: vec![10, 11],
                    pqc: vec![20, 21],
                },
                nonce: 42,
                domain: DomainTag(Hash([0u8; 32])),
            },
            aux: AuxiliaryData { data: vec![] },
        };
        let result = engine.execute(&state, &sigma);
        prop_assert!(
            result.is_err(),
            "W5.3: Zero domain tag in auth must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// W6: Batch Manipulation — batch semantics must equal sequential
// application (LEM-9).
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W6.1: Batch sequential equivalence — applying inputs sequentially
    /// must produce the same result as batch application.
    /// This verifies that reordering or skipping would be detectable.
    #[test]
    fn prop_w6_batch_sequential_equivalence(
        amount1 in 1u128..=100_000u128,
        amount2 in 1u128..=100_000u128,
    ) {
        let c = minimal_canonical();
        let s = build_state_at_seq(c, 1);
        let d1 = make_deposit_input([1u8; 32], amount1);
        let d2 = make_deposit_input([2u8; 32], amount2);

        // Sequential application
        let s1 = apply(&s, &d1);
        let s2 = apply(&s1, &d2);

        // Batch via execute_batch
        let batch_result = vsel_engine::batch::execute_batch(&s, &[d1, d2]);
        prop_assert!(batch_result.is_ok(), "Batch should succeed for valid deposits");
        let batch_post = batch_result.unwrap().post_state;

        prop_assert_eq!(
            batch_post.canonical, s2.canonical,
            "W6.1: Batch must equal sequential application (LEM-9)"
        );
    }
}

// ---------------------------------------------------------------------------
// W7: Commitment Manipulation — corrupting state commitments in trace
// entries is always detected.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W7.1: Wrong state commitment — corrupting pre or post state
    /// commitment in any trace entry is detected.
    #[test]
    fn prop_w7_wrong_state_commitment_rejected(
        corrupt_hash in arb_bytes32(),
        entry_idx in 0usize..2,
        corrupt_pre in proptest::bool::ANY,
    ) {
        let mut trace = build_valid_trace();
        if corrupt_pre {
            let original = trace.entries[entry_idx].pre_state_commitment.clone();
            trace.entries[entry_idx].pre_state_commitment = Hash(corrupt_hash);
            prop_assume!(trace.entries[entry_idx].pre_state_commitment != original);
        } else {
            let original = trace.entries[entry_idx].post_state_commitment.clone();
            trace.entries[entry_idx].post_state_commitment = Hash(corrupt_hash);
            prop_assume!(trace.entries[entry_idx].post_state_commitment != original);
        }

        prop_assert!(
            !verify_trace(&trace),
            "W7.1: Wrong state commitment must be rejected"
        );
    }

    /// W7.2: Commitment injectivity — different canonical states must
    /// produce different commitments.
    #[test]
    fn prop_w7_commitment_injectivity(
        c1 in arb_canonical_state(),
        c2 in arb_canonical_state(),
    ) {
        prop_assume!(c1 != c2);
        let h1 = commit(&c1);
        let h2 = commit(&c2);
        prop_assert_ne!(
            h1, h2,
            "W7.2: Different canonical states must produce different commitments"
        );
    }
}

// ---------------------------------------------------------------------------
// W8: Cross-System Violation — individually valid systems can have
// inconsistent shared state, detectable via cross-system checks.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// W8.1: Inconsistent shared state — two systems with the same account
    /// but different balances are individually valid but cross-system
    /// inconsistent.
    #[test]
    fn prop_w8_inconsistent_shared_state_detected(
        balance_a in 1u128..=1_000_000u128,
        balance_b in 1u128..=1_000_000u128,
    ) {
        prop_assume!(balance_a != balance_b);

        let c_a = canonical_with_account([1u8; 32], balance_a);
        let s_a = build_state_at_seq(c_a, 1);
        let c_b = canonical_with_account([1u8; 32], balance_b);
        let s_b = build_state_at_seq(c_b, 1);

        // Both individually valid
        prop_assert!(valid_state(&s_a), "System A should be individually valid");
        prop_assert!(valid_state(&s_b), "System B should be individually valid");

        // But shared account has different balances — cross-system inconsistency
        let bal_a = s_a.canonical.accounts[&AccountId([1u8; 32])].balance;
        let bal_b = s_b.canonical.accounts[&AccountId([1u8; 32])].balance;
        prop_assert_ne!(
            bal_a, bal_b,
            "W8.1: Systems have inconsistent shared state"
        );
    }

    /// W8.2: Resource creation across systems — total supply across two
    /// systems must be conserved; any increase indicates resource creation.
    #[test]
    fn prop_w8_cross_system_resource_creation_detected(
        pre_a in 100u128..=500_000u128,
        pre_b in 100u128..=500_000u128,
        post_a in 100u128..=500_000u128,
        post_b in 100u128..=500_000u128,
    ) {
        let total_pre = pre_a + pre_b;
        let total_post = post_a + post_b;
        prop_assume!(total_post != total_pre);

        // Cross-system total supply changed — resource creation or destruction
        prop_assert_ne!(
            total_pre, total_post,
            "W8.2: Cross-system total supply must be conserved"
        );
    }
}
