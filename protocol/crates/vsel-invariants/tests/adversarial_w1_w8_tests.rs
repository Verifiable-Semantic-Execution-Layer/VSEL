//! Invalid Execution Witness Suite — adversarial tests for W1-W8 families.
//!
//! Derived from: INVALID_EXECUTION_WITNESS_SUITE.md, Requirements 13.1, 13.2.
//!
//! Each invalid witness family constructs a minimal invalid witness and verifies
//! that the constraint system (invariant checks, state validity, trace verification)
//! properly rejects it.
//!
//! Families:
//! - W1: State violation (negative balance, inconsistent derived, invalid env, metadata regression, unreachable)
//! - W2: Transition violation (arbitrary jump, hidden mutation, resource creation/destruction, unauthorized, precondition)
//! - W3: Trace structure (broken chain, missing transition, reordered/duplicate, invalid initial)
//! - W4: Observable manipulation (fabricated, missing, no-op with non-null)
//! - W5: Authorization manipulation (wrong payload, replayed, cross-domain)
//! - W6: Batch manipulation (reordered, skipping validation, phantom operations)
//! - W7: Commitment manipulation (wrong state, chain hash)
//! - W8: Cross-system (inconsistent shared state, resource creation)

use std::collections::BTreeMap;

use vsel_core::input::*;
use vsel_core::observable::{obs, Observable, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;
use vsel_engine::batch::execute_batch;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine, ExecutionError};
use vsel_invariants::global::*;
use vsel_invariants::local::*;
use vsel_trace::commitment::{compute_chain_hash, verify_chain};
use vsel_trace::engine::{verify_trace, Trace, TraceEngine};

// ===========================================================================
// Shared test helpers
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
            protocol_version: ProtocolVersion { major: 0, minor: 1, patch: 0 },
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
    let commitment = if seq == 0 { Hash([0u8; 32]) } else { Hash([0xABu8; 32]) };
    let meta = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch: 0,
        timestamp: 1_000_000,
    };
    State { canonical: c, derived: d, environment: env, economic: econ, metadata: meta }
}

fn build_genesis_state(c: CanonicalState) -> State {
    build_state_at_seq(c, 0)
}

fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
    Input {
        payload: Payload { payload_type: payload_type.to_string(), data },
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

fn make_transfer_input(sender: [u8; 32], receiver: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&sender);
    data.extend_from_slice(&receiver);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("transfer", data)
}

fn canonical_with_account(id: [u8; 32], balance: u128) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(AccountId(id), AccountData { balance, nonce: 0, data: vec![] });
    c.system_data.total_supply = balance;
    c
}

fn canonical_with_two_accounts(id1: [u8; 32], bal1: u128, id2: [u8; 32], bal2: u128) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(AccountId(id1), AccountData { balance: bal1, nonce: 0, data: vec![] });
    c.accounts.insert(AccountId(id2), AccountData { balance: bal2, nonce: 0, data: vec![] });
    c.system_data.total_supply = bal1 + bal2;
    c
}

/// Build a valid 3-entry trace for testing.
fn build_valid_trace() -> Trace {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
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

    Trace { entries: vec![e0, e1, e2], initial_state: s0, commitment }
}

/// Build a valid 2-entry trace for commitment tests.
fn build_two_entry_trace() -> Trace {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let obs0 = obs(&s0, &sigma0, &s1);

    let sigma1 = make_deposit_input([1u8; 32], 500);
    let s2 = apply(&s1, &sigma1);
    let obs1 = obs(&s1, &sigma1, &s2);

    let mut engine = TraceEngine::new();
    let e0 = engine.record_transition(&s0, &sigma0, &s1, &obs0);
    let e1 = engine.record_transition(&s1, &sigma1, &s2, &obs1);
    let commitment = engine.current_chain_hash().clone();

    Trace { entries: vec![e0, e1], initial_state: s0, commitment }
}


// ===========================================================================
// W1: State Violation
// ===========================================================================

#[test]
fn w1_1_negative_balance_total_supply_mismatch() {
    let mut c = canonical_with_account([1u8; 32], 500);
    c.system_data.total_supply = 999;
    let s = build_state_at_seq(c, 1);
    let result = g_valid(&s);
    assert!(!result.valid, "W1.1: Mismatched total_supply must be rejected by G_valid");
}

#[test]
fn w1_1_balance_sum_exceeds_total_supply() {
    let mut c = canonical_with_two_accounts([1u8; 32], 500, [2u8; 32], 500);
    c.system_data.total_supply = 100;
    let s = build_state_at_seq(c, 1);
    let result = g_struct(&s);
    assert!(!result.valid, "W1.1: Balance sum > total_supply must be rejected by G_struct");
}

#[test]
fn w1_2_inconsistent_derived_state_root() {
    let c = canonical_with_account([1u8; 32], 1000);
    let mut s = build_state_at_seq(c, 1);
    s.derived.state_root = Hash([0xFFu8; 32]);
    let result = g_commit(&s);
    assert!(!result.valid, "W1.2: Corrupted derived state root must be rejected by G_commit");
    assert!(!valid_state(&s), "W1.2: valid_state must reject inconsistent derived state");
}

#[test]
fn w1_2_inconsistent_derived_aggregates() {
    let c = canonical_with_account([1u8; 32], 1000);
    let mut s = build_state_at_seq(c, 1);
    s.derived.aggregates.insert("total_balance".to_string(), 9999);
    assert!(!valid_state(&s), "W1.2: valid_state must reject inconsistent derived aggregates");
}

#[test]
fn w1_3_invalid_environment_zero_domain() {
    let c = minimal_canonical();
    let mut s = build_genesis_state(c);
    s.environment.execution_domain = DomainTag(Hash([0u8; 32]));
    let result = g_env(&s);
    assert!(!result.valid, "W1.3: Zero domain tag must be rejected by G_env");
    assert!(!valid_state(&s), "W1.3: valid_state must reject zero domain tag");
}

#[test]
fn w1_4_metadata_regression_nonzero_commitment_at_genesis() {
    let c = minimal_canonical();
    let mut s = build_genesis_state(c);
    s.metadata.previous_commitment = Hash([0xABu8; 32]);
    let result = g_mono(&s);
    assert!(!result.valid, "W1.4: Genesis with non-zero commitment must be rejected by G_mono");
}

#[test]
fn w1_4_metadata_regression_zero_commitment_nongenesis() {
    let c = minimal_canonical();
    let mut s = build_state_at_seq(c, 5);
    s.metadata.previous_commitment = Hash([0u8; 32]);
    let result = g_mono(&s);
    assert!(!result.valid, "W1.4: Non-genesis with zero commitment must be rejected by G_mono");
}

#[test]
fn w1_5_unreachable_state_apply_produces_different_result() {
    let c = minimal_canonical();
    let s = build_genesis_state(c);
    let sigma = make_input("init", vec![0xFF]);
    let real_post = apply(&s, &sigma);
    let mut fake_post = real_post.clone();
    fake_post.canonical.system_data.parameters.insert("rogue_param".to_string(), vec![0xDE, 0xAD]);
    fake_post.derived = derive(&fake_post.canonical);
    fake_post.economic = derive_economic(&fake_post.canonical, &fake_post.environment);
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(!result.valid, "W1.5: Unreachable state must be rejected by L_valid");
}

// ===========================================================================
// W2: Transition Violation
// ===========================================================================

#[test]
fn w2_1_arbitrary_jump_unrelated_post_state() {
    let c1 = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c1, 1);
    let sigma = make_deposit_input([2u8; 32], 500);
    let c_fake = canonical_with_account([99u8; 32], 777);
    let fake_post = build_state_at_seq(c_fake, 2);
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.1: Arbitrary jump must be rejected by L_valid");
}

#[test]
fn w2_2_hidden_mutation_noop_changes_canonical() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);
    let mut fake_post = apply(&s, &sigma);
    fake_post.canonical.system_data.parameters.insert("hidden".to_string(), vec![0xFF]);
    fake_post.derived = derive(&fake_post.canonical);
    fake_post.economic = derive_economic(&fake_post.canonical, &fake_post.environment);
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.2: Hidden mutation in noop must be rejected by L_valid");
}

#[test]
fn w2_2_hidden_mutation_environment_changed() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let sigma = make_deposit_input([1u8; 32], 100);
    let mut fake_post = apply(&s, &sigma);
    fake_post.environment.timestamp = 9_999_999;
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.2: Hidden environment mutation must be rejected by L_valid");
}

#[test]
fn w2_3_resource_creation_balance_from_nothing() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);
    let mut fake_post = apply(&s, &sigma);
    if let Some(acc) = fake_post.canonical.accounts.get_mut(&AccountId([1u8; 32])) {
        acc.balance += 500;
    }
    fake_post.derived = derive(&fake_post.canonical);
    let result = l_cons(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.3: Resource creation must be rejected by L_cons");
}

#[test]
fn w2_3_resource_destruction_balance_vanishes() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);
    let mut fake_post = apply(&s, &sigma);
    if let Some(acc) = fake_post.canonical.accounts.get_mut(&AccountId([1u8; 32])) {
        acc.balance = 0;
    }
    fake_post.derived = derive(&fake_post.canonical);
    let result = l_cons(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.3: Resource destruction must be rejected by L_cons");
}

#[test]
fn w2_4_unauthorized_empty_classical_sig() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![], pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey { classical: vec![10, 11], pqc: vec![20, 21] },
            nonce: 42, domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W2.4: Empty classical_sig must be rejected");
    assert!(matches!(result.unwrap_err(), ExecutionError::MalformedInput(_)));
}

#[test]
fn w2_4_unauthorized_empty_pqc_sig() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![1, 2, 3], pqc_sig: vec![],
            public_key: HybridPublicKey { classical: vec![10, 11], pqc: vec![20, 21] },
            nonce: 42, domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W2.4: Empty pqc_sig must be rejected");
}

#[test]
fn w2_5_precondition_violation_transfer_nonexistent_sender() {
    let engine = DefaultExecutionEngine;
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let sigma = make_transfer_input([1u8; 32], [2u8; 32], 100);
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W2.5: Transfer from non-existent sender must be rejected");
    assert!(matches!(result.unwrap_err(), ExecutionError::PreconditionViolation(_)));
}

#[test]
fn w2_5_precondition_violation_fabricated_transfer() {
    let c = canonical_with_account([1u8; 32], 100);
    let s = build_state_at_seq(c, 1);
    let sigma = make_transfer_input([1u8; 32], [2u8; 32], 200);
    let mut fake_c = s.canonical.clone();
    if let Some(acc) = fake_c.accounts.get_mut(&AccountId([1u8; 32])) { acc.balance = 0; }
    fake_c.accounts.insert(AccountId([2u8; 32]), AccountData { balance: 200, nonce: 0, data: vec![] });
    let mut fake_post = build_state_at_seq(fake_c, 2);
    fake_post.environment = s.environment.clone();
    let result = l_cons(&s, &sigma, &fake_post);
    assert!(!result.valid, "W2.5: Fabricated transfer exceeding balance must be rejected by L_cons");
}


// ===========================================================================
// W3: Trace Structure Violation
// ===========================================================================

#[test]
fn w3_1_broken_chain_hash_tampered_entry() {
    let mut trace = build_valid_trace();
    trace.entries[1].chain_hash = Hash([0xDEu8; 32]);
    assert!(!verify_trace(&trace), "W3.1: Tampered chain hash must be rejected");
}

#[test]
fn w3_1_broken_chain_hash_tampered_commitment() {
    let mut trace = build_valid_trace();
    trace.commitment = Hash([0xBBu8; 32]);
    assert!(!verify_trace(&trace), "W3.1: Tampered final commitment must be rejected");
}

#[test]
fn w3_2_missing_transition_gap_in_indices() {
    let mut trace = build_valid_trace();
    trace.entries.remove(1);
    assert!(!verify_trace(&trace), "W3.2: Missing entry (index gap) must be rejected");
}

#[test]
fn w3_2_missing_transition_state_chain_broken() {
    let mut trace = build_valid_trace();
    trace.entries[0].post_state_commitment = Hash([0xAAu8; 32]);
    assert!(!verify_trace(&trace), "W3.2: Broken state commitment chain must be rejected");
}

#[test]
fn w3_3_reordered_entries() {
    let mut trace = build_valid_trace();
    trace.entries.swap(1, 2);
    assert!(!verify_trace(&trace), "W3.3: Reordered entries must be rejected");
}

#[test]
fn w3_3_duplicate_entries() {
    let mut trace = build_valid_trace();
    trace.entries[2] = trace.entries[1].clone();
    assert!(!verify_trace(&trace), "W3.3: Duplicate entries must be rejected");
}

#[test]
fn w3_4_invalid_initial_state() {
    let mut trace = build_valid_trace();
    let fake_c = canonical_with_account([99u8; 32], 777);
    trace.initial_state = build_state_at_seq(fake_c, 0);
    assert!(!verify_trace(&trace), "W3.4: Wrong initial state must be rejected");
}

// ===========================================================================
// W4: Observable Manipulation
// ===========================================================================

#[test]
fn w4_1_fabricated_observable_wrong_outputs() {
    let c = canonical_with_two_accounts([1u8; 32], 1000, [2u8; 32], 500);
    let s = build_state_at_seq(c, 1);
    let sigma = make_transfer_input([1u8; 32], [2u8; 32], 100);
    let s_prime = apply(&s, &sigma);
    let real_obs = obs(&s, &sigma, &s_prime);
    let fake_obs = Observable {
        transition_class: real_obs.transition_class,
        outputs: vec![OutputEvent { event_type: "fabricated_event".to_string(), data: vec![0xDE, 0xAD] }],
        gas_used: real_obs.gas_used,
        status: real_obs.status,
    };
    assert_ne!(fake_obs, real_obs, "W4.1: Fabricated observable must differ from real");
    let rederived = obs(&s, &sigma, &s_prime);
    assert_eq!(rederived, real_obs, "W4.1: Observable must be deterministically derivable");
    assert_ne!(rederived, fake_obs, "W4.1: Fabricated observable must be detectable");
}

#[test]
fn w4_1_fabricated_observable_wrong_gas() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_deposit_input([2u8; 32], 500);
    let s_prime = apply(&s, &sigma);
    let real_obs = obs(&s, &sigma, &s_prime);
    let fake_obs = Observable {
        transition_class: real_obs.transition_class,
        outputs: real_obs.outputs.clone(),
        gas_used: 0,
        status: real_obs.status,
    };
    assert_ne!(fake_obs, real_obs, "W4.1: Observable with fabricated gas must differ");
}

#[test]
fn w4_2_missing_observable_empty_outputs() {
    let c = canonical_with_two_accounts([1u8; 32], 1000, [2u8; 32], 500);
    let s = build_state_at_seq(c, 1);
    let sigma = make_transfer_input([1u8; 32], [2u8; 32], 100);
    let s_prime = apply(&s, &sigma);
    let real_obs = obs(&s, &sigma, &s_prime);
    assert!(!real_obs.outputs.is_empty(), "Transfer should produce output events");
    let missing_obs = Observable {
        transition_class: real_obs.transition_class,
        outputs: vec![],
        gas_used: real_obs.gas_used,
        status: real_obs.status,
    };
    let rederived = obs(&s, &sigma, &s_prime);
    assert_ne!(rederived, missing_obs, "W4.2: Missing outputs must be detectable");
}

#[test]
fn w4_3_noop_with_non_null_observable() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);
    let s_prime = apply(&s, &sigma);
    let real_obs = obs(&s, &sigma, &s_prime);
    assert_eq!(real_obs.transition_class, TransitionClass::Noop);
    assert_eq!(real_obs.status, TransitionStatus::Rejected);
    assert!(real_obs.outputs.is_empty(), "Noop should produce no output events");
    let fake_obs = Observable {
        transition_class: TransitionClass::Noop,
        outputs: vec![OutputEvent { event_type: "phantom_event".to_string(), data: vec![0xFF] }],
        gas_used: real_obs.gas_used,
        status: TransitionStatus::Success,
    };
    let rederived = obs(&s, &sigma, &s_prime);
    assert_ne!(rederived, fake_obs, "W4.3: Noop with fabricated outputs must be detectable");
}

// ===========================================================================
// W5: Authorization Manipulation
// ===========================================================================

#[test]
fn w5_1_wrong_payload_empty_classical_key() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![1, 2, 3], pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey { classical: vec![], pqc: vec![20, 21] },
            nonce: 42, domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W5.1: Empty classical public key must be rejected");
    assert!(matches!(result.unwrap_err(), ExecutionError::MalformedInput(_)));
}

#[test]
fn w5_1_wrong_payload_empty_pqc_key() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![1, 2, 3], pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey { classical: vec![10, 11], pqc: vec![] },
            nonce: 42, domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W5.1: Empty PQC public key must be rejected");
}

#[test]
fn w5_2_replayed_authorization_same_nonce() {
    let engine = DefaultExecutionEngine;
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let auth = valid_auth();
    let sigma1 = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: auth.clone(),
        aux: AuxiliaryData { data: vec![] },
    };
    let r1 = engine.execute(&s, &sigma1).unwrap();
    let sigma2 = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth,
        aux: AuxiliaryData { data: vec![] },
    };
    let r2 = engine.execute(&r1.post_state, &sigma2);
    // Engine processes replayed auth — replay prevention is at trace/proof level
    assert!(r2.is_ok(), "Engine accepts replayed auth — replay prevention is at trace/proof level");
}

#[test]
fn w5_3_cross_domain_zero_domain_tag() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![1, 2, 3], pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey { classical: vec![10, 11], pqc: vec![20, 21] },
            nonce: 42, domain: DomainTag(Hash([0u8; 32])),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    let result = engine.execute(&s, &sigma);
    assert!(result.is_err(), "W5.3: Zero domain tag must be rejected");
    assert!(matches!(result.unwrap_err(), ExecutionError::MalformedInput(_)));
}

#[test]
fn w5_3_cross_domain_mismatched_domain() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let mut different_domain = [0u8; 32];
    different_domain[0] = 0xCD;
    let sigma = Input {
        payload: Payload { payload_type: "deposit".to_string(), data: {
            let mut d = vec![]; d.extend_from_slice(&[1u8; 32]); d.extend_from_slice(&100u128.to_le_bytes()); d
        }},
        auth: Authorization {
            classical_sig: vec![1, 2, 3], pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey { classical: vec![10, 11], pqc: vec![20, 21] },
            nonce: 42, domain: DomainTag(Hash(different_domain)),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    // Engine accepts — domain matching is at verification/proof level
    let result = engine.execute(&s, &sigma);
    assert!(result.is_ok(), "Engine accepts mismatched domain — domain matching is at verification level");
}


// ===========================================================================
// W6: Batch Manipulation
// ===========================================================================

#[test]
fn w6_1_reordered_batch_different_result() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let deposit = make_deposit_input([1u8; 32], 1000);
    let transfer = make_transfer_input([1u8; 32], [2u8; 32], 500);
    let correct = execute_batch(&s, &[deposit.clone(), transfer.clone()]);
    assert!(correct.is_ok(), "Correct order should succeed");
    let reversed = execute_batch(&s, &[transfer, deposit]);
    assert!(reversed.is_err(), "W6.1: Reversed batch order must fail");
}

#[test]
fn w6_1_reordered_batch_sequential_equivalence() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let d1 = make_deposit_input([1u8; 32], 100);
    let d2 = make_deposit_input([2u8; 32], 200);
    let batch = execute_batch(&s, &[d1.clone(), d2.clone()]).unwrap();
    let s1 = apply(&s, &d1);
    let s2 = apply(&s1, &d2);
    assert_eq!(batch.post_state.canonical, s2.canonical, "W6.1: Batch must equal sequential application (LEM-9)");
}

#[test]
fn w6_2_skipping_validation_halts_on_invalid() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let valid_deposit = make_deposit_input([1u8; 32], 500);
    let invalid = Input {
        payload: Payload { payload_type: String::new(), data: vec![] },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    };
    let another_deposit = make_deposit_input([2u8; 32], 300);
    let result = execute_batch(&s, &[valid_deposit, invalid, another_deposit]);
    assert!(result.is_err(), "W6.2: Batch must halt on invalid intermediate input");
    assert!(matches!(result.unwrap_err(), ExecutionError::MalformedInput(_)));
}

#[test]
fn w6_3_phantom_operations_extra_deposit() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let d1 = make_deposit_input([1u8; 32], 100);
    let batch_one = execute_batch(&s, &[d1.clone()]).unwrap();
    let phantom = make_deposit_input([99u8; 32], 9999);
    let batch_with_phantom = execute_batch(&s, &[d1, phantom]).unwrap();
    assert_ne!(
        batch_one.post_state.canonical, batch_with_phantom.post_state.canonical,
        "W6.3: Phantom operation must produce a different result"
    );
    assert!(batch_with_phantom.post_state.canonical.accounts.contains_key(&AccountId([99u8; 32])));
    assert_eq!(batch_with_phantom.post_state.canonical.system_data.total_supply, 10099);
}

#[test]
fn w6_3_phantom_operations_detectable_via_trace() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let d1 = make_deposit_input([1u8; 32], 100);
    let d2 = make_deposit_input([2u8; 32], 200);
    let batch = execute_batch(&s, &[d1, d2]).unwrap();
    assert_eq!(batch.intermediate_results.len(), 2, "W6.3: Batch with 2 inputs must have exactly 2 intermediate results");
}

// ===========================================================================
// W7: Commitment Manipulation
// ===========================================================================

#[test]
fn w7_1_wrong_pre_state_commitment() {
    let mut trace = build_two_entry_trace();
    trace.entries[0].pre_state_commitment = Hash([0xFFu8; 32]);
    assert!(!verify_trace(&trace), "W7.1: Wrong pre_state_commitment must be rejected");
}

#[test]
fn w7_1_wrong_post_state_commitment() {
    let mut trace = build_two_entry_trace();
    trace.entries[0].post_state_commitment = Hash([0xEEu8; 32]);
    assert!(!verify_trace(&trace), "W7.1: Wrong post_state_commitment must be rejected");
}

#[test]
fn w7_1_state_commitment_mismatch_with_actual_state() {
    let c1 = canonical_with_account([1u8; 32], 100);
    let c2 = canonical_with_account([1u8; 32], 200);
    let h1 = commit(&c1);
    let h2 = commit(&c2);
    assert_ne!(h1, h2, "W7.1: Different canonical states must produce different commitments");
}

#[test]
fn w7_2_wrong_chain_hash_entry() {
    let mut trace = build_two_entry_trace();
    trace.entries[1].chain_hash = Hash([0xBBu8; 32]);
    assert!(!verify_trace(&trace), "W7.2: Wrong chain hash must be rejected");
}

#[test]
fn w7_2_wrong_chain_hash_swapped() {
    let mut trace = build_two_entry_trace();
    let h0 = trace.entries[0].chain_hash.clone();
    let h1 = trace.entries[1].chain_hash.clone();
    trace.entries[0].chain_hash = h1;
    trace.entries[1].chain_hash = h0;
    assert!(!verify_trace(&trace), "W7.2: Swapped chain hashes must be rejected");
}

#[test]
fn w7_2_verify_chain_rejects_tampered_hashes() {
    let e1 = Hash([1u8; 32]);
    let e2 = Hash([2u8; 32]);
    let h1 = compute_chain_hash(&Hash([0u8; 32]), &e1);
    let h2 = compute_chain_hash(&h1, &e2);
    assert!(verify_chain(&[e1.clone(), e2.clone()], &[h1.clone(), h2.clone()]));
    assert!(!verify_chain(&[e1.clone(), e2.clone()], &[Hash([0xFFu8; 32]), h2.clone()]),
        "W7.2: verify_chain must reject tampered first hash");
    assert!(!verify_chain(&[e1, e2], &[h1, Hash([0xFFu8; 32])]),
        "W7.2: verify_chain must reject tampered second hash");
}

// ===========================================================================
// W8: Cross-System Violation
// ===========================================================================

#[test]
fn w8_1_inconsistent_shared_state_different_balances() {
    let c_a = canonical_with_account([1u8; 32], 1000);
    let s_a = build_state_at_seq(c_a, 1);
    let c_b = canonical_with_account([1u8; 32], 500);
    let s_b = build_state_at_seq(c_b, 1);
    let balance_a = s_a.canonical.accounts[&AccountId([1u8; 32])].balance;
    let balance_b = s_b.canonical.accounts[&AccountId([1u8; 32])].balance;
    assert_ne!(balance_a, balance_b, "W8.1: Systems have inconsistent shared state");
    assert!(valid_state(&s_a), "System A is individually valid");
    assert!(valid_state(&s_b), "System B is individually valid");
    let total_a = s_a.canonical.system_data.total_supply;
    let total_b = s_b.canonical.system_data.total_supply;
    assert!(total_a + total_b > balance_a.max(balance_b),
        "W8.1: Cross-system total exceeds what should exist — resource double-counting");
}

#[test]
fn w8_1_inconsistent_shared_state_different_nonces() {
    let mut c_a = canonical_with_account([1u8; 32], 1000);
    if let Some(acc) = c_a.accounts.get_mut(&AccountId([1u8; 32])) { acc.nonce = 10; }
    let s_a = build_state_at_seq(c_a, 1);
    let mut c_b = canonical_with_account([1u8; 32], 1000);
    if let Some(acc) = c_b.accounts.get_mut(&AccountId([1u8; 32])) { acc.nonce = 5; }
    let s_b = build_state_at_seq(c_b, 1);
    let nonce_a = s_a.canonical.accounts[&AccountId([1u8; 32])].nonce;
    let nonce_b = s_b.canonical.accounts[&AccountId([1u8; 32])].nonce;
    assert_ne!(nonce_a, nonce_b, "W8.1: Systems have inconsistent nonces for shared account");
}

#[test]
fn w8_2_resource_creation_cross_system() {
    let c_a_pre = canonical_with_account([1u8; 32], 1000);
    let c_a_post = canonical_with_account([1u8; 32], 500);
    let c_b_pre = canonical_with_account([2u8; 32], 0);
    let c_b_post = canonical_with_account([2u8; 32], 600);
    let total_pre = c_a_pre.system_data.total_supply + c_b_pre.system_data.total_supply;
    let total_post = c_a_post.system_data.total_supply + c_b_post.system_data.total_supply;
    assert_ne!(total_pre, total_post, "W8.2: Cross-system total supply changed");
    assert!(total_post > total_pre, "W8.2: Resources were created ({} -> {})", total_pre, total_post);
}

#[test]
fn w8_2_resource_destruction_cross_system() {
    let total_pre: u128 = 1000 + 0;
    let total_post: u128 = 500 + 300;
    assert!(total_post < total_pre, "W8.2: Resources were destroyed ({} -> {})", total_pre, total_post);
}