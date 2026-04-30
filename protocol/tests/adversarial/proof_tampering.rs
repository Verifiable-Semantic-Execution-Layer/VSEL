//! Adversarial proof tampering test suite — Task 25.3.3
//!
//! Generates proofs with tampered witnesses and verifies the verifier
//! rejects each tampered proof. Tests constraint system version mismatch
//! rejection as well.
//!
//! **Validates: Requirements 8.2, 8.4, 8.8**
//! _Remediates: M-003 from ULTRA_ADVERSARIAL_AUDIT.md_

use std::collections::BTreeMap;

use vsel_constraints::{
    Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
};
use vsel_core::input::{Authorization, Input};
use vsel_core::observable::{Observable, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::TransitionClass;
use vsel_core::types::*;
use vsel_proof::prover::{DefaultProver, Prover};
use vsel_proof::verifier::{
    DefaultVerifier, RejectionReason, VerificationResult, VerificationStep, Verifier,
};
use vsel_proof::witness::{construct_witness, WitnessEncoding};
use vsel_trace::engine::{Trace, TraceEntry};

// ===========================================================================
// Test helpers
// ===========================================================================

fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
}

fn test_version() -> ProtocolVersion {
    ProtocolVersion {
        major: 1,
        minor: 0,
        patch: 0,
    }
}

fn minimal_canonical() -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: test_version(),
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

fn test_state() -> State {
    let c = minimal_canonical();
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    let meta = TraceMetadata {
        sequence_index: 0,
        previous_commitment: Hash([0u8; 32]),
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

fn test_input() -> Input {
    Input {
        payload: Payload {
            payload_type: "transfer".to_string(),
            data: vec![1, 2, 3],
        },
        auth: Authorization {
            classical_sig: vec![1; 64],
            pqc_sig: vec![2; 128],
            public_key: HybridPublicKey {
                classical: vec![3; 32],
                pqc: vec![4; 64],
            },
            nonce: 1,
            domain: test_domain_tag(),
        },
        aux: AuxiliaryData {
            data: vec![0xAA, 0xBB],
        },
    }
}

fn test_observable() -> Observable {
    Observable {
        transition_class: TransitionClass::Update,
        outputs: vec![OutputEvent {
            event_type: "balance_change".to_string(),
            data: vec![1, 2, 3],
        }],
        gas_used: 21_000,
        status: TransitionStatus::Success,
    }
}

fn test_trace(num_entries: usize) -> Trace {
    let initial_state = test_state();
    let init_commit = commit(&initial_state.canonical);
    let mut entries = Vec::new();

    for i in 0..num_entries {
        let pre_commit = if i == 0 {
            init_commit.clone()
        } else {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            Hash(h)
        };
        let mut post_hash = [0u8; 32];
        post_hash[0] = (i + 1) as u8;
        let mut chain = [0u8; 32];
        chain[0] = (i + 100) as u8;

        entries.push(TraceEntry {
            index: i as u64,
            pre_state_commitment: pre_commit,
            input: test_input(),
            post_state_commitment: Hash(post_hash),
            observable: test_observable(),
            environment: initial_state.environment.clone(),
            chain_hash: Hash(chain),
        });
    }

    let final_commitment = if let Some(last) = entries.last() {
        last.chain_hash.clone()
    } else {
        Hash([0u8; 32])
    };

    Trace {
        entries,
        initial_state,
        commitment: final_commitment,
    }
}

fn test_constraint_system() -> ConstraintSystem {
    let mut cs = ConstraintSystem::new("1.0.0");
    cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::BoolConstant(true),
        category: ConstraintCategory::Structural,
        description: "test constraint".to_string(),
    });
    cs
}

fn make_valid_proof_and_witness() -> (
    vsel_proof::prover::Proof,
    vsel_proof::public_inputs::PublicInputs,
    vsel_proof::witness::Witness,
    ConstraintSystem,
) {
    let prover = DefaultProver::new("0.1.0-test");
    let trace = test_trace(2);
    let cs = test_constraint_system();
    let proof = prover.prove(&trace, &cs).expect("proof generation");
    let public_inputs = proof.public_inputs.clone();
    let witness = construct_witness(&trace);
    (proof, public_inputs, witness, cs)
}

fn default_verifier() -> DefaultVerifier {
    DefaultVerifier::new(test_version())
}

// ===========================================================================
// Adversarial proof tampering tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Tampered witness: modified intermediate state
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_modified_intermediate_state() {
    let verifier = default_verifier();
    let (proof, pub_inputs, mut witness, cs) = make_valid_proof_and_witness();

    // Tamper with the witness: modify intermediate state.
    // Add a fake intermediate state that doesn't match the proof.
    let mut fake_state = test_state();
    fake_state.canonical.system_data.total_supply = 999_999;
    witness.intermediate_states.push(fake_state);

    // The verifier should reject because the witness commitment
    // no longer matches the proof's witness commitment.
    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with tampered intermediate state"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(
            step,
            VerificationStep::ConstraintSatisfaction,
            "Rejection must occur at constraint satisfaction step"
        );
        assert_eq!(
            reason,
            RejectionReason::ConstraintViolation,
            "Rejection reason must be ConstraintViolation"
        );
    }
}

// ---------------------------------------------------------------------------
// Tampered witness: altered input
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_altered_input() {
    let verifier = default_verifier();
    let (proof, pub_inputs, mut witness, cs) = make_valid_proof_and_witness();

    // Tamper with the witness: alter an input's payload data.
    if let Some(input) = witness.input_sequence.first_mut() {
        input.payload.data = vec![0xFF, 0xFE, 0xFD]; // Different data
    }

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with altered input in witness"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Tampered witness: altered input nonce
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_altered_nonce() {
    let verifier = default_verifier();
    let (proof, pub_inputs, mut witness, cs) = make_valid_proof_and_witness();

    // Tamper with the witness: change an input's auth nonce.
    if let Some(input) = witness.input_sequence.first_mut() {
        input.auth.nonce = 999_999;
    }

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with altered nonce in witness"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Tampered witness: wrong observable (via altered aux computation)
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_altered_aux_computation() {
    let verifier = default_verifier();
    let (proof, pub_inputs, mut witness, cs) = make_valid_proof_and_witness();

    // Tamper with the witness: add extra auxiliary computation values.
    witness
        .aux_computation
        .add("fake_commitment".to_string(), vec![0xDE, 0xAD]);

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with tampered auxiliary computation"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Tampered witness: removed input from sequence
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_removed_input() {
    let verifier = default_verifier();
    let (proof, pub_inputs, mut witness, cs) = make_valid_proof_and_witness();

    // Tamper with the witness: remove an input.
    if !witness.input_sequence.is_empty() {
        witness.input_sequence.pop();
    }

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with removed input from witness"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Wrong constraint system version
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_constraint_system_version() {
    let verifier = default_verifier();
    let (proof, pub_inputs, witness, _cs) = make_valid_proof_and_witness();

    // Use a different constraint system version.
    let mut wrong_cs = ConstraintSystem::new("2.0.0"); // Different version
    wrong_cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::BoolConstant(true),
        category: ConstraintCategory::Structural,
        description: "test constraint".to_string(),
    });

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &wrong_cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with wrong constraint system version"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Wrong constraint system: different constraints
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_constraint_system_different_constraints() {
    let verifier = default_verifier();
    let (proof, pub_inputs, witness, _cs) = make_valid_proof_and_witness();

    // Use a constraint system with different constraints.
    let mut wrong_cs = ConstraintSystem::new("1.0.0"); // Same version
    wrong_cs.add_constraint(Constraint {
        id: ConstraintId(99),
        expr: ConstraintExpr::BoolConstant(false), // Always fails
        category: ConstraintCategory::Semantic,
        description: "adversarial constraint".to_string(),
    });

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &wrong_cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with different constraint system"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}

// ---------------------------------------------------------------------------
// Valid proof with constraints passes
// ---------------------------------------------------------------------------

#[test]
fn test_valid_proof_with_constraints_accepted() {
    let verifier = default_verifier();
    let (proof, pub_inputs, witness, cs) = make_valid_proof_and_witness();

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &witness, &cs);
    assert_eq!(
        result,
        VerificationResult::Accepted,
        "Valid proof with matching witness and constraints must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Standard verification still works (backward compatibility)
// ---------------------------------------------------------------------------

#[test]
fn test_standard_verification_backward_compatible() {
    let verifier = default_verifier();
    let prover = DefaultProver::new("0.1.0-test");
    let trace = test_trace(2);
    let cs = test_constraint_system();
    let proof = prover.prove(&trace, &cs).expect("proof");
    let pub_inputs = proof.public_inputs.clone();

    // Standard verify (without constraints) must still work.
    let result = verifier.verify(&proof, &pub_inputs);
    assert_eq!(
        result,
        VerificationResult::Accepted,
        "Standard verification must remain backward compatible"
    );
}

// ---------------------------------------------------------------------------
// Witness encoding completeness
// ---------------------------------------------------------------------------

#[test]
fn test_witness_encoding_completeness() {
    let trace = test_trace(3);
    let witness = construct_witness(&trace);
    let encoding = WitnessEncoding::from_witness(&witness);

    assert!(
        encoding.verify_completeness(&witness),
        "Witness encoding must be complete and consistent"
    );
    assert_eq!(encoding.input_count, witness.input_sequence.len());
    assert_eq!(
        encoding.intermediate_state_count,
        witness.intermediate_states.len()
    );
    assert_eq!(encoding.aux_count, witness.aux_computation.values.len());
}

// ---------------------------------------------------------------------------
// Witness encoding detects tampering
// ---------------------------------------------------------------------------

#[test]
fn test_witness_encoding_detects_tampering() {
    let trace = test_trace(3);
    let witness = construct_witness(&trace);
    let encoding = WitnessEncoding::from_witness(&witness);

    // Tamper with the witness after encoding.
    let mut tampered = witness.clone();
    if let Some(input) = tampered.input_sequence.first_mut() {
        input.payload.data = vec![0xFF];
    }

    assert!(
        !encoding.verify_completeness(&tampered),
        "Witness encoding must detect tampering"
    );
}

// ---------------------------------------------------------------------------
// Tampered witness: completely empty witness
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_witness_empty() {
    let verifier = default_verifier();
    let (proof, pub_inputs, _witness, cs) = make_valid_proof_and_witness();

    // Use a completely empty witness.
    let empty_witness = vsel_proof::witness::Witness {
        intermediate_states: vec![],
        input_sequence: vec![],
        aux_computation: vsel_proof::witness::AuxiliaryComputation::empty(),
    };

    let result = verifier.verify_with_constraints(&proof, &pub_inputs, &empty_witness, &cs);
    assert!(
        result.is_rejected(),
        "Verifier must reject proof with empty witness"
    );
}

// ---------------------------------------------------------------------------
// Constraint with BoolConstant(false) always rejects
// ---------------------------------------------------------------------------

#[test]
fn test_unsatisfiable_constraint_rejects() {
    let verifier = default_verifier();
    let (_proof, _pub_inputs, _witness, _cs) = make_valid_proof_and_witness();

    // Build a constraint system with an unsatisfiable constraint.
    // We need the constraint commitment to match, so we build a proof
    // with this constraint system.
    let mut bad_cs = ConstraintSystem::new("1.0.0");
    bad_cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::BoolConstant(false), // Always fails
        category: ConstraintCategory::Structural,
        description: "unsatisfiable constraint".to_string(),
    });

    // Generate a proof with the bad constraint system so commitments match.
    let prover = DefaultProver::new("0.1.0-test");
    let trace = test_trace(2);
    let proof_with_bad_cs = prover.prove(&trace, &bad_cs).expect("proof");
    let pub_inputs_bad = proof_with_bad_cs.public_inputs.clone();
    let witness_bad = construct_witness(&trace);

    let result = verifier.verify_with_constraints(
        &proof_with_bad_cs,
        &pub_inputs_bad,
        &witness_bad,
        &bad_cs,
    );
    assert!(
        result.is_rejected(),
        "Verifier must reject proof when constraint evaluates to false"
    );
    if let VerificationResult::Rejected { reason, step } = result {
        assert_eq!(step, VerificationStep::ConstraintSatisfaction);
        assert_eq!(reason, RejectionReason::ConstraintViolation);
    }
}
