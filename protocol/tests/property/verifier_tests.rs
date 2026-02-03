//! Property-based tests for the VSEL Verification Pipeline (vsel-proof::verifier).
//!
//! Uses `proptest` to verify correctness properties derived from
//! VERIFICATION_LAYER.md, PROOF_LAYER.md §5, Requirements 7.1, 8.2–8.9.
//!
//! **Property 32: Proof Soundness (THM-8)** — `verify(π, pub) = Accepted ⟹ valid_trace(τ)`
//! **Validates: Requirements 7.1, 8.2, 8.9**
//!
//! **Property 39: Verifier Domain Correctness** — proofs with wrong domain are rejected
//! **Validates: Requirements 8.3**
//!
//! **Property 40: Malformed Proof Rejection** — all structurally invalid proofs rejected immediately
//! **Validates: Requirements 8.4**
//!
//! **Property 41: Stateful Verification Continuity** — `root_prev = root_expected` enforced
//! **Validates: Requirements 8.5**
//!
//! **Property 42: Version Compatibility Enforcement** — old proofs rejected under new semantics unless allowed
//! **Validates: Requirements 8.6**

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_constraints::{
    Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
};
use vsel_core::input::*;
use vsel_core::observable::{Observable, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::TransitionClass;
use vsel_core::types::*;
use vsel_crypto::domain::proof_tag;
use vsel_proof::prover::{DefaultProver, Prover};
use vsel_proof::public_inputs::PublicInputs;
use vsel_proof::verifier::{
    DefaultVerifier, RejectionReason, StatefulVerifier, VerificationResult, VerificationStep,
    Verifier,
};
use vsel_trace::engine::{Trace, TraceEntry};

// ---------------------------------------------------------------------------
// Arbitrary strategies (same patterns as proof_tests.rs)
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

fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
    prop::collection::vec(any::<u8>(), 1..64).prop_map(StorageKey)
}

fn arb_storage_value() -> impl Strategy<Value = StorageValue> {
    prop::collection::vec(any::<u8>(), 0..128).prop_map(StorageValue)
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
        prop::collection::btree_map(arb_account_id(), arb_account_data(), 0..5),
        prop::collection::btree_map(arb_storage_key(), arb_storage_value(), 0..5),
        arb_protocol_version(),
    )
        .prop_map(|(accounts, storage, protocol_version)| {
            let total_supply: u128 = accounts.values().map(|a| a.balance).sum();
            CanonicalState {
                accounts,
                storage,
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

fn arb_trace_metadata() -> impl Strategy<Value = TraceMetadata> {
    (0u64..=1_000_000u64, 0u64..=100u64).prop_map(|(timestamp, epoch)| TraceMetadata {
        sequence_index: 0,
        previous_commitment: Hash([0u8; 32]),
        epoch,
        timestamp,
    })
}

fn arb_valid_state() -> impl Strategy<Value = State> {
    (arb_canonical_state(), arb_environment(), arb_trace_metadata()).prop_map(
        |(canonical, environment, metadata)| {
            let derived = derive(&canonical);
            let economic = derive_economic(&canonical, &environment);
            State {
                canonical,
                derived,
                environment,
                economic,
                metadata,
            }
        },
    )
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

fn arb_valid_input() -> impl Strategy<Value = Input> {
    (
        "[a-z]{1,20}",
        prop::collection::vec(any::<u8>(), 1..128),
        arb_valid_authorization(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(payload_type, data, auth, aux_data)| Input {
            payload: Payload {
                payload_type,
                data,
            },
            auth,
            aux: AuxiliaryData { data: aux_data },
        })
}

fn arb_observable() -> impl Strategy<Value = Observable> {
    (
        prop_oneof![
            Just(TransitionClass::Update),
            Just(TransitionClass::Init),
            Just(TransitionClass::Noop),
        ],
        0u64..=1_000_000u64,
    )
        .prop_map(|(class, gas)| {
            let status = match class {
                TransitionClass::Update | TransitionClass::Init => TransitionStatus::Success,
                _ => TransitionStatus::Rejected,
            };
            Observable {
                transition_class: class,
                outputs: vec![],
                gas_used: gas,
                status,
            }
        })
}

// ---------------------------------------------------------------------------
// Trace construction helpers
// ---------------------------------------------------------------------------

/// Build a valid trace from an initial state and a sequence of inputs.
fn build_trace(initial_state: State, inputs: Vec<Input>, observables: Vec<Observable>) -> Trace {
    let init_commit = commit(&initial_state.canonical);
    let mut entries = Vec::new();
    let mut prev_chain = Hash([0u8; 32]);

    for (i, (input, obs)) in inputs.into_iter().zip(observables.into_iter()).enumerate() {
        let pre_commit = if i == 0 {
            init_commit.clone()
        } else {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = (i >> 8) as u8;
            Hash(h)
        };
        let mut post_hash = [0u8; 32];
        post_hash[0] = (i + 1) as u8;
        post_hash[1] = ((i + 1) >> 8) as u8;

        let mut chain_data = Vec::new();
        chain_data.extend_from_slice(&prev_chain.0);
        chain_data.extend_from_slice(&pre_commit.0);
        chain_data.extend_from_slice(&post_hash);
        chain_data.extend_from_slice(&(i as u64).to_le_bytes());
        let chain_hash = {
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&chain_data);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash(bytes)
        };

        entries.push(TraceEntry {
            index: i as u64,
            pre_state_commitment: pre_commit,
            input,
            post_state_commitment: Hash(post_hash),
            observable: obs,
            environment: initial_state.environment.clone(),
            chain_hash: chain_hash.clone(),
        });

        prev_chain = chain_hash;
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

/// Build a minimal constraint system for testing.
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

/// Strategy for generating a valid trace with 1-5 entries.
fn arb_valid_trace() -> impl Strategy<Value = Trace> {
    (arb_valid_state(), 1usize..=5)
        .prop_flat_map(|(state, n)| {
            let inputs = prop::collection::vec(arb_valid_input(), n);
            let observables = prop::collection::vec(arb_observable(), n);
            (Just(state), inputs, observables)
        })
        .prop_map(|(state, inputs, observables)| build_trace(state, inputs, observables))
}

// ---------------------------------------------------------------------------
// Helper: generate a valid proof from a trace
// ---------------------------------------------------------------------------

/// Generate a valid proof from a trace, returning (proof, public_inputs, version).
fn make_valid_proof_from_trace(trace: &Trace) -> (vsel_proof::prover::Proof, PublicInputs) {
    let prover = DefaultProver::new("0.1.0-test");
    let cs = test_constraint_system();
    let proof = prover.prove(trace, &cs).expect("proof generation must succeed");
    let public_inputs = proof.public_inputs.clone();
    (proof, public_inputs)
}

// ---------------------------------------------------------------------------
// Property 32: Proof Soundness (THM-8)
// verify(π, pub) = Accepted ⟹ valid_trace(τ)
// For any valid trace, prove it, then verify it — must be Accepted.
// For any valid proof, corrupting the proof_data must cause rejection.
// **Validates: Requirements 7.1, 8.2, 8.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 32a (Proof Soundness — valid proof accepted): For any valid
    /// trace, generating a proof and verifying it must produce Accepted.
    /// This demonstrates THM-8: verify(π, pub) = Accepted for valid traces.
    ///
    /// **Validates: Requirements 7.1, 8.2, 8.9**
    #[test]
    fn prop_proof_soundness_valid_accepted(
        trace in arb_valid_trace(),
    ) {
        let (proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Accepted,
            "THM-8: verify(π, pub) must be Accepted for a valid proof from a valid trace"
        );
    }

    /// Property 32b (Proof Soundness — corrupted proof rejected): For any
    /// valid proof, corrupting the proof_data must cause rejection.
    /// This demonstrates that invalid proofs are not accepted (Req 8.9).
    ///
    /// **Validates: Requirements 7.1, 8.2, 8.9**
    #[test]
    fn prop_proof_soundness_corrupted_rejected(
        trace in arb_valid_trace(),
        corruption_byte in any::<u8>(),
        corruption_index in any::<prop::sample::Index>(),
    ) {
        let (mut proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        // Corrupt the proof_data at a random position.
        let idx = corruption_index.index(proof.proof_data.len());
        let original = proof.proof_data[idx];
        // Ensure the corruption actually changes the byte.
        let corrupted = if corruption_byte == original {
            original.wrapping_add(1)
        } else {
            corruption_byte
        };
        proof.proof_data[idx] = corrupted;

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert!(
            result.is_rejected(),
            "THM-8: corrupting proof_data must cause rejection, got Accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 39: Verifier Domain Correctness
// Proofs with wrong domain are rejected at DomainValidation step.
// **Validates: Requirements 8.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 39a (Domain Correctness — wrong metadata domain rejected):
    /// For any valid proof, changing the metadata domain must cause rejection
    /// at the DomainValidation step.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_domain_correctness_wrong_metadata_domain(
        trace in arb_valid_trace(),
        bad_domain_bytes in arb_bytes32(),
    ) {
        let (mut proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        // Change the metadata domain to something other than proof_tag().
        let bad_domain = DomainTag(Hash(bad_domain_bytes));
        prop_assume!(bad_domain != proof_tag());
        proof.metadata.domain = bad_domain;

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Rejected {
                reason: RejectionReason::DomainMismatch,
                step: VerificationStep::DomainValidation,
            },
            "Req 8.3: wrong metadata domain must be rejected at DomainValidation"
        );
    }

    /// Property 39b (Domain Correctness — wrong public inputs domain rejected):
    /// For any valid proof, changing the public inputs domain must cause rejection.
    ///
    /// **Validates: Requirements 8.3**
    #[test]
    fn prop_domain_correctness_wrong_public_inputs_domain(
        trace in arb_valid_trace(),
        bad_domain_bytes in arb_bytes32(),
    ) {
        let (proof, mut public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        // Change the external public inputs domain so it differs from proof's.
        let bad_domain = DomainTag(Hash(bad_domain_bytes));
        prop_assume!(bad_domain != proof.public_inputs.domain);
        public_inputs.domain = bad_domain;

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Rejected {
                reason: RejectionReason::DomainMismatch,
                step: VerificationStep::DomainValidation,
            },
            "Req 8.3: wrong public inputs domain must be rejected at DomainValidation"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 40: Malformed Proof Rejection
// All structurally invalid proofs rejected immediately at StructuralValidation.
// **Validates: Requirements 8.4**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 40a (Malformed Proof — empty proof_data rejected): For any
    /// valid proof, emptying proof_data must cause rejection at
    /// StructuralValidation step.
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_malformed_proof_empty_data_rejected(
        trace in arb_valid_trace(),
    ) {
        let (mut proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        // Empty the proof data.
        proof.proof_data = vec![];

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Rejected {
                reason: RejectionReason::MalformedProof,
                step: VerificationStep::StructuralValidation,
            },
            "Req 8.4: empty proof_data must be rejected at StructuralValidation"
        );
    }

    /// Property 40b (Malformed Proof — zeroed commitment rejected): For any
    /// valid proof, zeroing any commitment must cause rejection at
    /// StructuralValidation step.
    ///
    /// **Validates: Requirements 8.4**
    #[test]
    fn prop_malformed_proof_zeroed_commitment_rejected(
        trace in arb_valid_trace(),
        commitment_index in 0u8..3u8,
    ) {
        let (mut proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let version = public_inputs.version.clone();
        let verifier = DefaultVerifier::new(version);

        let zero_hash = Hash([0u8; 32]);

        // Zero out one of the three commitments based on index.
        match commitment_index {
            0 => proof.commitments.trace_commitment = zero_hash,
            1 => proof.commitments.witness_commitment = zero_hash,
            _ => proof.commitments.constraint_commitment = zero_hash,
        }

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Rejected {
                reason: RejectionReason::MalformedProof,
                step: VerificationStep::StructuralValidation,
            },
            "Req 8.4: zeroed commitment (index {}) must be rejected at StructuralValidation",
            commitment_index
        );
    }
}

// ---------------------------------------------------------------------------
// Property 41: Stateful Verification Continuity
// root_prev = root_expected enforced.
// **Validates: Requirements 8.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 41a (Stateful Continuity — chained proofs accepted): For any
    /// two valid proofs where proof1.root_final == proof2.root_init, stateful
    /// verification accepts both in sequence.
    ///
    /// **Validates: Requirements 8.5**
    #[test]
    fn prop_stateful_continuity_chained_accepted(
        trace1 in arb_valid_trace(),
        trace2 in arb_valid_trace(),
    ) {
        let (proof1, pub_inputs1) = make_valid_proof_from_trace(&trace1);
        let version = pub_inputs1.version.clone();

        // Build proof2 from trace2, then patch its root_init to chain from proof1.
        let (mut proof2, _) = make_valid_proof_from_trace(&trace2);

        // Patch proof2 to chain: root_init = proof1.root_final
        proof2.public_inputs.root_init = pub_inputs1.root_final.clone();
        // Ensure domain and version match proof1 for consistency.
        proof2.public_inputs.domain = pub_inputs1.domain.clone();
        proof2.public_inputs.version = pub_inputs1.version.clone();
        // Recompute proof_data so cryptographic verification passes.
        proof2.proof_data = recompute_proof_data(&proof2.commitments, &proof2.public_inputs);
        // Ensure metadata domain is correct.
        proof2.metadata.domain = proof_tag();
        let pub_inputs2 = proof2.public_inputs.clone();

        let mut verifier = StatefulVerifier::new(version);

        let r1 = verifier.verify_stateful(&proof1, &pub_inputs1);
        prop_assert_eq!(
            r1,
            VerificationResult::Accepted,
            "Req 8.5: first proof in chain must be accepted"
        );

        let r2 = verifier.verify_stateful(&proof2, &pub_inputs2);
        prop_assert_eq!(
            r2,
            VerificationResult::Accepted,
            "Req 8.5: second proof chaining from first must be accepted"
        );
    }

    /// Property 41b (Stateful Continuity — broken chain rejected): For any
    /// two valid proofs where proof2.root_init != proof1.root_final, stateful
    /// verification rejects the second.
    ///
    /// **Validates: Requirements 8.5**
    #[test]
    fn prop_stateful_continuity_broken_chain_rejected(
        trace1 in arb_valid_trace(),
        trace2 in arb_valid_trace(),
    ) {
        let (proof1, pub_inputs1) = make_valid_proof_from_trace(&trace1);
        let (mut proof2, _) = make_valid_proof_from_trace(&trace2);

        // Force proof2 to have the same major version as proof1 so the base
        // pipeline doesn't reject at InvariantEnforcement before we reach
        // the stateful continuity check.
        proof2.public_inputs.version.major = pub_inputs1.version.major;
        proof2.public_inputs.version.minor = pub_inputs1.version.minor;
        proof2.public_inputs.version.patch = pub_inputs1.version.patch;
        // Recompute proof_data after patching version.
        proof2.proof_data = recompute_proof_data(&proof2.commitments, &proof2.public_inputs);
        let pub_inputs2 = proof2.public_inputs.clone();

        let version = pub_inputs1.version.clone();

        // Ensure the two proofs don't accidentally chain.
        prop_assume!(pub_inputs2.root_init != pub_inputs1.root_final);

        let mut verifier = StatefulVerifier::new(version);

        let r1 = verifier.verify_stateful(&proof1, &pub_inputs1);
        prop_assert_eq!(
            r1,
            VerificationResult::Accepted,
            "Req 8.5: first proof must be accepted"
        );

        let r2 = verifier.verify_stateful(&proof2, &pub_inputs2);
        prop_assert_eq!(
            r2,
            VerificationResult::Rejected {
                reason: RejectionReason::StateContinuityBroken,
                step: VerificationStep::CommitmentValidation,
            },
            "Req 8.5: proof with root_init != latest_commitment must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 42: Version Compatibility Enforcement
// Old proofs rejected under new semantics unless allowed.
// **Validates: Requirements 8.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 42a (Version Compatibility — different major rejected): For
    /// any valid proof, a verifier with a different major version rejects it.
    ///
    /// **Validates: Requirements 8.6**
    #[test]
    fn prop_version_compatibility_different_major_rejected(
        trace in arb_valid_trace(),
        verifier_major in 0u32..10u32,
    ) {
        let (proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let proof_major = public_inputs.version.major;

        // Ensure the verifier major version differs from the proof's.
        prop_assume!(verifier_major != proof_major);

        let verifier = DefaultVerifier::new(ProtocolVersion {
            major: verifier_major,
            minor: 0,
            patch: 0,
        });

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Rejected {
                reason: RejectionReason::VersionMismatch,
                step: VerificationStep::InvariantEnforcement,
            },
            "Req 8.6: different major version must be rejected at InvariantEnforcement"
        );
    }

    /// Property 42b (Version Compatibility — same major different minor accepted):
    /// For any valid proof, a verifier with the same major but different minor
    /// version accepts it.
    ///
    /// **Validates: Requirements 8.6**
    #[test]
    fn prop_version_compatibility_same_major_different_minor_accepted(
        trace in arb_valid_trace(),
        verifier_minor in 0u32..100u32,
    ) {
        let (proof, public_inputs) = make_valid_proof_from_trace(&trace);
        let proof_major = public_inputs.version.major;

        let verifier = DefaultVerifier::new(ProtocolVersion {
            major: proof_major,
            minor: verifier_minor,
            patch: 0,
        });

        let result = verifier.verify(&proof, &public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Accepted,
            "Req 8.6: same major version with different minor must be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Helper: recompute proof data (mirrors DefaultProver::generate_proof_data)
// ---------------------------------------------------------------------------

/// Recompute the expected proof_data from commitments and public inputs.
/// This mirrors the prover's generate_proof_data exactly.
fn recompute_proof_data(
    commitments: &vsel_proof::prover::ProofCommitments,
    public_inputs: &PublicInputs,
) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(&commitments.trace_commitment.0);
    hasher.update(&commitments.witness_commitment.0);
    hasher.update(&commitments.constraint_commitment.0);
    hasher.update(&public_inputs.root_init.0);
    hasher.update(&public_inputs.root_final.0);
    hasher.update(&(public_inputs.observables.len() as u64).to_le_bytes());
    hasher.update(&(public_inputs.domain.0).0);
    hasher.update(&public_inputs.version.major.to_le_bytes());
    hasher.update(&public_inputs.version.minor.to_le_bytes());
    hasher.update(&public_inputs.version.patch.to_le_bytes());
    hasher.finalize().to_vec()
}
