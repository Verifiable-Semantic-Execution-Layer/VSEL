//! Property-based tests for the ZkBackend abstraction layer.
//!
//! **Property 2: HashBackend Equivalence with Legacy Prover**
//! Since `DefaultProver` is `GenericProver<HashBackend>` (a type alias),
//! this property verifies that the HashBackend prove/verify round-trip
//! works correctly, proof data is deterministic, and proofs pass
//! verification through the DefaultVerifier pipeline.
//!
//! For any valid trace and constraint system:
//! - `GenericProver<HashBackend>` produces deterministic commitments,
//!   public inputs, and proof data
//! - The proof passes the full 7-step DefaultVerifier pipeline
//! - The HashBackend's standalone prove/verify round-trip succeeds
//!
//! **Validates: Requirements 1.3, 1.6**
//!
//! **Property 3: Backend Error Propagation Includes Identifier**
//! For any ZkBackend implementation and any input that causes `prove`
//! to return an error, the propagated error message contains the string
//! returned by `backend_id()`. Also, `deserialize_proof` errors must
//! contain the backend identifier. No silent fallback is permitted.
//!
//! **Validates: Requirements 1.8**

// Feature: production-readiness, Property 2: HashBackend Equivalence with Legacy Prover
// Feature: production-readiness, Property 3: Backend Error Propagation Includes Identifier

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
use vsel_proof::backend::ZkBackend;
use vsel_proof::hash_backend::HashBackend;
use vsel_proof::prover::{DefaultProver, GenericProver, Prover};
use vsel_proof::public_inputs::PublicInputs;
use vsel_proof::verifier::{DefaultVerifier, VerificationResult, Verifier};
use vsel_proof::witness::{construct_witness, Witness};
use vsel_trace::engine::{Trace, TraceEntry};

// ---------------------------------------------------------------------------
// Configure proptest case count from environment
// ---------------------------------------------------------------------------

fn proptest_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
}

// ---------------------------------------------------------------------------
// Arbitrary strategies (reused from proof_tests.rs patterns)
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

        // Compute chain hash deterministically
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
///
/// Uses `Eq(WitnessRef("x"), WitnessRef("x"))` which compiles to the
/// polynomial identity `x - x = 0` — trivially satisfiable for any trace.
/// This works with both the HashBackend (which doesn't evaluate AIR) and
/// the Plonky3Backend (which requires AIR constraints to hold on every row).
///
/// Note: `BoolConstant(true)` compiles to `PolyExpr::Constant(1)` which
/// the AIR asserts equals zero — always failing with real STARK proofs.
fn test_constraint_system() -> ConstraintSystem {
    let mut cs = ConstraintSystem::new("1.0.0");
    cs.add_witness_variable(vsel_constraints::WitnessVariable {
        name: "x".to_string(),
        kind: vsel_constraints::WitnessVariableKind::Semantic,
        description: "test witness variable".to_string(),
    });
    cs.add_constraint(Constraint {
        id: ConstraintId(0),
        expr: ConstraintExpr::Eq(
            Box::new(ConstraintExpr::WitnessRef("x".to_string())),
            Box::new(ConstraintExpr::WitnessRef("x".to_string())),
        ),
        category: ConstraintCategory::Structural,
        description: "x = x (trivially true)".to_string(),
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
// Property 2a: HashBackend prove/verify round-trip determinism
//
// For any valid trace and constraint system, proving twice with
// GenericProver<HashBackend> (= DefaultProver) produces identical
// commitments, public inputs, and proof data.
//
// **Validates: Requirements 1.3, 1.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 2a: Proof determinism — same trace + same constraints
    /// always produces identical proof artifacts.
    #[test]
    fn prop_hash_backend_proof_determinism(
        trace in arb_valid_trace(),
    ) {
        let prover: GenericProver<HashBackend> = GenericProver::new("0.1.0-test");
        let cs = test_constraint_system();

        let proof1 = prover.prove(&trace, &cs).expect("proof 1 should succeed");
        let proof2 = prover.prove(&trace, &cs).expect("proof 2 should succeed");

        // Commitments must be identical.
        prop_assert_eq!(
            proof1.commitments, proof2.commitments,
            "Property 2: same trace must produce identical commitments"
        );

        // Public inputs must be identical.
        prop_assert_eq!(
            proof1.public_inputs, proof2.public_inputs,
            "Property 2: same trace must produce identical public inputs"
        );

        // Proof data must be identical.
        prop_assert_eq!(
            proof1.proof_data, proof2.proof_data,
            "Property 2: same trace must produce identical proof data"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2b: HashBackend proof passes DefaultVerifier pipeline
//
// For any valid trace, the proof produced by GenericProver<HashBackend>
// passes the full 7-step verification pipeline of DefaultVerifier.
//
// **Validates: Requirements 1.3, 1.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 2b: Prove-verify round-trip through the full pipeline —
    /// every proof produced by DefaultProver (= GenericProver<HashBackend>)
    /// is accepted by DefaultVerifier (= GenericVerifier<HashBackend>).
    #[test]
    fn prop_hash_backend_prove_verify_pipeline(
        trace in arb_valid_trace(),
    ) {
        let prover = DefaultProver::new("0.1.0-test");
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof should succeed");

        // The verifier's expected version must match the proof's version.
        let verifier = DefaultVerifier::new(proof.public_inputs.version.clone());

        let result = verifier.verify(&proof, &proof.public_inputs);

        prop_assert_eq!(
            result,
            VerificationResult::Accepted,
            "Property 2: proof from DefaultProver must pass DefaultVerifier pipeline"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2c: HashBackend standalone prove/verify round-trip
//
// For any valid trace, the HashBackend's standalone ZkBackend::prove
// and ZkBackend::verify round-trip succeeds. This tests the backend
// abstraction layer independently of the GenericProver pipeline.
//
// **Validates: Requirements 1.3, 1.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 2c: HashBackend standalone round-trip — for any valid
    /// trace, constructing a witness and proving through the ZkBackend
    /// trait directly produces a proof that passes ZkBackend::verify.
    #[test]
    fn prop_hash_backend_standalone_round_trip(
        trace in arb_valid_trace(),
    ) {
        let backend = HashBackend::new();
        let cs = test_constraint_system();

        // Construct witness and public inputs from the trace
        // (mirroring what GenericProver does internally).
        let witness = construct_witness(&trace);
        let public_inputs = PublicInputs::from_trace(&trace);

        let proof = backend
            .prove(&witness, &cs, &public_inputs)
            .expect("HashBackend::prove should succeed");

        // Compute constraint commitment for verification.
        // Use the same logic as the prover: domain-separated hash of constraints.
        let constraint_commitment = {
            use vsel_crypto::domain::{domain_hash, proof_tag as ptag};
            let proof_domain = ptag();
            let mut data = Vec::new();
            data.extend_from_slice(cs.version.as_bytes());
            data.extend_from_slice(&(cs.constraints.len() as u64).to_le_bytes());
            data.extend_from_slice(&(cs.witness_variables.len() as u64).to_le_bytes());
            data.extend_from_slice(&(cs.public_inputs.len() as u64).to_le_bytes());
            for constraint in &cs.constraints {
                data.extend_from_slice(&constraint.id.0.to_le_bytes());
                data.extend_from_slice(constraint.description.as_bytes());
            }
            domain_hash(&proof_domain, &data)
        };

        prop_assert!(
            backend.verify(&proof, &public_inputs, &constraint_commitment),
            "Property 2: HashBackend prove-verify round-trip must succeed"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2d: GenericProver<HashBackend> and DefaultProver are identical
//
// Since DefaultProver IS GenericProver<HashBackend> (type alias), verify
// that explicitly constructing both types produces byte-identical proofs.
// This confirms the type alias is a pure refactoring.
//
// **Validates: Requirements 1.3, 1.6**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 2d: Type alias equivalence — GenericProver<HashBackend>
    /// and DefaultProver produce byte-identical proof artifacts.
    #[test]
    fn prop_generic_prover_equals_default_prover(
        trace in arb_valid_trace(),
    ) {
        let generic_prover: GenericProver<HashBackend> = GenericProver::new("0.1.0-test");
        let default_prover: DefaultProver = DefaultProver::new("0.1.0-test");
        let cs = test_constraint_system();

        let generic_proof = generic_prover.prove(&trace, &cs).expect("generic proof");
        let default_proof = default_prover.prove(&trace, &cs).expect("default proof");

        // Commitments must be identical.
        prop_assert_eq!(
            generic_proof.commitments, default_proof.commitments,
            "Property 2: GenericProver<HashBackend> and DefaultProver must produce identical commitments"
        );

        // Public inputs must be identical.
        prop_assert_eq!(
            generic_proof.public_inputs, default_proof.public_inputs,
            "Property 2: GenericProver<HashBackend> and DefaultProver must produce identical public inputs"
        );

        // Proof data must be identical.
        prop_assert_eq!(
            generic_proof.proof_data, default_proof.proof_data,
            "Property 2: GenericProver<HashBackend> and DefaultProver must produce identical proof data"
        );

        // Metadata must be identical (same version, same proof system).
        prop_assert_eq!(
            generic_proof.metadata.prover_version, default_proof.metadata.prover_version,
            "Property 2: prover versions must match"
        );
        prop_assert_eq!(
            generic_proof.metadata.proof_system, default_proof.metadata.proof_system,
            "Property 2: proof systems must match"
        );
        prop_assert_eq!(
            generic_proof.metadata.domain, default_proof.metadata.domain,
            "Property 2: metadata domains must match"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 3: Backend Error Propagation Includes Identifier
//
// For any ZkBackend implementation and any input that causes `prove`
// to return an error, the propagated error message contains the string
// returned by `backend_id()`. Also, `deserialize_proof` errors must
// contain the backend identifier. No silent fallback is permitted.
//
// Feature: production-readiness, Property 3: Backend Error Propagation Includes Identifier
//
// **Validates: Requirements 1.8**
// ---------------------------------------------------------------------------

// -- Strategies for generating inputs that trigger errors --

/// Strategy for generating an empty witness (all fields empty).
/// This triggers `HashBackendError::EmptyWitness`.
fn arb_empty_witness() -> impl Strategy<Value = Witness> {
    Just(Witness {
        intermediate_states: vec![],
        input_sequence: vec![],
        aux_computation: vsel_proof::witness::AuxiliaryComputation::empty(),
    })
}

/// Strategy for generating invalid byte sequences for deserialization.
/// These should all fail `HashBackend::deserialize_proof`:
/// - Empty bytes
/// - Too short (1..31 bytes)
/// - Too long (33..128 bytes)
fn arb_invalid_proof_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // Empty bytes
        Just(vec![]),
        // Too short: 1..31 bytes
        (1usize..32).prop_flat_map(|len| {
            prop::collection::vec(any::<u8>(), len)
        }),
        // Too long: 33..128 bytes
        (33usize..128).prop_flat_map(|len| {
            prop::collection::vec(any::<u8>(), len)
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 3a: Empty witness causes `prove` to error, and the error
    /// message contains the backend identifier "hash-sha3".
    ///
    /// **Validates: Requirements 1.8**
    #[test]
    fn prop_prove_error_contains_backend_id(
        witness in arb_empty_witness(),
        // Generate arbitrary constraint systems and public inputs —
        // the error should fire regardless of these values.
        domain_bytes in prop::array::uniform32(1u8..=255u8),
        version_major in 0u32..10,
        version_minor in 0u32..100,
        version_patch in 0u32..100,
    ) {
        let backend = HashBackend::new();
        let cs = test_constraint_system();
        let public_inputs = PublicInputs {
            root_init: Hash([1u8; 32]),
            root_final: Hash([2u8; 32]),
            observables: vec![],
            domain: DomainTag(Hash(domain_bytes)),
            version: ProtocolVersion {
                major: version_major,
                minor: version_minor,
                patch: version_patch,
            },
        };

        let result = backend.prove(&witness, &cs, &public_inputs);

        // The empty witness must cause an error.
        prop_assert!(
            result.is_err(),
            "Property 3: empty witness must cause prove to error"
        );

        let err_msg = result.unwrap_err().to_string();
        prop_assert!(
            err_msg.contains(backend.backend_id()),
            "Property 3: error message '{}' must contain backend_id '{}'",
            err_msg,
            backend.backend_id()
        );
    }

    /// Property 3b: Invalid bytes cause `deserialize_proof` to error,
    /// and the error message contains the backend identifier "hash-sha3".
    ///
    /// **Validates: Requirements 1.8**
    #[test]
    fn prop_deserialize_error_contains_backend_id(
        invalid_bytes in arb_invalid_proof_bytes(),
    ) {
        let backend = HashBackend::new();

        let result = backend.deserialize_proof(&invalid_bytes);

        // Invalid bytes must cause a deserialization error.
        prop_assert!(
            result.is_err(),
            "Property 3: invalid bytes (len={}) must cause deserialize_proof to error",
            invalid_bytes.len()
        );

        let err_msg = result.unwrap_err().to_string();
        prop_assert!(
            err_msg.contains(backend.backend_id()),
            "Property 3: deserialization error '{}' must contain backend_id '{}'",
            err_msg,
            backend.backend_id()
        );
    }

    /// Property 3c: All HashBackendError variants contain the backend
    /// identifier. This tests that the error type itself is correctly
    /// constructed — for any error variant, the Display output includes
    /// "hash-sha3".
    ///
    /// **Validates: Requirements 1.8**
    #[test]
    fn prop_all_error_variants_contain_backend_id(
        detail_msg in "[a-zA-Z0-9 _\\-]{0,100}",
    ) {
        use vsel_proof::hash_backend::HashBackendError;

        let backend_id = "hash-sha3";

        let errors: Vec<HashBackendError> = vec![
            HashBackendError::EmptyWitness,
            HashBackendError::ProofGenerationFailed(detail_msg.clone()),
            HashBackendError::DeserializationFailed(detail_msg),
        ];

        for err in errors {
            let msg = err.to_string();
            prop_assert!(
                msg.contains(backend_id),
                "Property 3: error variant '{}' must contain '{}'",
                msg,
                backend_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 1: ZkBackend Prove-Verify Round-Trip
//
// For any valid witness, constraint system, and public inputs triple,
// if `ZkBackend::prove` succeeds producing proof π, then
// `ZkBackend::verify(π, public_inputs, constraint_commitment)` returns
// true. This must hold for every `ZkBackend` implementation.
//
// Feature: production-readiness, Property 1: ZkBackend Prove-Verify Round-Trip
//
// **Validates: Requirements 1.1, 2.1**
// ---------------------------------------------------------------------------

/// Helper: compute constraint commitment using the same domain-separated
/// hash logic as the prover pipeline.
fn compute_constraint_commitment(cs: &ConstraintSystem) -> Hash {
    use sha3::{Digest, Sha3_256};
    let cs_bytes = bincode::serialize(cs).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(b"vsel-constraint-system-v1");
    hasher.update(&cs_bytes);
    let hash = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&hash);
    Hash(commitment)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 1a: HashBackend prove-verify round-trip via ZkBackend trait.
    ///
    /// For any valid trace, constructing a witness and public inputs,
    /// then calling `HashBackend::prove` followed by `HashBackend::verify`
    /// must return true. This tests the ZkBackend contract directly.
    ///
    /// **Validates: Requirements 1.1**
    #[test]
    fn prop_hash_backend_zkbackend_prove_verify_round_trip(
        trace in arb_valid_trace(),
    ) {
        let backend = HashBackend::new();
        let cs = test_constraint_system();

        let witness = construct_witness(&trace);
        let public_inputs = PublicInputs::from_trace(&trace);
        let constraint_commitment = compute_constraint_commitment(&cs);

        let proof = backend
            .prove(&witness, &cs, &public_inputs)
            .expect("Property 1: HashBackend::prove should succeed for valid inputs");

        prop_assert!(
            backend.verify(&proof, &public_inputs, &constraint_commitment),
            "Property 1: HashBackend prove-verify round-trip must succeed"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 1 (Plonky3Backend): Prove-Verify Round-Trip
//
// Feature-gated behind `plonky3-backend`. For any valid trace,
// Plonky3Backend::prove followed by Plonky3Backend::verify returns true.
//
// **Validates: Requirements 2.1**
// ---------------------------------------------------------------------------

#[cfg(feature = "plonky3-backend")]
mod plonky3_prove_verify {
    use super::*;
    use vsel_proof::plonky3_backend::Plonky3Backend;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

        /// Property 1b: Plonky3Backend prove-verify round-trip via ZkBackend trait.
        ///
        /// For any valid trace, constructing a witness and public inputs,
        /// then calling `Plonky3Backend::prove` followed by `Plonky3Backend::verify`
        /// must return true.
        ///
        /// **Validates: Requirements 2.1**
        #[test]
        fn prop_plonky3_backend_zkbackend_prove_verify_round_trip(
            trace in arb_valid_trace(),
        ) {
            let backend = Plonky3Backend::new();
            let cs = test_constraint_system();

            let witness = construct_witness(&trace);
            let public_inputs = PublicInputs::from_trace(&trace);
            let constraint_commitment = compute_constraint_commitment(&cs);

            let proof = backend
                .prove(&witness, &cs, &public_inputs)
                .expect("Property 1: Plonky3Backend::prove should succeed for valid inputs");

            prop_assert!(
                backend.verify(&proof, &public_inputs, &constraint_commitment),
                "Property 1: Plonky3Backend prove-verify round-trip must succeed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: Proof Serialization Round-Trip
//
// For any valid STARK proof produced by Plonky3Backend, serializing the
// proof to bytes via `serialize_proof` and then deserializing via
// `deserialize_proof` produces a proof that is byte-equivalent to the
// original. The serialization is deterministic.
//
// Feature: production-readiness, Property 5: Proof Serialization Round-Trip
//
// **Validates: Requirements 2.8**
// ---------------------------------------------------------------------------

// -- HashBackend serialization round-trip (always available) --

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// Property 5a: HashBackend serialization round-trip.
    ///
    /// For any valid proof produced by HashBackend, serialize then
    /// deserialize produces a byte-equivalent proof.
    ///
    /// **Validates: Requirements 2.8**
    #[test]
    fn prop_hash_backend_serialization_round_trip(
        trace in arb_valid_trace(),
    ) {
        let backend = HashBackend::new();
        let cs = test_constraint_system();

        let witness = construct_witness(&trace);
        let public_inputs = PublicInputs::from_trace(&trace);

        let proof = backend
            .prove(&witness, &cs, &public_inputs)
            .expect("prove should succeed");

        let serialized = backend.serialize_proof(&proof);
        let deserialized = backend
            .deserialize_proof(&serialized)
            .expect("deserialize should succeed");

        prop_assert_eq!(
            proof.as_ref(),
            deserialized.as_ref(),
            "Property 5: HashBackend serialize-deserialize round-trip must be byte-equivalent"
        );
    }
}

// -- Plonky3Backend serialization round-trip (feature-gated) --

#[cfg(feature = "plonky3-backend")]
mod plonky3_serialization {
    use super::*;
    use vsel_proof::plonky3_backend::Plonky3Backend;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

        /// Property 5b: Plonky3Backend serialization round-trip.
        ///
        /// For any valid STARK proof produced by Plonky3Backend,
        /// `deserialize(serialize(proof))` is byte-equivalent to the original.
        /// The serialization is deterministic.
        ///
        /// **Validates: Requirements 2.8**
        #[test]
        fn prop_plonky3_backend_serialization_round_trip(
            trace in arb_valid_trace(),
        ) {
            let backend = Plonky3Backend::new();
            let cs = test_constraint_system();

            let witness = construct_witness(&trace);
            let public_inputs = PublicInputs::from_trace(&trace);

            let proof = backend
                .prove(&witness, &cs, &public_inputs)
                .expect("Plonky3Backend::prove should succeed");

            let serialized = backend.serialize_proof(&proof);
            let deserialized = backend
                .deserialize_proof(&serialized)
                .expect("Plonky3Backend::deserialize_proof should succeed");

            // Byte-equivalence: the serialized form of the deserialized proof
            // must match the original serialized bytes.
            let reserialized = backend.serialize_proof(&deserialized);
            prop_assert_eq!(
                serialized,
                reserialized,
                "Property 5: Plonky3Backend serialize-deserialize round-trip must be byte-equivalent"
            );

            // Also verify the deserialized proof still passes verification.
            let constraint_commitment = compute_constraint_commitment(&cs);
            prop_assert!(
                backend.verify(&deserialized, &public_inputs, &constraint_commitment),
                "Property 5: deserialized proof must still pass verification"
            );
        }

        /// Property 5c: Plonky3Backend serialization is deterministic.
        ///
        /// Serializing the same proof twice produces identical byte sequences.
        ///
        /// **Validates: Requirements 2.8**
        #[test]
        fn prop_plonky3_backend_serialization_deterministic(
            trace in arb_valid_trace(),
        ) {
            let backend = Plonky3Backend::new();
            let cs = test_constraint_system();

            let witness = construct_witness(&trace);
            let public_inputs = PublicInputs::from_trace(&trace);

            let proof = backend
                .prove(&witness, &cs, &public_inputs)
                .expect("prove should succeed");

            let serialized1 = backend.serialize_proof(&proof);
            let serialized2 = backend.serialize_proof(&proof);

            prop_assert_eq!(
                serialized1,
                serialized2,
                "Property 5: serialization must be deterministic"
            );
        }
    }
}
