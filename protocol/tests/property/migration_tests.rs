//! Property-based tests for legacy Poseidon conditional acceptance.
//!
//! Uses `proptest` to verify correctness properties derived from the
//! production-readiness design document.
//!
//! Properties tested:
//! - Property 13: Legacy Poseidon Conditional Acceptance
//!   **Validates: Requirements 6.5**
//!
//! Requirement 6.5 states:
//!   IF legacy Poseidon commitments are encountered during verification,
//!   THEN THE Verifier SHALL accept them only when the proof metadata
//!   indicates `proof_system: "stark-placeholder"` — production proofs
//!   require Goldilocks Poseidon.
//!
//! Since the Plonky3Backend does not yet exist, this test validates the
//! migration policy at the metadata level: it creates test proofs with
//! different `proof_system` metadata values and verifies the acceptance/
//! rejection logic. When the Plonky3Backend is implemented, the verifier
//! should incorporate this policy into its verification pipeline.

// Feature: production-readiness, Property 13: Legacy Poseidon Conditional Acceptance

use proptest::prelude::*;

use vsel_core::types::{Hash, ProtocolVersion};
use vsel_crypto::domain::proof_tag;
use vsel_proof::prover::{Proof, ProofCommitments, ProofMetadata};
use vsel_proof::public_inputs::PublicInputs;
use vsel_proof::verifier::Verifier;

// ---------------------------------------------------------------------------
// Commitment type classification
// ---------------------------------------------------------------------------

/// Identifies whether a proof's commitments were generated using the legacy
/// Poseidon (wrapping-u64) or the production Goldilocks Poseidon.
///
/// In a real implementation, this would be determined by inspecting the
/// commitment structure or a metadata flag. For testing purposes, we use
/// an explicit enum to drive the property test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitmentType {
    /// Legacy Poseidon commitments (wrapping-u64, placeholder).
    LegacyPoseidon,
    /// Production Goldilocks Poseidon commitments (field-native).
    ProductionGoldilocks,
}

// ---------------------------------------------------------------------------
// Migration acceptance policy
// ---------------------------------------------------------------------------

/// The legacy Poseidon conditional acceptance policy.
///
/// This function encodes Requirement 6.5:
///   - Legacy Poseidon commitments are accepted ONLY when
///     `proof_system == "stark-placeholder"`.
///   - Production proofs (any proof_system containing "plonky3")
///     with legacy Poseidon commitments are REJECTED.
///   - Production Goldilocks commitments are always accepted
///     regardless of proof_system.
///
/// When the Plonky3Backend is implemented, this logic should be
/// incorporated into the verifier's pipeline (e.g., as a step in
/// `DefaultVerifier::validate_structure` or a new migration validation step).
fn accepts_legacy_poseidon(proof_system: &str, commitment_type: CommitmentType) -> bool {
    match commitment_type {
        // Production Goldilocks commitments are always acceptable.
        CommitmentType::ProductionGoldilocks => true,
        // Legacy Poseidon commitments are only acceptable with the
        // placeholder STARK system — not with production backends.
        CommitmentType::LegacyPoseidon => proof_system == "stark-placeholder",
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Generator for proof_system identifiers that represent the legacy
/// placeholder STARK system.
fn arb_legacy_proof_system() -> impl Strategy<Value = String> {
    Just("stark-placeholder".to_string())
}

/// Generator for proof_system identifiers that represent production
/// backends (Plonky3 variants).
fn arb_production_proof_system() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("plonky3-stark".to_string()),
        Just("plonky3".to_string()),
        Just("plonky3-stark-v2".to_string()),
        // Any string containing "plonky3" is a production backend
        "[a-z]{0,5}plonky3[a-z\\-]{0,10}".prop_map(|s| s),
    ]
}

/// Generator for arbitrary proof_system identifiers that are NOT
/// "stark-placeholder" (i.e., any non-legacy system).
fn arb_non_placeholder_proof_system() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_production_proof_system(),
        // Other hypothetical future backends
        Just("groth16".to_string()),
        Just("halo2".to_string()),
        Just("nova-folding".to_string()),
        // Random non-placeholder strings
        "[a-z]{3,20}".prop_filter("must not be stark-placeholder", |s| s
            != "stark-placeholder"),
    ]
}

/// Generator for non-zero Hash values (used for commitments).
fn arb_nonzero_hash() -> impl Strategy<Value = Hash> {
    prop::array::uniform32(1u8..=255u8).prop_map(Hash)
}

/// Generator for a valid proof_system string (any non-empty string).
fn arb_proof_system() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => arb_legacy_proof_system(),
        3 => arb_production_proof_system(),
        2 => arb_non_placeholder_proof_system(),
    ]
}

/// Build a minimal valid Proof with the given proof_system metadata.
///
/// The proof is structurally valid (non-zero commitments, non-empty proof_data,
/// matching public inputs) so that the migration policy is the deciding factor.
fn build_test_proof(proof_system: &str) -> (Proof, PublicInputs) {
    let domain = proof_tag();
    let version = ProtocolVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };

    let root_init = Hash([0x01; 32]);
    let root_final = Hash([0x02; 32]);

    let public_inputs = PublicInputs {
        root_init: root_init.clone(),
        root_final: root_final.clone(),
        observables: vec![],
        domain: domain.clone(),
        version: version.clone(),
    };

    let commitments = ProofCommitments {
        trace_commitment: Hash([0x10; 32]),
        witness_commitment: Hash([0x20; 32]),
        constraint_commitment: Hash([0x30; 32]),
    };

    // Generate proof_data that matches the verifier's recomputation.
    // This mirrors DefaultProver::generate_proof_data.
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
    let proof_data = hasher.finalize().to_vec();

    let metadata = ProofMetadata {
        prover_version: "0.1.0-test".to_string(),
        timestamp: 0,
        domain: domain.clone(),
        proof_system: proof_system.to_string(),
    };

    let proof = Proof {
        commitments,
        proof_data,
        public_inputs: public_inputs.clone(),
        metadata,
    };

    (proof, public_inputs)
}

// ---------------------------------------------------------------------------
// Property 13: Legacy Poseidon Conditional Acceptance
//
// For any proof containing legacy Poseidon commitments (wrapping-u64),
// the verifier shall accept the proof if and only if
// proof.metadata.proof_system == "stark-placeholder".
// Production proofs (proof_system containing "plonky3") with legacy
// Poseidon commitments shall be rejected.
//
// **Validates: Requirements 6.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100)
    ))]

    /// Property 13a: Legacy Poseidon commitments with "stark-placeholder"
    /// proof_system are ACCEPTED.
    ///
    /// For any structurally valid proof where proof_system == "stark-placeholder"
    /// and commitments are legacy Poseidon, the migration policy accepts.
    #[test]
    fn prop_legacy_poseidon_accepted_with_placeholder(
        // Use arbitrary non-zero hashes to vary the commitment values
        trace_commit in arb_nonzero_hash(),
        witness_commit in arb_nonzero_hash(),
        constraint_commit in arb_nonzero_hash(),
    ) {
        let proof_system = "stark-placeholder";
        let commitment_type = CommitmentType::LegacyPoseidon;

        // The policy must accept legacy Poseidon with stark-placeholder
        let accepted = accepts_legacy_poseidon(proof_system, commitment_type);
        prop_assert!(
            accepted,
            "Legacy Poseidon commitments MUST be accepted when proof_system == \
             'stark-placeholder'. Got rejected for commitments: trace={:?}, \
             witness={:?}, constraint={:?}",
            trace_commit, witness_commit, constraint_commit
        );

        // Also verify the proof is structurally valid for the verifier
        let (proof, public_inputs) = build_test_proof(proof_system);
        let verifier = vsel_proof::verifier::DefaultVerifier::new(ProtocolVersion {
            major: 1,
            minor: 0,
            patch: 0,
        });
        let result = verifier.verify(&proof, &public_inputs);
        prop_assert!(
            result.is_cryptographically_consistent(),
            "Structurally valid proof with stark-placeholder should pass \
             the 7-step verification pipeline. Got: {:?}",
            result
        );
    }

    /// Property 13b: Production proofs (plonky3) with legacy Poseidon
    /// commitments are REJECTED.
    ///
    /// For any proof_system containing "plonky3" and legacy Poseidon
    /// commitments, the migration policy rejects.
    #[test]
    fn prop_legacy_poseidon_rejected_with_production_backend(
        proof_system in arb_production_proof_system(),
    ) {
        let commitment_type = CommitmentType::LegacyPoseidon;

        let accepted = accepts_legacy_poseidon(&proof_system, commitment_type);
        prop_assert!(
            !accepted,
            "Legacy Poseidon commitments MUST be rejected when proof_system \
             is a production backend. proof_system='{}' should not accept \
             legacy Poseidon commitments.",
            proof_system
        );
    }

    /// Property 13c: Legacy Poseidon commitments with any non-placeholder
    /// proof_system are REJECTED.
    ///
    /// This is the general case: legacy Poseidon is only accepted with
    /// "stark-placeholder", and rejected for ALL other proof_system values.
    #[test]
    fn prop_legacy_poseidon_rejected_with_non_placeholder(
        proof_system in arb_non_placeholder_proof_system(),
    ) {
        let commitment_type = CommitmentType::LegacyPoseidon;

        let accepted = accepts_legacy_poseidon(&proof_system, commitment_type);
        prop_assert!(
            !accepted,
            "Legacy Poseidon commitments MUST be rejected when proof_system \
             != 'stark-placeholder'. proof_system='{}' should not accept \
             legacy Poseidon commitments.",
            proof_system
        );
    }

    /// Property 13d: Production Goldilocks commitments are ALWAYS accepted
    /// regardless of proof_system.
    ///
    /// This ensures that the migration policy does not accidentally reject
    /// valid production commitments.
    #[test]
    fn prop_production_goldilocks_always_accepted(
        proof_system in arb_proof_system(),
    ) {
        let commitment_type = CommitmentType::ProductionGoldilocks;

        let accepted = accepts_legacy_poseidon(&proof_system, commitment_type);
        prop_assert!(
            accepted,
            "Production Goldilocks commitments MUST always be accepted \
             regardless of proof_system. proof_system='{}' rejected \
             production commitments.",
            proof_system
        );
    }

    /// Property 13e: The acceptance decision is a pure function of
    /// (proof_system, commitment_type) — deterministic and consistent.
    ///
    /// For any proof_system and commitment_type, calling the policy
    /// function twice produces the same result.
    #[test]
    fn prop_acceptance_deterministic(
        proof_system in arb_proof_system(),
        is_legacy in any::<bool>(),
    ) {
        let commitment_type = if is_legacy {
            CommitmentType::LegacyPoseidon
        } else {
            CommitmentType::ProductionGoldilocks
        };

        let result1 = accepts_legacy_poseidon(&proof_system, commitment_type);
        let result2 = accepts_legacy_poseidon(&proof_system, commitment_type);

        prop_assert_eq!(
            result1,
            result2,
            "Migration acceptance policy must be deterministic. \
             proof_system='{}', commitment_type={:?}",
            proof_system, commitment_type
        );
    }
}

// ---------------------------------------------------------------------------
// Unit tests for migration policy edge cases
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_legacy_poseidon_accepted_with_exact_placeholder() {
        assert!(accepts_legacy_poseidon(
            "stark-placeholder",
            CommitmentType::LegacyPoseidon
        ));
    }

    #[test]
    fn test_legacy_poseidon_rejected_with_plonky3_stark() {
        assert!(!accepts_legacy_poseidon(
            "plonky3-stark",
            CommitmentType::LegacyPoseidon
        ));
    }

    #[test]
    fn test_legacy_poseidon_rejected_with_plonky3() {
        assert!(!accepts_legacy_poseidon(
            "plonky3",
            CommitmentType::LegacyPoseidon
        ));
    }

    #[test]
    fn test_legacy_poseidon_rejected_with_empty_string() {
        assert!(!accepts_legacy_poseidon("", CommitmentType::LegacyPoseidon));
    }

    #[test]
    fn test_legacy_poseidon_rejected_with_similar_name() {
        // "stark-placeholder" is the ONLY accepted value — similar names fail
        assert!(!accepts_legacy_poseidon(
            "stark-placeholder-v2",
            CommitmentType::LegacyPoseidon
        ));
        assert!(!accepts_legacy_poseidon(
            "STARK-PLACEHOLDER",
            CommitmentType::LegacyPoseidon
        ));
        assert!(!accepts_legacy_poseidon(
            "stark_placeholder",
            CommitmentType::LegacyPoseidon
        ));
    }

    #[test]
    fn test_production_goldilocks_accepted_with_any_backend() {
        for system in &[
            "stark-placeholder",
            "plonky3-stark",
            "plonky3",
            "groth16",
            "halo2",
            "",
            "unknown-system",
        ] {
            assert!(
                accepts_legacy_poseidon(system, CommitmentType::ProductionGoldilocks),
                "Production Goldilocks should be accepted with proof_system='{}'",
                system
            );
        }
    }

    #[test]
    fn test_placeholder_proof_passes_verifier() {
        // A proof with proof_system="stark-placeholder" should pass the
        // current DefaultVerifier (which is the placeholder STARK system).
        let (proof, public_inputs) = build_test_proof("stark-placeholder");
        let verifier = vsel_proof::verifier::DefaultVerifier::new(ProtocolVersion {
            major: 1,
            minor: 0,
            patch: 0,
        });
        let result = verifier.verify(&proof, &public_inputs);
        assert!(
            result.is_cryptographically_consistent(),
            "Proof with stark-placeholder should be accepted by DefaultVerifier: {:?}",
            result
        );
    }
}
