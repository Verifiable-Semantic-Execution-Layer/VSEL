//! Cross-system proof composition for compositional verification.
//!
//! Derived from: COMPOSITION_MODEL.md, PROOF_LAYER.md §6,
//! Requirements 11.4, 11.6.
//!
//! Composes two system proofs and a cross-invariant proof into a single
//! composed proof:
//!
//!   compose_proofs(π_a, π_b, π_cross) → π_ab
//!
//! THM-10: verify(π_ab) ⟹ valid_trace_a ∧ valid_trace_b ∧ G_cross
//!
//! The composed proof has:
//! - root_init from proof_a
//! - root_final from proof_b
//! - observables concatenated from all three proofs
//! - commitments derived by hashing all individual commitments with
//!   domain-separated SHA3-256

use sha3::{Digest, Sha3_256};
use thiserror::Error;

use vsel_core::types::Hash;
use vsel_proof::prover::{Proof, ProofCommitments, ProofMetadata};
use vsel_proof::public_inputs::PublicInputs;

// ---------------------------------------------------------------------------
// Domain separator for cross-system proof composition
// ---------------------------------------------------------------------------

/// Domain separator for cross-system proof composition operations.
const DOMAIN_CROSS_PROOF_COMPOSE: &[u8] = b"VSEL::v1::cross_proof_composition";

// ---------------------------------------------------------------------------
// CompositionError — errors during proof composition
// ---------------------------------------------------------------------------

/// Errors that can occur during cross-system proof composition.
#[derive(Debug, Error)]
pub enum CompositionError {
    /// One or more proofs have empty proof data.
    #[error("empty proof: one or more proofs have no proof data")]
    EmptyProof,

    /// The domain tags of the proofs do not match.
    #[error("domain mismatch: proof domains are inconsistent")]
    DomainMismatch,

    /// The protocol versions of the proofs do not match.
    #[error("version mismatch: proof protocol versions are inconsistent")]
    VersionMismatch,

    /// The state chain is broken between proof_a's final state and proof_b's initial state.
    #[error("state chain broken: proof_a.root_final != proof_b.root_init")]
    StateChainBroken,

    /// A cross-invariant violation was detected.
    #[error("cross-invariant violation: {0}")]
    CrossInvariantViolation(String),
}

// ---------------------------------------------------------------------------
// compose_proofs — cross-system proof composition (THM-10)
// ---------------------------------------------------------------------------

/// Compose two system proofs and a cross-invariant proof into a single
/// composed proof.
///
/// THM-10: `verify(π_ab) ⟹ valid_trace_a ∧ valid_trace_b ∧ G_cross`
///
/// Validates:
/// - No proof has empty proof data
/// - Domain consistency: all three proofs share the same domain
/// - Version consistency: all three proofs share the same protocol version
///
/// The composed proof has:
/// - `root_init` from `proof_a`
/// - `root_final` from `proof_b`
/// - Observables concatenated from proof_a, proof_b, and proof_cross
/// - Commitments derived by hashing all individual commitments together
///   using SHA3-256 with domain separation
///
/// Requirements 11.4, 11.6.
pub fn compose_proofs(
    proof_a: &Proof,
    proof_b: &Proof,
    proof_cross: &Proof,
) -> Result<Proof, CompositionError> {
    // Validate no empty proofs.
    if proof_a.proof_data.is_empty()
        || proof_b.proof_data.is_empty()
        || proof_cross.proof_data.is_empty()
    {
        return Err(CompositionError::EmptyProof);
    }

    // Validate domain consistency.
    if proof_a.public_inputs.domain != proof_b.public_inputs.domain
        || proof_a.public_inputs.domain != proof_cross.public_inputs.domain
    {
        return Err(CompositionError::DomainMismatch);
    }

    // Validate version consistency.
    if proof_a.public_inputs.version != proof_b.public_inputs.version
        || proof_a.public_inputs.version != proof_cross.public_inputs.version
    {
        return Err(CompositionError::VersionMismatch);
    }

    // Concatenate observables from all three proofs in order.
    let mut combined_observables = Vec::new();
    combined_observables.extend(proof_a.public_inputs.observables.clone());
    combined_observables.extend(proof_b.public_inputs.observables.clone());
    combined_observables.extend(proof_cross.public_inputs.observables.clone());

    // Build composed public inputs.
    let composed_public_inputs = PublicInputs {
        root_init: proof_a.public_inputs.root_init.clone(),
        root_final: proof_b.public_inputs.root_final.clone(),
        observables: combined_observables,
        domain: proof_a.public_inputs.domain.clone(),
        version: proof_a.public_inputs.version.clone(),
    };

    // Derive composed commitments from all three proofs.
    let composed_commitments = compose_commitments(proof_a, proof_b, proof_cross);

    // Generate composed proof data.
    let composed_proof_data = compose_proof_data(
        proof_a,
        proof_b,
        proof_cross,
        &composed_commitments,
        &composed_public_inputs,
    );

    // Metadata for the composed proof.
    let metadata = ProofMetadata {
        prover_version: proof_a.metadata.prover_version.clone(),
        timestamp: 0,
        domain: proof_a.metadata.domain.clone(),
        proof_system: "stark-placeholder-cross-composed".to_string(),
    };

    Ok(Proof {
        commitments: composed_commitments,
        proof_data: composed_proof_data,
        public_inputs: composed_public_inputs,
        metadata,
    })
}

// ---------------------------------------------------------------------------
// compose_commitments — hash all individual commitments together
// ---------------------------------------------------------------------------

/// Derive composed commitments from all three proofs using domain-separated
/// SHA3-256 hashing.
///
/// Each commitment field is computed by hashing the corresponding fields
/// from all three proofs with the cross-composition domain separator.
fn compose_commitments(proof_a: &Proof, proof_b: &Proof, proof_cross: &Proof) -> ProofCommitments {
    // Compose trace commitments.
    let trace_commitment = domain_hash_commitments(
        b"trace",
        &proof_a.commitments.trace_commitment,
        &proof_b.commitments.trace_commitment,
        &proof_cross.commitments.trace_commitment,
    );

    // Compose witness commitments.
    let witness_commitment = domain_hash_commitments(
        b"witness",
        &proof_a.commitments.witness_commitment,
        &proof_b.commitments.witness_commitment,
        &proof_cross.commitments.witness_commitment,
    );

    // Compose constraint commitments.
    let constraint_commitment = domain_hash_commitments(
        b"constraint",
        &proof_a.commitments.constraint_commitment,
        &proof_b.commitments.constraint_commitment,
        &proof_cross.commitments.constraint_commitment,
    );

    ProofCommitments {
        trace_commitment,
        witness_commitment,
        constraint_commitment,
    }
}

/// Domain-separated hash of three commitment values.
fn domain_hash_commitments(label: &[u8], a: &Hash, b: &Hash, c: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_CROSS_PROOF_COMPOSE);
    hasher.update(b"::");
    hasher.update(label);
    hasher.update(&a.0);
    hasher.update(&b.0);
    hasher.update(&c.0);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash(bytes)
}

// ---------------------------------------------------------------------------
// compose_proof_data — generate composed proof data
// ---------------------------------------------------------------------------

/// Generate proof data for the composed proof.
///
/// Hashes all individual proof data together with the composed commitments
/// and public inputs for binding.
fn compose_proof_data(
    proof_a: &Proof,
    proof_b: &Proof,
    proof_cross: &Proof,
    commitments: &ProofCommitments,
    public_inputs: &PublicInputs,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();

    // Domain separation.
    hasher.update(DOMAIN_CROSS_PROOF_COMPOSE);

    // Bind to composed commitments.
    hasher.update(&commitments.trace_commitment.0);
    hasher.update(&commitments.witness_commitment.0);
    hasher.update(&commitments.constraint_commitment.0);

    // Bind to composed public inputs.
    hasher.update(&public_inputs.root_init.0);
    hasher.update(&public_inputs.root_final.0);
    hasher.update(&(public_inputs.observables.len() as u64).to_le_bytes());
    hasher.update(&(public_inputs.domain.0).0);
    hasher.update(&public_inputs.version.major.to_le_bytes());
    hasher.update(&public_inputs.version.minor.to_le_bytes());
    hasher.update(&public_inputs.version.patch.to_le_bytes());

    // Bind to all three individual proof data.
    hasher.update(&(proof_a.proof_data.len() as u64).to_le_bytes());
    hasher.update(&proof_a.proof_data);
    hasher.update(&(proof_b.proof_data.len() as u64).to_le_bytes());
    hasher.update(&proof_b.proof_data);
    hasher.update(&(proof_cross.proof_data.len() as u64).to_le_bytes());
    hasher.update(&proof_cross.proof_data);

    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::transition::TransitionClass;
    use vsel_core::types::{DomainTag, Hash, ProtocolVersion};
    use vsel_crypto::domain::proof_tag;

    // -- Test helpers --

    fn test_domain() -> DomainTag {
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

    fn make_hash(seed: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = seed;
        Hash(h)
    }

    fn make_observable(gas: u64) -> Observable {
        Observable {
            transition_class: TransitionClass::Update,
            outputs: vec![],
            gas_used: gas,
            status: TransitionStatus::Success,
        }
    }

    fn make_proof(root_init: Hash, root_final: Hash, gas: u64) -> Proof {
        let commitments = ProofCommitments {
            trace_commitment: make_hash(0x10),
            witness_commitment: make_hash(0x20),
            constraint_commitment: make_hash(0x30),
        };
        let public_inputs = PublicInputs {
            root_init,
            root_final,
            observables: vec![make_observable(gas)],
            domain: test_domain(),
            version: test_version(),
        };
        let metadata = ProofMetadata {
            prover_version: "0.1.0-test".to_string(),
            timestamp: 0,
            domain: proof_tag(),
            proof_system: "stark-placeholder".to_string(),
        };
        Proof {
            commitments,
            proof_data: vec![0xDE, 0xAD],
            public_inputs,
            metadata,
        }
    }

    // -- compose_proofs: success cases --

    #[test]
    fn test_compose_proofs_success() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let composed =
            compose_proofs(&proof_a, &proof_b, &proof_cross).expect("composition should succeed");

        // root_init from proof_a.
        assert_eq!(composed.public_inputs.root_init, make_hash(0));
        // root_final from proof_b.
        assert_eq!(composed.public_inputs.root_final, make_hash(2));
        // Observables concatenated from all three.
        assert_eq!(composed.public_inputs.observables.len(), 3);
        assert_eq!(composed.public_inputs.observables[0].gas_used, 100);
        assert_eq!(composed.public_inputs.observables[1].gas_used, 200);
        assert_eq!(composed.public_inputs.observables[2].gas_used, 50);
        // Domain preserved.
        assert_eq!(composed.public_inputs.domain, test_domain());
        // Version preserved.
        assert_eq!(composed.public_inputs.version, test_version());
        // Proof data non-empty.
        assert!(!composed.proof_data.is_empty());
        // Metadata.
        assert_eq!(
            composed.metadata.proof_system,
            "stark-placeholder-cross-composed"
        );
    }

    #[test]
    fn test_compose_proofs_deterministic() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let c1 = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("c1");
        let c2 = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("c2");

        assert_eq!(c1.commitments, c2.commitments);
        assert_eq!(c1.proof_data, c2.proof_data);
        assert_eq!(c1.public_inputs, c2.public_inputs);
    }

    #[test]
    fn test_compose_proofs_commitments_differ_from_individual() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let composed = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("compose");

        // Composed commitments should differ from any individual proof's.
        assert_ne!(
            composed.commitments.trace_commitment,
            proof_a.commitments.trace_commitment
        );
        assert_ne!(
            composed.commitments.trace_commitment,
            proof_b.commitments.trace_commitment
        );
    }

    #[test]
    fn test_compose_proofs_preserves_observable_order() {
        let mut proof_a = make_proof(make_hash(0), make_hash(1), 100);
        proof_a.public_inputs.observables = vec![make_observable(1), make_observable(2)];
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let composed = compose_proofs(&proof_a, &proof_b, &proof_cross).expect("compose");

        assert_eq!(composed.public_inputs.observables.len(), 4);
        assert_eq!(composed.public_inputs.observables[0].gas_used, 1);
        assert_eq!(composed.public_inputs.observables[1].gas_used, 2);
        assert_eq!(composed.public_inputs.observables[2].gas_used, 200);
        assert_eq!(composed.public_inputs.observables[3].gas_used, 50);
    }

    // -- compose_proofs: error cases --

    #[test]
    fn test_compose_proofs_empty_proof_a() {
        let mut proof_a = make_proof(make_hash(0), make_hash(1), 100);
        proof_a.proof_data = vec![];
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty proof"));
    }

    #[test]
    fn test_compose_proofs_empty_proof_b() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let mut proof_b = make_proof(make_hash(1), make_hash(2), 200);
        proof_b.proof_data = vec![];
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
    }

    #[test]
    fn test_compose_proofs_empty_proof_cross() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let mut proof_cross = make_proof(make_hash(0), make_hash(2), 50);
        proof_cross.proof_data = vec![];

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
    }

    #[test]
    fn test_compose_proofs_domain_mismatch_ab() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let mut proof_b = make_proof(make_hash(1), make_hash(2), 200);
        proof_b.public_inputs.domain = DomainTag(Hash([0xFF; 32]));
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("domain mismatch"));
    }

    #[test]
    fn test_compose_proofs_domain_mismatch_cross() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let mut proof_cross = make_proof(make_hash(0), make_hash(2), 50);
        proof_cross.public_inputs.domain = DomainTag(Hash([0xFF; 32]));

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("domain mismatch"));
    }

    #[test]
    fn test_compose_proofs_version_mismatch() {
        let proof_a = make_proof(make_hash(0), make_hash(1), 100);
        let mut proof_b = make_proof(make_hash(1), make_hash(2), 200);
        proof_b.public_inputs.version = ProtocolVersion {
            major: 99,
            minor: 0,
            patch: 0,
        };
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let result = compose_proofs(&proof_a, &proof_b, &proof_cross);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("version mismatch"));
    }

    #[test]
    fn test_compose_proofs_different_inputs_different_output() {
        let mut proof_a1 = make_proof(make_hash(0), make_hash(1), 100);
        proof_a1.proof_data = vec![0x01, 0x02, 0x03];
        let mut proof_a2 = make_proof(make_hash(0), make_hash(1), 100);
        proof_a2.proof_data = vec![0xAA, 0xBB, 0xCC];
        let proof_b = make_proof(make_hash(1), make_hash(2), 200);
        let proof_cross = make_proof(make_hash(0), make_hash(2), 50);

        let c1 = compose_proofs(&proof_a1, &proof_b, &proof_cross).expect("c1");
        let c2 = compose_proofs(&proof_a2, &proof_b, &proof_cross).expect("c2");

        // Different proof data in inputs → different composed proof data.
        assert_ne!(c1.proof_data, c2.proof_data);
    }
}
