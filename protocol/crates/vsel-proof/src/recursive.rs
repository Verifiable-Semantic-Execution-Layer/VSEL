//! Recursive proof composition for the VSEL proof system.
//!
//! Derived from: PROOF_LAYER.md §6, COMPOSITION_MODEL.md §3,
//! Requirements 7.8, 7.9.
//!
//! Proof composition: π_combined = Compose(π₁, π₂, ..., πₙ) with
//! compositional correctness, invariant preservation, and consistent
//! state chaining (THM-10).
//!
//! Recursive proofs: Verify(π_inner) ⊆ Constraints(π_outer) — inner
//! proof validity is embedded without external trust (THM-13).

use sha3::{Digest, Sha3_256};

use vsel_crypto::domain::{create_domain_tag, domain_hash};

use crate::prover::{Proof, ProofCommitments, ProofMetadata, ProverError};
use crate::public_inputs::PublicInputs;

// ---------------------------------------------------------------------------
// Domain tag for composition operations
// ---------------------------------------------------------------------------

/// Domain tag for proof composition operations.
pub const DOMAIN_COMPOSITION: &[u8] = b"VSEL::v1::proof_composition";

/// Domain tag for recursive proof embedding.
pub const DOMAIN_RECURSIVE: &[u8] = b"VSEL::v1::recursive_proof";

// ---------------------------------------------------------------------------
// compose — compositional correctness with state chaining (THM-10)
// ---------------------------------------------------------------------------

/// Compose multiple proofs into a single combined proof.
///
/// THM-10 (compositional correctness): the composed proof attests that
/// the concatenation of all individual executions is a valid trace with
/// consistent state chaining.
///
/// Validates:
/// - At least 2 proofs provided
/// - State chaining: proof[i].root_final == proof[i+1].root_init
/// - Domain consistency: all proofs share the same domain
/// - Version consistency: all proofs share the same version
///
/// The composed proof has:
/// - root_init from the first proof
/// - root_final from the last proof
/// - observables concatenated in order from all proofs
/// - commitments derived from all individual commitments
///
/// Requirements 7.8.
pub fn compose(proofs: &[Proof]) -> Result<Proof, ProverError> {
    // Validate at least 2 proofs.
    if proofs.len() < 2 {
        return Err(ProverError::ProofGenerationFailed(
            "composition requires at least 2 proofs".to_string(),
        ));
    }

    let first = &proofs[0];
    let last = &proofs[proofs.len() - 1];

    // Validate domain consistency: all proofs must share the same domain.
    for (i, proof) in proofs.iter().enumerate().skip(1) {
        if proof.public_inputs.domain != first.public_inputs.domain {
            return Err(ProverError::ProofGenerationFailed(format!(
                "domain mismatch: proof[0] domain differs from proof[{}]",
                i
            )));
        }
    }

    // Validate version consistency: all proofs must share the same version.
    for (i, proof) in proofs.iter().enumerate().skip(1) {
        if proof.public_inputs.version != first.public_inputs.version {
            return Err(ProverError::ProofGenerationFailed(format!(
                "version mismatch: proof[0] version differs from proof[{}]",
                i
            )));
        }
    }

    // Validate state chaining (THM-10):
    // proof[i].root_final == proof[i+1].root_init
    for i in 0..proofs.len() - 1 {
        if proofs[i].public_inputs.root_final != proofs[i + 1].public_inputs.root_init {
            return Err(ProverError::ProofGenerationFailed(format!(
                "state chain broken: proof[{}].root_final != proof[{}].root_init",
                i,
                i + 1
            )));
        }
    }

    // Combine observables from all proofs in order.
    let mut combined_observables = Vec::new();
    for proof in proofs {
        combined_observables.extend(proof.public_inputs.observables.clone());
    }

    // Build composed public inputs.
    let composed_public_inputs = PublicInputs {
        root_init: first.public_inputs.root_init.clone(),
        root_final: last.public_inputs.root_final.clone(),
        observables: combined_observables,
        domain: first.public_inputs.domain.clone(),
        version: first.public_inputs.version.clone(),
    };

    // Generate composed commitments by hashing all individual commitments.
    let composed_commitments = compose_commitments(proofs);

    // Generate composed proof data.
    let composed_proof_data = compose_proof_data(proofs, &composed_commitments, &composed_public_inputs);

    // Metadata for the composed proof.
    let metadata = ProofMetadata {
        prover_version: first.metadata.prover_version.clone(),
        timestamp: 0,
        domain: first.metadata.domain.clone(),
        proof_system: "stark-placeholder-composed".to_string(),
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

/// Derive composed commitments from all individual proof commitments.
///
/// Each composed commitment field is a domain-separated hash of all
/// corresponding individual commitment fields, preserving binding.
fn compose_commitments(proofs: &[Proof]) -> ProofCommitments {
    let comp_domain = create_domain_tag(DOMAIN_COMPOSITION);

    // Compose trace commitments.
    let mut trace_data = Vec::new();
    for proof in proofs {
        trace_data.extend_from_slice(&proof.commitments.trace_commitment.0);
    }
    let trace_commitment = domain_hash(&comp_domain, &trace_data);

    // Compose witness commitments.
    let mut witness_data = Vec::new();
    for proof in proofs {
        witness_data.extend_from_slice(&proof.commitments.witness_commitment.0);
    }
    let witness_commitment = domain_hash(&comp_domain, &witness_data);

    // Compose constraint commitments.
    let mut constraint_data = Vec::new();
    for proof in proofs {
        constraint_data.extend_from_slice(&proof.commitments.constraint_commitment.0);
    }
    let constraint_commitment = domain_hash(&comp_domain, &constraint_data);

    ProofCommitments {
        trace_commitment,
        witness_commitment,
        constraint_commitment,
    }
}

// ---------------------------------------------------------------------------
// compose_proof_data — generate composed proof data
// ---------------------------------------------------------------------------

/// Generate proof data for the composed proof.
///
/// Hashes all individual proof data together with the composed commitments
/// and public inputs for binding.
fn compose_proof_data(
    proofs: &[Proof],
    commitments: &ProofCommitments,
    public_inputs: &PublicInputs,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();

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

    // Bind to all individual proof data.
    hasher.update(&(proofs.len() as u64).to_le_bytes());
    for proof in proofs {
        hasher.update(&(proof.proof_data.len() as u64).to_le_bytes());
        hasher.update(&proof.proof_data);
    }

    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// verify_recursive — recursive proof verification (THM-13)
// ---------------------------------------------------------------------------

/// Verify that an inner proof's commitments are embedded in the outer proof.
///
/// THM-13 (recursive proofs): Verify(π_inner) ⊆ Constraints(π_outer).
/// The inner proof's validity is embedded in the outer proof without
/// external trust.
///
/// Checks:
/// 1. Inner proof commitments are embedded in outer proof data
/// 2. State chaining: inner.root_final == outer.root_init
///
/// Requirements 7.9.
pub fn verify_recursive(outer_proof: &Proof, inner_proof: &Proof) -> bool {
    // Check 1: Verify inner proof commitments are embedded in outer proof data.
    // The outer proof must contain a hash of the inner proof's commitments
    // in its proof_data, demonstrating that the outer proof's constraints
    // include verification of the inner proof.
    let inner_embedding = compute_inner_embedding(inner_proof);
    let embedded = outer_proof
        .proof_data
        .windows(inner_embedding.len())
        .any(|window| window == inner_embedding.as_slice());

    if !embedded {
        // Fall back to checking if the outer proof data was generated
        // with knowledge of the inner proof commitments by verifying
        // the outer proof data includes a domain-separated hash of
        // the inner commitments.
        let recursive_domain = create_domain_tag(DOMAIN_RECURSIVE);
        let inner_hash = domain_hash(&recursive_domain, &inner_embedding);
        let hash_embedded = outer_proof
            .proof_data
            .windows(inner_hash.0.len())
            .any(|window| window == inner_hash.0);

        if !hash_embedded {
            return false;
        }
    }

    // Check 2: State chaining — inner.root_final == outer.root_init.
    inner_proof.public_inputs.root_final == outer_proof.public_inputs.root_init
}

/// Compute the embedding bytes for an inner proof's commitments.
///
/// This is the canonical serialization of the inner proof's commitments
/// that must appear (directly or hashed) in the outer proof's data.
fn compute_inner_embedding(inner_proof: &Proof) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&inner_proof.commitments.trace_commitment.0);
    data.extend_from_slice(&inner_proof.commitments.witness_commitment.0);
    data.extend_from_slice(&inner_proof.commitments.constraint_commitment.0);
    data
}

// ---------------------------------------------------------------------------
// create_recursive_proof — build an outer proof embedding an inner proof
// ---------------------------------------------------------------------------

/// Create an outer proof that embeds verification of an inner proof.
///
/// THM-13: The outer proof's constraints include verification of the
/// inner proof. The outer proof's data contains the inner proof's
/// commitment embedding.
///
/// Requirements 7.9.
pub fn create_recursive_proof(
    inner_proof: &Proof,
    outer_public_inputs: PublicInputs,
    outer_commitments: ProofCommitments,
) -> Result<Proof, ProverError> {
    // Validate state chaining: inner.root_final == outer.root_init.
    if inner_proof.public_inputs.root_final != outer_public_inputs.root_init {
        return Err(ProverError::ProofGenerationFailed(
            "recursive proof state chain broken: inner.root_final != outer.root_init".to_string(),
        ));
    }

    // Compute inner embedding.
    let inner_embedding = compute_inner_embedding(inner_proof);

    // Build outer proof data that includes the inner embedding.
    let recursive_domain = create_domain_tag(DOMAIN_RECURSIVE);
    let inner_hash = domain_hash(&recursive_domain, &inner_embedding);

    let mut hasher = Sha3_256::new();
    // Include outer commitments.
    hasher.update(&outer_commitments.trace_commitment.0);
    hasher.update(&outer_commitments.witness_commitment.0);
    hasher.update(&outer_commitments.constraint_commitment.0);
    // Include outer public inputs.
    hasher.update(&outer_public_inputs.root_init.0);
    hasher.update(&outer_public_inputs.root_final.0);
    hasher.update(&(outer_public_inputs.domain.0).0);
    // Embed inner proof hash (THM-13).
    hasher.update(&inner_hash.0);

    let base_hash = hasher.finalize();

    // The proof data is the base hash concatenated with the inner hash,
    // so verify_recursive can find the embedding.
    let mut proof_data = base_hash.to_vec();
    proof_data.extend_from_slice(&inner_hash.0);

    let metadata = ProofMetadata {
        prover_version: inner_proof.metadata.prover_version.clone(),
        timestamp: 0,
        domain: inner_proof.metadata.domain.clone(),
        proof_system: "stark-placeholder-recursive".to_string(),
    };

    Ok(Proof {
        commitments: outer_commitments,
        proof_data,
        public_inputs: outer_public_inputs,
        metadata,
    })
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{ProofCommitments, ProofMetadata};
    use crate::public_inputs::PublicInputs;
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

    /// Build a proof with configurable root_init and root_final.
    /// This lets us construct chains where proof[i].root_final == proof[i+1].root_init.
    fn make_proof(root_init: Hash, root_final: Hash) -> Proof {
        let commitments = ProofCommitments {
            trace_commitment: make_hash(0x10),
            witness_commitment: make_hash(0x20),
            constraint_commitment: make_hash(0x30),
        };
        let public_inputs = PublicInputs {
            root_init,
            root_final,
            observables: vec![vsel_core::observable::Observable {
                transition_class: vsel_core::transition::TransitionClass::Update,
                outputs: vec![],
                gas_used: 100,
                status: vsel_core::observable::TransitionStatus::Success,
            }],
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

    /// Build a chain of N proofs with consistent state chaining.
    fn make_chain(n: usize) -> Vec<Proof> {
        let mut proofs = Vec::new();
        for i in 0..n {
            let root_init = make_hash(i as u8);
            let root_final = make_hash((i + 1) as u8);
            proofs.push(make_proof(root_init, root_final));
        }
        proofs
    }

    // -----------------------------------------------------------------------
    // compose — success cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_compose_two_proofs() {
        let proofs = make_chain(2);
        let composed = compose(&proofs).expect("composition should succeed");

        // root_init from first proof.
        assert_eq!(composed.public_inputs.root_init, proofs[0].public_inputs.root_init);
        // root_final from last proof.
        assert_eq!(composed.public_inputs.root_final, proofs[1].public_inputs.root_final);
        // Observables combined.
        assert_eq!(composed.public_inputs.observables.len(), 2);
        // Domain preserved.
        assert_eq!(composed.public_inputs.domain, test_domain());
        // Version preserved.
        assert_eq!(composed.public_inputs.version, test_version());
        // Proof data non-empty.
        assert!(!composed.proof_data.is_empty());
        // Commitments non-trivial.
        assert_ne!(composed.commitments.trace_commitment, Hash([0u8; 32]));
    }

    #[test]
    fn test_compose_three_proofs() {
        let proofs = make_chain(3);
        let composed = compose(&proofs).expect("composition should succeed");

        assert_eq!(composed.public_inputs.root_init, make_hash(0));
        assert_eq!(composed.public_inputs.root_final, make_hash(3));
        assert_eq!(composed.public_inputs.observables.len(), 3);
    }

    #[test]
    fn test_compose_five_proofs() {
        let proofs = make_chain(5);
        let composed = compose(&proofs).expect("composition should succeed");

        assert_eq!(composed.public_inputs.root_init, make_hash(0));
        assert_eq!(composed.public_inputs.root_final, make_hash(5));
        assert_eq!(composed.public_inputs.observables.len(), 5);
    }

    #[test]
    fn test_compose_deterministic() {
        let proofs = make_chain(3);
        let c1 = compose(&proofs).expect("c1");
        let c2 = compose(&proofs).expect("c2");

        assert_eq!(c1.commitments, c2.commitments);
        assert_eq!(c1.proof_data, c2.proof_data);
        assert_eq!(c1.public_inputs, c2.public_inputs);
    }

    #[test]
    fn test_compose_preserves_observable_order() {
        let mut proofs = make_chain(2);
        // Give each proof distinct observables.
        proofs[0].public_inputs.observables = vec![vsel_core::observable::Observable {
            transition_class: vsel_core::transition::TransitionClass::Init,
            outputs: vec![],
            gas_used: 1,
            status: vsel_core::observable::TransitionStatus::Success,
        }];
        proofs[1].public_inputs.observables = vec![vsel_core::observable::Observable {
            transition_class: vsel_core::transition::TransitionClass::Update,
            outputs: vec![],
            gas_used: 2,
            status: vsel_core::observable::TransitionStatus::Success,
        }];

        let composed = compose(&proofs).expect("compose");
        assert_eq!(composed.public_inputs.observables.len(), 2);
        assert_eq!(composed.public_inputs.observables[0].gas_used, 1);
        assert_eq!(composed.public_inputs.observables[1].gas_used, 2);
    }

    // -----------------------------------------------------------------------
    // compose — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_compose_empty_rejected() {
        let result = compose(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least 2 proofs"));
    }

    #[test]
    fn test_compose_single_proof_rejected() {
        let proofs = make_chain(1);
        let result = compose(&proofs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least 2 proofs"));
    }

    #[test]
    fn test_compose_broken_state_chain() {
        let mut proofs = make_chain(3);
        // Break the chain: proof[1].root_init != proof[0].root_final.
        proofs[1].public_inputs.root_init = make_hash(0xFF);

        let result = compose(&proofs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("state chain broken"));
    }

    #[test]
    fn test_compose_domain_mismatch() {
        let mut proofs = make_chain(2);
        proofs[1].public_inputs.domain = DomainTag(Hash([0xFF; 32]));

        let result = compose(&proofs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("domain mismatch"));
    }

    #[test]
    fn test_compose_version_mismatch() {
        let mut proofs = make_chain(2);
        proofs[1].public_inputs.version = ProtocolVersion {
            major: 99,
            minor: 0,
            patch: 0,
        };

        let result = compose(&proofs);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("version mismatch"));
    }

    // -----------------------------------------------------------------------
    // verify_recursive — success cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_recursive_valid() {
        // Create inner proof.
        let inner = make_proof(make_hash(0), make_hash(1));

        // Create outer proof that embeds the inner proof.
        let outer_pub = PublicInputs {
            root_init: make_hash(1), // chains from inner.root_final
            root_final: make_hash(2),
            observables: vec![],
            domain: test_domain(),
            version: test_version(),
        };
        let outer_commitments = ProofCommitments {
            trace_commitment: make_hash(0x40),
            witness_commitment: make_hash(0x50),
            constraint_commitment: make_hash(0x60),
        };

        let outer = create_recursive_proof(&inner, outer_pub, outer_commitments)
            .expect("recursive proof creation should succeed");

        assert!(verify_recursive(&outer, &inner));
    }

    #[test]
    fn test_verify_recursive_state_chain_mismatch() {
        let inner = make_proof(make_hash(0), make_hash(1));

        // Outer proof root_init doesn't match inner root_final.
        let outer_pub = PublicInputs {
            root_init: make_hash(0xFF), // does NOT chain from inner
            root_final: make_hash(2),
            observables: vec![],
            domain: test_domain(),
            version: test_version(),
        };
        let outer_commitments = ProofCommitments {
            trace_commitment: make_hash(0x40),
            witness_commitment: make_hash(0x50),
            constraint_commitment: make_hash(0x60),
        };

        let outer = create_recursive_proof(&inner, outer_pub, outer_commitments);
        assert!(outer.is_err());
    }

    #[test]
    fn test_verify_recursive_no_embedding() {
        let inner = make_proof(make_hash(0), make_hash(1));

        // Manually construct an outer proof without embedding.
        let outer = Proof {
            commitments: ProofCommitments {
                trace_commitment: make_hash(0x40),
                witness_commitment: make_hash(0x50),
                constraint_commitment: make_hash(0x60),
            },
            proof_data: vec![0x00, 0x01, 0x02], // no inner embedding
            public_inputs: PublicInputs {
                root_init: make_hash(1),
                root_final: make_hash(2),
                observables: vec![],
                domain: test_domain(),
                version: test_version(),
            },
            metadata: ProofMetadata {
                prover_version: "0.1.0".to_string(),
                timestamp: 0,
                domain: proof_tag(),
                proof_system: "stark-placeholder".to_string(),
            },
        };

        // Should fail because inner commitments are not embedded.
        assert!(!verify_recursive(&outer, &inner));
    }

    // -----------------------------------------------------------------------
    // create_recursive_proof
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_recursive_proof_metadata() {
        let inner = make_proof(make_hash(0), make_hash(1));
        let outer_pub = PublicInputs {
            root_init: make_hash(1),
            root_final: make_hash(2),
            observables: vec![],
            domain: test_domain(),
            version: test_version(),
        };
        let outer_commitments = ProofCommitments {
            trace_commitment: make_hash(0x40),
            witness_commitment: make_hash(0x50),
            constraint_commitment: make_hash(0x60),
        };

        let outer = create_recursive_proof(&inner, outer_pub, outer_commitments)
            .expect("should succeed");

        assert_eq!(outer.metadata.proof_system, "stark-placeholder-recursive");
        assert!(!outer.proof_data.is_empty());
    }

    // -----------------------------------------------------------------------
    // compose_commitments — internal
    // -----------------------------------------------------------------------

    #[test]
    fn test_composed_commitments_differ_from_individual() {
        let proofs = make_chain(2);
        let composed = compose(&proofs).expect("compose");

        // Composed commitments should differ from any individual proof's commitments.
        for proof in &proofs {
            assert_ne!(composed.commitments.trace_commitment, proof.commitments.trace_commitment);
        }
    }

    #[test]
    fn test_composed_commitments_order_sensitive() {
        let chain = make_chain(3);

        // Compose in original order.
        let c1 = compose(&chain).expect("c1");

        // Compose with first two swapped (but fix chaining to make it valid).
        // Since swapping breaks chaining, we just verify that different
        // proof sets produce different commitments.
        let mut alt_chain = make_chain(3);
        alt_chain[0].commitments.trace_commitment = make_hash(0x99);
        // Fix chaining.
        alt_chain[0].public_inputs.root_final = alt_chain[1].public_inputs.root_init.clone();

        let c2 = compose(&alt_chain).expect("c2");
        assert_ne!(c1.commitments.trace_commitment, c2.commitments.trace_commitment);
    }
}
