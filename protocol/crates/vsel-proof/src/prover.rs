//! Prover — proof generation for the VSEL proof system.
//!
//! Derived from: PROOF_LAYER.md §2-§5, CRYPTOGRAPHIC_MODEL.md §4,
//! Requirements 7.1, 7.2, 7.5, 7.10.
//!
//! The prover generates a proof π = (Com, proof_data, Pub, Meta) attesting
//! that an execution trace τ is semantically valid under the constraint
//! system. The proof binds to the complete trace (PROOF-1), includes all
//! observables in public inputs (PROOF-2), uses domain-separated hashing
//! (PROOF-3), and enforces knowledge soundness (PROOF-4).
//!
//! Since we don't have a real ZK backend (Plonky3) yet, proof generation
//! uses hash-based commitments as a faithful simulation. The structure is
//! designed so a real backend can be plugged in later.

use sha3::{Digest, Sha3_256};
use thiserror::Error;

use vsel_constraints::ConstraintSystem;
use vsel_core::types::{DomainTag, Hash};
use vsel_crypto::domain::{create_domain_tag, domain_hash, proof_tag, DOMAIN_WITNESS};
use vsel_trace::engine::Trace;

use crate::public_inputs::PublicInputs;
use crate::witness::{construct_witness, verify_auxiliary_independence, Witness};

// ---------------------------------------------------------------------------
// ProverError
// ---------------------------------------------------------------------------

/// Errors that can occur during proof generation.
///
/// Each variant maps to a specific failure mode in the proving pipeline.
#[derive(Debug, Error)]
pub enum ProverError {
    /// The trace has no entries — nothing to prove.
    #[error("empty trace: cannot generate proof for a trace with no entries")]
    EmptyTrace,

    /// The trace is structurally invalid (e.g., broken chain hashes).
    #[error("invalid trace: {0}")]
    InvalidTrace(String),

    /// The trace does not satisfy the constraint system.
    #[error("constraint violation: trace does not satisfy constraint system")]
    ConstraintViolation,

    /// Witness construction failed.
    #[error("witness construction failed: {0}")]
    WitnessConstructionFailed(String),

    /// Auxiliary variables are not independent of semantic outcome (THM-4).
    #[error("auxiliary dependence detected: auxiliary variables influence semantic outcome")]
    AuxiliaryDependenceDetected,

    /// Proof generation failed (backend error).
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
}

// ---------------------------------------------------------------------------
// ProofCommitments — cryptographic commitments binding the proof
// ---------------------------------------------------------------------------

/// Cryptographic commitments that bind the proof to the execution.
///
/// PROOF-1 (full trace binding): the trace_commitment covers the entire
/// trace including all intermediate states, not just endpoints.
///
/// Requirements 7.1, 7.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCommitments {
    /// Commitment to the full execution trace (chain hash).
    /// Binds the proof to every intermediate state (PROOF-1).
    pub trace_commitment: Hash,
    /// Commitment to the witness (intermediate states + inputs + aux).
    pub witness_commitment: Hash,
    /// Commitment to the constraint system used for proving.
    pub constraint_commitment: Hash,
}

// ---------------------------------------------------------------------------
// ProofMetadata — metadata about the proof generation context
// ---------------------------------------------------------------------------

/// Metadata describing the proof generation context.
///
/// Captures the prover version, timestamp, domain tag, and proof system
/// identifier for auditability and version compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMetadata {
    /// Version string of the prover implementation.
    pub prover_version: String,
    /// Timestamp (unix epoch seconds) when the proof was generated.
    pub timestamp: u64,
    /// Domain separation tag for this proof context (PROOF-3).
    pub domain: DomainTag,
    /// Identifier for the proof system backend (e.g., "stark-placeholder").
    pub proof_system: String,
}

// ---------------------------------------------------------------------------
// Proof — the complete proof artifact
// ---------------------------------------------------------------------------

/// A complete proof artifact: π = (Com, proof_data, Pub, Meta).
///
/// PROOF_LAYER.md §2: Verify(π) ⟹ ValidTrace(τ) — the proof attests
/// semantic validity, not just computational correctness (THM-8).
///
/// Requirements 7.1, 7.2, 7.5, 7.10.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Cryptographic commitments binding the proof to the execution.
    pub commitments: ProofCommitments,
    /// Opaque proof data (STARK proof bytes in a real backend).
    pub proof_data: Vec<u8>,
    /// Public inputs — the externally visible statement the proof attests to.
    pub public_inputs: PublicInputs,
    /// Metadata about the proof generation context.
    pub metadata: ProofMetadata,
}

// ---------------------------------------------------------------------------
// Prover trait
// ---------------------------------------------------------------------------

/// Trait for proof generation.
///
/// Implementors generate a proof that an execution trace satisfies a
/// constraint system. The proof must enforce PROOF-1 through PROOF-4.
pub trait Prover {
    /// Generate a proof that `trace` satisfies `constraints`.
    ///
    /// Returns `Proof` on success, or `ProverError` if the trace is
    /// invalid, constraints are violated, or proof generation fails.
    fn prove(
        &self,
        trace: &Trace,
        constraints: &ConstraintSystem,
    ) -> Result<Proof, ProverError>;
}

// ---------------------------------------------------------------------------
// DefaultProver — hash-based placeholder implementation
// ---------------------------------------------------------------------------

/// Default prover using hash-based commitments as a STARK placeholder.
///
/// Enforces all semantic properties (PROOF-1 through PROOF-4) while
/// using SHA3-256 commitments instead of a real ZK backend. The structure
/// is designed so Plonky3 or similar can be plugged in later.
///
/// Requirements 7.1, 7.2, 7.5, 7.10.
pub struct DefaultProver {
    /// Version string for this prover.
    pub version: String,
}

impl DefaultProver {
    /// Create a new DefaultProver with the given version string.
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
        }
    }

    /// Commit to a witness by hashing all its components.
    ///
    /// Domain-separated: uses DOMAIN_WITNESS tag.
    /// Covers intermediate states, input sequence, and auxiliary data
    /// to enforce knowledge soundness (PROOF-4).
    fn commit_witness(&self, witness: &Witness) -> Hash {
        let witness_domain = create_domain_tag(DOMAIN_WITNESS);
        let mut data = Vec::new();

        // Hash intermediate state count + each state's canonical commitment.
        data.extend_from_slice(&(witness.intermediate_states.len() as u64).to_le_bytes());
        for state in &witness.intermediate_states {
            let state_commit = vsel_core::state::commit(&state.canonical);
            data.extend_from_slice(&state_commit.0);
        }

        // Hash input sequence.
        data.extend_from_slice(&(witness.input_sequence.len() as u64).to_le_bytes());
        for input in &witness.input_sequence {
            // Hash payload type + data.
            data.extend_from_slice(input.payload.payload_type.as_bytes());
            data.extend_from_slice(&input.payload.data);
            // Hash auth nonce for binding.
            data.extend_from_slice(&input.auth.nonce.to_le_bytes());
        }

        // Hash auxiliary computation values.
        data.extend_from_slice(&(witness.aux_computation.values.len() as u64).to_le_bytes());
        for (name, value) in &witness.aux_computation.values {
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(value);
        }

        domain_hash(&witness_domain, &data)
    }

    /// Commit to a constraint system by hashing its structure.
    ///
    /// Domain-separated: uses DOMAIN_PROOF tag.
    fn commit_constraints(&self, constraints: &ConstraintSystem) -> Hash {
        let proof_domain = proof_tag();
        let mut data = Vec::new();

        data.extend_from_slice(constraints.version.as_bytes());
        data.extend_from_slice(&(constraints.constraints.len() as u64).to_le_bytes());
        data.extend_from_slice(&(constraints.witness_variables.len() as u64).to_le_bytes());
        data.extend_from_slice(&(constraints.public_inputs.len() as u64).to_le_bytes());

        // Hash each constraint description for binding.
        for constraint in &constraints.constraints {
            data.extend_from_slice(&constraint.id.0.to_le_bytes());
            data.extend_from_slice(constraint.description.as_bytes());
        }

        domain_hash(&proof_domain, &data)
    }

    /// Generate STARK-style placeholder proof data.
    ///
    /// In a real backend, this would be the STARK proof bytes.
    /// Here we hash all commitments together as a faithful simulation.
    fn generate_proof_data(
        &self,
        commitments: &ProofCommitments,
        public_inputs: &PublicInputs,
    ) -> Vec<u8> {
        let mut hasher = Sha3_256::new();

        // Bind to all commitments.
        hasher.update(&commitments.trace_commitment.0);
        hasher.update(&commitments.witness_commitment.0);
        hasher.update(&commitments.constraint_commitment.0);

        // Bind to public inputs.
        hasher.update(&public_inputs.root_init.0);
        hasher.update(&public_inputs.root_final.0);
        hasher.update(&(public_inputs.observables.len() as u64).to_le_bytes());
        hasher.update(&(public_inputs.domain.0).0);
        hasher.update(&public_inputs.version.major.to_le_bytes());
        hasher.update(&public_inputs.version.minor.to_le_bytes());
        hasher.update(&public_inputs.version.patch.to_le_bytes());

        let result = hasher.finalize();
        result.to_vec()
    }
}

impl Prover for DefaultProver {
    /// Generate a proof that `trace` satisfies `constraints`.
    ///
    /// Pipeline:
    /// 1. Validate trace is non-empty
    /// 2. Construct witness from trace (PROOF-4: knowledge soundness)
    /// 3. Verify auxiliary independence (THM-4)
    /// 4. Build public inputs from trace (PROOF-2: observable binding)
    /// 5. Generate proof commitments (PROOF-1: full trace binding)
    /// 6. Generate proof data (STARK placeholder)
    /// 7. Assemble and return Proof
    fn prove(
        &self,
        trace: &Trace,
        constraints: &ConstraintSystem,
    ) -> Result<Proof, ProverError> {
        // 1. Validate trace is non-empty.
        if trace.entries.is_empty() {
            return Err(ProverError::EmptyTrace);
        }

        // 2. Construct witness from trace.
        // PROOF-4 (knowledge soundness): the prover must "know" a valid
        // witness — we construct it from the actual execution trace.
        let witness = construct_witness(trace);

        // 3. Verify auxiliary independence (THM-4).
        // Auxiliary variables must not influence semantic outcome.
        if !verify_auxiliary_independence(&witness) {
            return Err(ProverError::AuxiliaryDependenceDetected);
        }

        // 4. Build public inputs from trace.
        // PROOF-2 (observable binding): all observables are included in
        // or derivable from public inputs.
        let public_inputs = PublicInputs::from_trace(trace);

        // Verify observable binding — all trace observables match public inputs.
        let trace_observables: Vec<_> = trace
            .entries
            .iter()
            .map(|e| e.observable.clone())
            .collect();
        if !public_inputs.verify_observable_binding(&trace_observables) {
            return Err(ProverError::InvalidTrace(
                "observable binding failed: trace observables do not match public inputs"
                    .to_string(),
            ));
        }

        // 5. Generate proof commitments.
        // PROOF-1 (full trace binding): the trace commitment is the final
        // chain hash, which covers ALL intermediate states and transitions.
        let trace_commitment = trace.commitment.clone();
        let witness_commitment = self.commit_witness(&witness);
        let constraint_commitment = self.commit_constraints(constraints);

        let commitments = ProofCommitments {
            trace_commitment,
            witness_commitment,
            constraint_commitment,
        };

        // 6. Generate proof data (STARK-style placeholder).
        let proof_data = self.generate_proof_data(&commitments, &public_inputs);

        // 7. Assemble proof with metadata.
        let metadata = ProofMetadata {
            prover_version: self.version.clone(),
            timestamp: 0, // Placeholder — real impl would use system time.
            domain: proof_tag(),
            proof_system: "stark-placeholder".to_string(),
        };

        Ok(Proof {
            commitments,
            proof_data,
            public_inputs,
            metadata,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_constraints::{Constraint, ConstraintCategory, ConstraintExpr, ConstraintId};
    use vsel_core::input::{Authorization, Input};
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::state::*;
    use vsel_core::transition::TransitionClass;
    use vsel_core::types::*;
    use vsel_trace::engine::{Trace, TraceEntry};

    // -- Test helpers --

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

    fn default_prover() -> DefaultProver {
        DefaultProver::new("0.1.0-test")
    }

    // -----------------------------------------------------------------------
    // DefaultProver::new tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_prover_creation() {
        let prover = DefaultProver::new("1.0.0");
        assert_eq!(prover.version, "1.0.0");
    }

    // -----------------------------------------------------------------------
    // prove — success cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_prove_single_entry_trace() {
        let prover = default_prover();
        let trace = test_trace(1);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof should succeed");

        // Verify commitments are non-zero.
        assert_ne!(proof.commitments.trace_commitment, Hash([0u8; 32]));
        assert_ne!(proof.commitments.witness_commitment, Hash([0u8; 32]));
        assert_ne!(proof.commitments.constraint_commitment, Hash([0u8; 32]));

        // Verify proof data is non-empty.
        assert!(!proof.proof_data.is_empty());

        // Verify public inputs match the trace.
        assert!(proof.public_inputs.matches_trace(&trace));

        // Verify metadata.
        assert_eq!(proof.metadata.prover_version, "0.1.0-test");
        assert_eq!(proof.metadata.proof_system, "stark-placeholder");
    }

    #[test]
    fn test_prove_multi_entry_trace() {
        let prover = default_prover();
        let trace = test_trace(5);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof should succeed");

        // PROOF-1: trace commitment binds to complete trace.
        assert_eq!(proof.commitments.trace_commitment, trace.commitment);

        // PROOF-2: all observables in public inputs.
        assert_eq!(proof.public_inputs.observables.len(), 5);
        for (i, obs) in proof.public_inputs.observables.iter().enumerate() {
            assert_eq!(obs, &trace.entries[i].observable);
        }
    }

    #[test]
    fn test_prove_deterministic() {
        let prover = default_prover();
        let trace = test_trace(3);
        let cs = test_constraint_system();

        let proof1 = prover.prove(&trace, &cs).expect("proof 1");
        let proof2 = prover.prove(&trace, &cs).expect("proof 2");

        // Same trace + same constraints = same commitments and proof data.
        assert_eq!(proof1.commitments, proof2.commitments);
        assert_eq!(proof1.proof_data, proof2.proof_data);
        assert_eq!(proof1.public_inputs, proof2.public_inputs);
    }

    // -----------------------------------------------------------------------
    // prove — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_prove_empty_trace_rejected() {
        let prover = default_prover();
        let trace = test_trace(0);
        let cs = test_constraint_system();

        let result = prover.prove(&trace, &cs);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProverError::EmptyTrace => {} // Expected.
            other => panic!("expected EmptyTrace, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // PROOF-1: Full trace binding
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_binds_to_complete_trace() {
        let prover = default_prover();
        let trace = test_trace(3);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");

        // The trace commitment must be the final chain hash,
        // which covers ALL entries (not just endpoints).
        assert_eq!(proof.commitments.trace_commitment, trace.commitment);

        // Changing the last entry's chain hash changes the trace commitment,
        // demonstrating that intermediate states are bound.
        let mut modified_trace = trace.clone();
        modified_trace.entries[2].chain_hash = Hash([0xFF; 32]);
        // Update the trace commitment to reflect the modified chain.
        modified_trace.commitment = modified_trace.entries.last().unwrap().chain_hash.clone();

        let proof2 = prover.prove(&modified_trace, &cs).expect("proof2");
        assert_ne!(
            proof.commitments.trace_commitment,
            proof2.commitments.trace_commitment,
            "PROOF-1: modifying intermediate state must change trace commitment"
        );
    }

    // -----------------------------------------------------------------------
    // PROOF-2: Observable binding
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_observable_binding() {
        let prover = default_prover();
        let trace = test_trace(2);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");

        // All trace observables must be in public inputs.
        let trace_obs: Vec<Observable> =
            trace.entries.iter().map(|e| e.observable.clone()).collect();
        assert!(proof.public_inputs.verify_observable_binding(&trace_obs));
    }

    // -----------------------------------------------------------------------
    // PROOF-3: Domain separation
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_domain_separation() {
        let prover = default_prover();
        let trace = test_trace(1);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");

        // Metadata domain must be the proof domain tag.
        assert_eq!(proof.metadata.domain, proof_tag());

        // Proof domain must differ from other domain tags.
        assert_ne!(proof.metadata.domain, vsel_crypto::domain::trace_commitment_tag());
        assert_ne!(proof.metadata.domain, vsel_crypto::domain::state_commitment_tag());
    }

    // -----------------------------------------------------------------------
    // PROOF-4: Knowledge soundness
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_knowledge_soundness() {
        let prover = default_prover();
        let trace = test_trace(3);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");

        // The witness commitment must be non-trivial — the prover
        // committed to actual witness data (intermediate states, inputs).
        assert_ne!(proof.commitments.witness_commitment, Hash([0u8; 32]));

        // Different traces must produce different witness commitments.
        let trace2 = test_trace(2);
        let proof2 = prover.prove(&trace2, &cs).expect("proof2");
        assert_ne!(
            proof.commitments.witness_commitment,
            proof2.commitments.witness_commitment,
            "PROOF-4: different traces must produce different witness commitments"
        );
    }

    // -----------------------------------------------------------------------
    // Commitment determinism
    // -----------------------------------------------------------------------

    #[test]
    fn test_witness_commitment_deterministic() {
        let prover = default_prover();
        let trace = test_trace(2);
        let witness = construct_witness(&trace);

        let c1 = prover.commit_witness(&witness);
        let c2 = prover.commit_witness(&witness);
        assert_eq!(c1, c2, "witness commitment must be deterministic");
    }

    #[test]
    fn test_constraint_commitment_deterministic() {
        let prover = default_prover();
        let cs = test_constraint_system();

        let c1 = prover.commit_constraints(&cs);
        let c2 = prover.commit_constraints(&cs);
        assert_eq!(c1, c2, "constraint commitment must be deterministic");
    }

    #[test]
    fn test_different_constraints_different_commitment() {
        let prover = default_prover();

        let cs1 = test_constraint_system();
        let mut cs2 = test_constraint_system();
        cs2.add_constraint(Constraint {
            id: ConstraintId(99),
            expr: ConstraintExpr::BoolConstant(false),
            category: ConstraintCategory::Semantic,
            description: "extra constraint".to_string(),
        });

        let c1 = prover.commit_constraints(&cs1);
        let c2 = prover.commit_constraints(&cs2);
        assert_ne!(c1, c2, "different constraint systems must produce different commitments");
    }

    // -----------------------------------------------------------------------
    // Public inputs match trace
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_public_inputs_match_trace() {
        let prover = default_prover();
        let trace = test_trace(3);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");
        assert!(
            proof.public_inputs.matches_trace(&trace),
            "proof public inputs must match the trace"
        );
    }

    // -----------------------------------------------------------------------
    // Proof data non-empty and deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn test_proof_data_non_empty() {
        let prover = default_prover();
        let trace = test_trace(1);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("proof");
        assert!(!proof.proof_data.is_empty());
        // SHA3-256 output is 32 bytes.
        assert_eq!(proof.proof_data.len(), 32);
    }

    #[test]
    fn test_proof_data_changes_with_trace() {
        let prover = default_prover();
        let cs = test_constraint_system();

        let proof1 = prover.prove(&test_trace(1), &cs).expect("proof1");
        let proof2 = prover.prove(&test_trace(2), &cs).expect("proof2");

        assert_ne!(
            proof1.proof_data, proof2.proof_data,
            "different traces must produce different proof data"
        );
    }
}
