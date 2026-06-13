//! Prover — proof generation for the VSEL proof system.
//!
//! Derived from: PROOF_LAYER.md §2-§5, CRYPTOGRAPHIC_MODEL.md §4,
//! Requirements 1.4, 1.5, 1.6, 1.8, 7.1, 7.2, 7.5, 7.10.
//!
//! The prover generates a proof π = (Com, proof_data, Pub, Meta) binding
//! the trace-derived commitments, public inputs, and backend proof data. This
//! is not a standalone semantic-validity certificate. Final semantic
//! acceptance is a verifier-side decision requiring strict witness/constraint
//! checks and authoritative semantic evidence.
//!
//! `GenericProver<B: ZkBackend>` is the legacy hash-placeholder prover kept
//! for backward compatibility. It does not produce backend-native proof
//! bytes. `BackendProver<B: ZkBackend>` owns a concrete backend and delegates
//! proof generation through `ZkBackend::prove`; this is the prover shape
//! required for STARK-backed final acceptance.

use std::marker::PhantomData;

use sha3::{Digest, Sha3_256};
use thiserror::Error;

use vsel_constraints::{ConstraintCategory, ConstraintExpr, ConstraintSystem, WitnessVariableKind};
use vsel_core::types::{DomainTag, Hash};
use vsel_crypto::domain::{create_domain_tag, domain_hash, proof_tag, DOMAIN_WITNESS};
use vsel_trace::engine::Trace;

use crate::backend::ZkBackend;
use crate::hash_backend::HashBackend;
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
/// The proof binds commitments, proof data, public inputs, and metadata.
/// Semantic validity is not established by a proof artifact alone; final
/// acceptance requires `VerificationPipeline::verify_strict` with witness,
/// constraints, and authoritative semantic verification evidence.
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
    fn prove(&self, trace: &Trace, constraints: &ConstraintSystem) -> Result<Proof, ProverError>;
}

// ---------------------------------------------------------------------------
// GenericProver<B: ZkBackend> — legacy hash-placeholder prover
// ---------------------------------------------------------------------------

/// Legacy prover parameterized over a ZK backend type.
///
/// The proving pipeline (validate → witness → aux independence →
/// public inputs → commitments → proof) is preserved for compatibility,
/// but proof bytes are synthetic SHA3-256 binding bytes. The backend type
/// parameter is retained to avoid breaking existing APIs; it is not used to
/// generate backend-native proofs.
///
/// This prover must not be used as evidence for STARK/Cairo final acceptance.
/// Use `BackendProver<B>` with a concrete `ZkBackend` for backend-native proof
/// generation.
///
/// Requirements 1.4, 1.5, 7.1, 7.2, 7.5, 7.10.
pub struct GenericProver<B: ZkBackend> {
    /// Version string for this prover.
    pub version: String,
    /// Phantom data for the legacy backend type parameter.
    _backend: PhantomData<B>,
}

/// Backend-backed prover that delegates proof generation to a concrete
/// `ZkBackend`.
///
/// This prover closes the placeholder/proof-system relabel gap: proof metadata
/// is derived from `backend.backend_id()` and proof bytes are exactly
/// `backend.serialize_proof(backend.prove(...))`.
pub struct BackendProver<B: ZkBackend> {
    /// Version string for this prover.
    pub version: String,
    /// Concrete proof backend.
    pub backend: B,
}

/// Backward-compatible type alias.
///
/// `DefaultProver` is `GenericProver<HashBackend>`, preserving all existing
/// API usage: `DefaultProver::new(...)`, `prover.prove(...)`, etc.
///
/// Requirements 1.5, 1.6.
pub type DefaultProver = GenericProver<HashBackend>;

impl<B: ZkBackend> GenericProver<B> {
    /// Create a new GenericProver with the given version string.
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            _backend: PhantomData,
        }
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

        // Bind to public inputs, including complete observable content.
        hasher.update(&public_inputs.root_init.0);
        hasher.update(&public_inputs.root_final.0);
        hasher.update(&(public_inputs.observables.len() as u64).to_le_bytes());
        for observable in &public_inputs.observables {
            hash_observable(&mut hasher, observable);
        }
        hasher.update(&(public_inputs.domain.0).0);
        hasher.update(&public_inputs.version.major.to_le_bytes());
        hasher.update(&public_inputs.version.minor.to_le_bytes());
        hasher.update(&public_inputs.version.patch.to_le_bytes());

        let result = hasher.finalize();
        result.to_vec()
    }
}

impl<B: ZkBackend> BackendProver<B> {
    /// Create a backend-backed prover with a concrete proof backend.
    pub fn new(version: &str, backend: B) -> Self {
        Self {
            version: version.to_string(),
            backend,
        }
    }
}

struct PreparedProofStatement {
    witness: Witness,
    public_inputs: PublicInputs,
    commitments: ProofCommitments,
}

fn prepare_proof_statement(
    trace: &Trace,
    constraints: &ConstraintSystem,
) -> Result<PreparedProofStatement, ProverError> {
    // 1. Validate trace is non-empty.
    if trace.entries.is_empty() {
        return Err(ProverError::EmptyTrace);
    }

    // 2. Construct witness from trace.
    let witness = construct_witness(trace);

    // 3. Verify auxiliary independence (THM-4).
    if !verify_auxiliary_independence(&witness) {
        return Err(ProverError::AuxiliaryDependenceDetected);
    }

    // 4. Build public inputs from trace and verify observable binding.
    let public_inputs = PublicInputs::from_trace(trace);
    let trace_observables: Vec<_> = trace.entries.iter().map(|e| e.observable.clone()).collect();
    if !public_inputs.verify_observable_binding(&trace_observables) {
        return Err(ProverError::InvalidTrace(
            "observable binding failed: trace observables do not match public inputs".to_string(),
        ));
    }

    // 5. Generate proof commitments.
    let commitments = ProofCommitments {
        trace_commitment: trace.commitment.clone(),
        witness_commitment: canonical_witness_commitment(&witness),
        constraint_commitment: canonical_constraint_commitment(constraints),
    };

    Ok(PreparedProofStatement {
        witness,
        public_inputs,
        commitments,
    })
}

/// Compute the canonical witness commitment used by backend-native proof
/// adapters and strict verification.
///
/// External VSEL-aware adapters may use this value as an allowlist input when
/// binding native proof artifacts to a concrete VSEL witness.
pub fn canonical_witness_commitment(witness: &Witness) -> Hash {
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
        data.extend_from_slice(input.payload.payload_type.as_bytes());
        data.extend_from_slice(&input.payload.data);
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

/// Compute the canonical constraint-system commitment used by backend-native
/// proof adapters and strict verification.
///
/// This is part of the public integration contract for native proof adapters:
/// a native verifier wrapper must reject artifacts whose attested constraint
/// commitment is not this value for the supplied constraint system.
pub fn canonical_constraint_commitment(constraints: &ConstraintSystem) -> Hash {
    let proof_domain = proof_tag();
    let mut data = Vec::new();

    encode_string(&mut data, &constraints.version);
    data.extend_from_slice(&(constraints.constraints.len() as u64).to_le_bytes());
    data.extend_from_slice(&(constraints.witness_variables.len() as u64).to_le_bytes());
    data.extend_from_slice(&(constraints.public_inputs.len() as u64).to_le_bytes());

    for constraint in &constraints.constraints {
        data.extend_from_slice(&constraint.id.0.to_le_bytes());
        data.push(encode_constraint_category(constraint.category));
        encode_string(&mut data, &constraint.description);
        encode_constraint_expr(&mut data, &constraint.expr);
    }

    for variable in &constraints.witness_variables {
        encode_string(&mut data, &variable.name);
        data.push(encode_witness_kind(variable.kind));
        encode_string(&mut data, &variable.description);
    }

    for public_input in &constraints.public_inputs {
        encode_string(&mut data, &public_input.name);
        encode_string(&mut data, &public_input.description);
    }

    domain_hash(&proof_domain, &data)
}

fn encode_string(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn encode_constraint_category(category: ConstraintCategory) -> u8 {
    match category {
        ConstraintCategory::Structural => 0,
        ConstraintCategory::Semantic => 1,
        ConstraintCategory::Invariant => 2,
        ConstraintCategory::CarryOver => 3,
        ConstraintCategory::Branch => 4,
    }
}

fn encode_witness_kind(kind: WitnessVariableKind) -> u8 {
    match kind {
        WitnessVariableKind::Semantic => 0,
        WitnessVariableKind::Auxiliary => 1,
        WitnessVariableKind::Derived => 2,
    }
}

fn encode_constraint_expr(buf: &mut Vec<u8>, expr: &ConstraintExpr) {
    match expr {
        ConstraintExpr::Constant(value) => {
            buf.push(0);
            buf.extend_from_slice(&value.to_le_bytes());
        }
        ConstraintExpr::BoolConstant(value) => {
            buf.push(1);
            buf.push(u8::from(*value));
        }
        ConstraintExpr::WitnessRef(name) => {
            buf.push(2);
            encode_string(buf, name);
        }
        ConstraintExpr::PublicInputRef(name) => {
            buf.push(3);
            encode_string(buf, name);
        }
        ConstraintExpr::Eq(left, right) => encode_binary_expr(buf, 4, left, right),
        ConstraintExpr::Neq(left, right) => encode_binary_expr(buf, 5, left, right),
        ConstraintExpr::Lt(left, right) => encode_binary_expr(buf, 6, left, right),
        ConstraintExpr::Le(left, right) => encode_binary_expr(buf, 7, left, right),
        ConstraintExpr::Gt(left, right) => encode_binary_expr(buf, 8, left, right),
        ConstraintExpr::Ge(left, right) => encode_binary_expr(buf, 9, left, right),
        ConstraintExpr::Add(left, right) => encode_binary_expr(buf, 10, left, right),
        ConstraintExpr::Sub(left, right) => encode_binary_expr(buf, 11, left, right),
        ConstraintExpr::Mul(left, right) => encode_binary_expr(buf, 12, left, right),
        ConstraintExpr::And(left, right) => encode_binary_expr(buf, 13, left, right),
        ConstraintExpr::Or(left, right) => encode_binary_expr(buf, 14, left, right),
        ConstraintExpr::IfThenElse(cond, then_, else_) => {
            buf.push(15);
            encode_constraint_expr(buf, cond);
            encode_constraint_expr(buf, then_);
            encode_constraint_expr(buf, else_);
        }
        ConstraintExpr::FieldAccess(base, field) => {
            buf.push(16);
            encode_constraint_expr(buf, base);
            encode_string(buf, field);
        }
    }
}

fn encode_binary_expr(buf: &mut Vec<u8>, tag: u8, left: &ConstraintExpr, right: &ConstraintExpr) {
    buf.push(tag);
    encode_constraint_expr(buf, left);
    encode_constraint_expr(buf, right);
}

fn hash_observable(hasher: &mut Sha3_256, observable: &vsel_core::observable::Observable) {
    hasher.update(&[observable.transition_class as u8]);
    hasher.update(&[match observable.status {
        vsel_core::observable::TransitionStatus::Success => 0,
        vsel_core::observable::TransitionStatus::Rejected => 1,
        vsel_core::observable::TransitionStatus::Error => 2,
    }]);
    hasher.update(&observable.gas_used.to_le_bytes());
    hasher.update(&(observable.outputs.len() as u64).to_le_bytes());
    for output in &observable.outputs {
        hasher.update(&(output.event_type.len() as u64).to_le_bytes());
        hasher.update(output.event_type.as_bytes());
        hasher.update(&(output.data.len() as u64).to_le_bytes());
        hasher.update(&output.data);
    }
}

impl<B: ZkBackend> Prover for GenericProver<B> {
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
    fn prove(&self, trace: &Trace, constraints: &ConstraintSystem) -> Result<Proof, ProverError> {
        let PreparedProofStatement {
            public_inputs,
            commitments,
            ..
        } = prepare_proof_statement(trace, constraints)?;

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

impl<B: ZkBackend> Prover for BackendProver<B> {
    /// Generate a backend-native proof that `trace` satisfies `constraints`.
    ///
    /// The returned proof metadata is bound to the concrete backend id and the
    /// proof bytes are the backend serialization. No hash-placeholder proof
    /// data is generated on this path.
    fn prove(&self, trace: &Trace, constraints: &ConstraintSystem) -> Result<Proof, ProverError> {
        let PreparedProofStatement {
            witness,
            public_inputs,
            commitments,
        } = prepare_proof_statement(trace, constraints)?;

        let backend_proof = self
            .backend
            .prove(&witness, constraints, &public_inputs)
            .map_err(|e| ProverError::ProofGenerationFailed(e.to_string()))?;
        let proof_data = self.backend.serialize_proof(&backend_proof);
        if proof_data.is_empty() {
            return Err(ProverError::ProofGenerationFailed(format!(
                "{} produced empty proof serialization",
                self.backend.backend_id()
            )));
        }

        let metadata = ProofMetadata {
            prover_version: self.version.clone(),
            timestamp: 0,
            domain: proof_tag(),
            proof_system: self.backend.backend_id().to_string(),
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
    use std::{collections::BTreeMap, error::Error, fmt};
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

    #[cfg(feature = "plonky3-backend")]
    fn plonky3_compatible_constraint_system() -> ConstraintSystem {
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
            description: "x = x".to_string(),
        });
        cs
    }

    fn default_prover() -> DefaultProver {
        DefaultProver::new("0.1.0-test")
    }

    #[derive(Clone)]
    struct MockBackendProof(Vec<u8>);

    impl AsRef<[u8]> for MockBackendProof {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug)]
    struct MockBackendError(String);

    impl fmt::Display for MockBackendError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl Error for MockBackendError {}

    struct MockBackend {
        proof_bytes: Vec<u8>,
        fail: bool,
    }

    impl MockBackend {
        fn new(proof_bytes: &[u8]) -> Self {
            Self {
                proof_bytes: proof_bytes.to_vec(),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                proof_bytes: Vec::new(),
                fail: true,
            }
        }
    }

    impl ZkBackend for MockBackend {
        type Proof = MockBackendProof;
        type Error = MockBackendError;

        fn prove(
            &self,
            _witness: &Witness,
            _constraints: &ConstraintSystem,
            _public_inputs: &PublicInputs,
        ) -> Result<Self::Proof, Self::Error> {
            if self.fail {
                Err(MockBackendError(
                    "mock-stark: synthetic backend failure".to_string(),
                ))
            } else {
                Ok(MockBackendProof(self.proof_bytes.clone()))
            }
        }

        fn verify(
            &self,
            proof: &Self::Proof,
            _public_inputs: &PublicInputs,
            _constraint_commitment: &Hash,
        ) -> bool {
            proof.as_ref() == self.proof_bytes.as_slice()
        }

        fn backend_id(&self) -> &str {
            "mock-stark"
        }

        fn is_post_quantum(&self) -> bool {
            true
        }

        fn serialize_proof(&self, proof: &Self::Proof) -> Vec<u8> {
            proof.0.clone()
        }

        fn deserialize_proof(&self, data: &[u8]) -> Result<Self::Proof, Self::Error> {
            Ok(MockBackendProof(data.to_vec()))
        }
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
            proof.commitments.trace_commitment, proof2.commitments.trace_commitment,
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
        assert_ne!(
            proof.metadata.domain,
            vsel_crypto::domain::trace_commitment_tag()
        );
        assert_ne!(
            proof.metadata.domain,
            vsel_crypto::domain::state_commitment_tag()
        );
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
            proof.commitments.witness_commitment, proof2.commitments.witness_commitment,
            "PROOF-4: different traces must produce different witness commitments"
        );
    }

    // -----------------------------------------------------------------------
    // Commitment determinism
    // -----------------------------------------------------------------------

    #[test]
    fn test_witness_commitment_deterministic() {
        let trace = test_trace(2);
        let witness = construct_witness(&trace);

        let c1 = canonical_witness_commitment(&witness);
        let c2 = canonical_witness_commitment(&witness);
        assert_eq!(c1, c2, "witness commitment must be deterministic");
    }

    #[test]
    fn test_constraint_commitment_deterministic() {
        let cs = test_constraint_system();

        let c1 = canonical_constraint_commitment(&cs);
        let c2 = canonical_constraint_commitment(&cs);
        assert_eq!(c1, c2, "constraint commitment must be deterministic");
    }

    #[test]
    fn test_different_constraints_different_commitment() {
        let cs1 = test_constraint_system();
        let mut cs2 = test_constraint_system();
        cs2.add_constraint(Constraint {
            id: ConstraintId(99),
            expr: ConstraintExpr::BoolConstant(false),
            category: ConstraintCategory::Semantic,
            description: "extra constraint".to_string(),
        });

        let c1 = canonical_constraint_commitment(&cs1);
        let c2 = canonical_constraint_commitment(&cs2);
        assert_ne!(
            c1, c2,
            "different constraint systems must produce different commitments"
        );
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

    #[test]
    fn test_backend_prover_delegates_to_concrete_backend() {
        let backend_bytes = b"native-stark-proof-bytes";
        let prover = BackendProver::new("0.1.0-test", MockBackend::new(backend_bytes));
        let trace = test_trace(2);
        let cs = test_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("backend proof");

        assert_eq!(proof.metadata.proof_system, "mock-stark");
        assert_eq!(proof.proof_data, backend_bytes);
        assert_eq!(
            proof.commitments.constraint_commitment,
            canonical_constraint_commitment(&cs)
        );
        assert!(
            proof.public_inputs.matches_trace(&trace),
            "backend prover must preserve trace/public input binding"
        );
    }

    #[test]
    fn test_backend_prover_propagates_backend_failure() {
        let prover = BackendProver::new("0.1.0-test", MockBackend::failing());
        let trace = test_trace(1);
        let cs = test_constraint_system();

        let err = prover
            .prove(&trace, &cs)
            .expect_err("backend failure must abort proving");

        match err {
            ProverError::ProofGenerationFailed(message) => {
                assert!(message.contains("mock-stark"));
            }
            other => panic!("expected ProofGenerationFailed, got: {:?}", other),
        }
    }

    #[cfg(feature = "plonky3-backend")]
    #[test]
    fn test_backend_prover_plonky3_round_trip_uses_canonical_commitment() {
        let prover =
            BackendProver::new("0.1.0-test", crate::plonky3_backend::Plonky3Backend::new());
        let trace = test_trace(1);
        let cs = plonky3_compatible_constraint_system();

        let proof = prover.prove(&trace, &cs).expect("plonky3 backend proof");

        assert_eq!(proof.metadata.proof_system, "plonky3-stark");
        assert_eq!(
            proof.commitments.constraint_commitment,
            canonical_constraint_commitment(&cs)
        );

        let verifier = crate::verifier::BackendCryptographicVerifier::new(
            test_version(),
            crate::plonky3_backend::Plonky3Backend::new(),
        );
        let result = crate::verifier::CryptographicVerifier::verify_cryptographic(
            &verifier,
            &proof,
            &proof.public_inputs,
        );

        assert!(
            result.is_consistent(),
            "backend-generated Plonky3 proof must verify with canonical commitment: {:?}",
            result
        );
    }
}
