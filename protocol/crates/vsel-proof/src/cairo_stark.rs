//! Cairo/STARK backend adapter.
//!
//! This module deliberately does not treat a Cairo envelope as proof validity.
//! A Cairo artifact is accepted only when a concrete adapter verifies the
//! underlying Cairo/STARK proof and returns a certificate bound to the exact
//! verifier version/hash, Cairo source hash, Sierra hash, CASM hash,
//! executable program hash, semantic binding hash, Cairo trace hash, public
//! input hash, constraint commitment, VSEL statement hash, proof hash, and
//! verifier transcript hash.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use sha3::{Digest, Sha3_256};
use thiserror::Error;

use vsel_constraints::ConstraintSystem;
use vsel_core::observable::TransitionStatus;
use vsel_core::transition::TransitionClass;
use vsel_core::types::Hash;

use crate::backend::ZkBackend;
use crate::prover::{canonical_constraint_commitment, canonical_witness_commitment};
use crate::public_inputs::PublicInputs;
use crate::witness::Witness;

const CAIRO_PROOF_MAGIC: [u8; 4] = *b"VCAI";
const CAIRO_PROOF_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum CairoStarkError {
    #[error("cairo-stark: proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("cairo-stark: verification failed: {0}")]
    VerificationFailed(String),
    #[error("cairo-stark: deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("cairo-stark: command adapter failed: {0}")]
    CommandFailed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoProgramCommitments {
    pub cairo_program_hash: Hash,
    pub sierra_program_hash: Hash,
    pub casm_program_hash: Hash,
    pub executable_program_hash: Hash,
    pub semantic_binding_hash: Hash,
}

impl CairoProgramCommitments {
    pub fn new(
        cairo_program_hash: Hash,
        sierra_program_hash: Hash,
        casm_program_hash: Hash,
        executable_program_hash: Hash,
        semantic_binding_hash: Hash,
    ) -> Self {
        Self {
            cairo_program_hash,
            sierra_program_hash,
            casm_program_hash,
            executable_program_hash,
            semantic_binding_hash,
        }
    }

    fn validate_nonzero(&self) -> Result<(), CairoStarkError> {
        for (name, hash) in [
            ("cairo_program_hash", &self.cairo_program_hash),
            ("sierra_program_hash", &self.sierra_program_hash),
            ("casm_program_hash", &self.casm_program_hash),
            ("executable_program_hash", &self.executable_program_hash),
            ("semantic_binding_hash", &self.semantic_binding_hash),
        ] {
            if hash.0 == [0u8; 32] {
                return Err(CairoStarkError::VerificationFailed(format!(
                    "{} must be non-zero",
                    name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoExpectedStatement {
    pub backend_id: String,
    pub program: CairoProgramCommitments,
    pub public_input_hash: Hash,
    pub constraint_commitment: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoStatement {
    pub backend_id: String,
    pub program: CairoProgramCommitments,
    pub cairo_trace_hash: Hash,
    pub public_input_hash: Hash,
    pub constraint_commitment: Hash,
}

impl CairoStatement {
    pub fn from_expected(expected: &CairoExpectedStatement, cairo_trace_hash: Hash) -> Self {
        Self {
            backend_id: expected.backend_id.clone(),
            program: expected.program.clone(),
            cairo_trace_hash,
            public_input_hash: expected.public_input_hash.clone(),
            constraint_commitment: expected.constraint_commitment.clone(),
        }
    }

    pub fn hash(&self) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(b"vsel-cairo-statement-v1");
        update_string(&mut hasher, &self.backend_id);
        update_hash(&mut hasher, &self.program.cairo_program_hash);
        update_hash(&mut hasher, &self.program.sierra_program_hash);
        update_hash(&mut hasher, &self.program.casm_program_hash);
        update_hash(&mut hasher, &self.program.executable_program_hash);
        update_hash(&mut hasher, &self.program.semantic_binding_hash);
        update_hash(&mut hasher, &self.cairo_trace_hash);
        update_hash(&mut hasher, &self.public_input_hash);
        update_hash(&mut hasher, &self.constraint_commitment);
        finalize_hash(hasher)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoVerifierCertificate {
    pub adapter_id: String,
    pub verifier_version: String,
    pub verifier_binary_hash: Hash,
    pub backend_id: String,
    pub program: CairoProgramCommitments,
    pub cairo_trace_hash: Hash,
    pub public_input_hash: Hash,
    pub constraint_commitment: Hash,
    pub statement_hash: Hash,
    pub proof_hash: Hash,
    pub transcript_hash: Hash,
    pub accepted: bool,
}

impl CairoVerifierCertificate {
    pub fn validate_for_statement(
        &self,
        statement: &CairoStatement,
        statement_hash: &Hash,
        proof_hash: &Hash,
    ) -> bool {
        self.accepted
            && valid_certificate_string(&self.adapter_id)
            && valid_certificate_string(&self.verifier_version)
            && self.verifier_binary_hash.0 != [0u8; 32]
            && self.backend_id == statement.backend_id
            && self.program == statement.program
            && self.cairo_trace_hash == statement.cairo_trace_hash
            && self.public_input_hash == statement.public_input_hash
            && self.constraint_commitment == statement.constraint_commitment
            && &self.statement_hash == statement_hash
            && &self.proof_hash == proof_hash
            && self.transcript_hash.0 != [0u8; 32]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CairoStarkProof {
    pub backend_id: String,
    pub program: CairoProgramCommitments,
    pub cairo_trace_hash: Hash,
    pub public_input_hash: Hash,
    pub constraint_commitment: Hash,
    pub statement_hash: Hash,
    pub proof_hash: Hash,
    pub proof_bytes: Vec<u8>,
    pub verifier_certificate: CairoVerifierCertificate,
    pub serialized: Vec<u8>,
}

impl CairoStarkProof {
    pub fn new(
        backend_id: String,
        program: CairoProgramCommitments,
        cairo_trace_hash: Hash,
        public_input_hash: Hash,
        constraint_commitment: Hash,
        proof_bytes: Vec<u8>,
        verifier_certificate: CairoVerifierCertificate,
    ) -> Result<Self, CairoStarkError> {
        let statement = CairoStatement {
            backend_id: backend_id.clone(),
            program: program.clone(),
            cairo_trace_hash: cairo_trace_hash.clone(),
            public_input_hash: public_input_hash.clone(),
            constraint_commitment: constraint_commitment.clone(),
        };
        let statement_hash = statement.hash();
        let proof_hash = hash_domain_bytes(b"vsel-cairo-proof-bytes-v1", &proof_bytes);
        let mut proof = Self {
            backend_id,
            program,
            cairo_trace_hash,
            public_input_hash,
            constraint_commitment,
            statement_hash,
            proof_hash,
            proof_bytes,
            verifier_certificate,
            serialized: Vec::new(),
        };
        proof.validate_static()?;
        proof.serialized = proof.to_bytes();
        Ok(proof)
    }

    pub fn validate_against(
        &self,
        expected: &CairoExpectedStatement,
    ) -> Result<(), CairoStarkError> {
        self.validate_static()?;

        if self.backend_id != expected.backend_id {
            return Err(CairoStarkError::VerificationFailed(format!(
                "backend id mismatch: artifact={}, expected={}",
                self.backend_id, expected.backend_id
            )));
        }
        if self.program != expected.program {
            return Err(CairoStarkError::VerificationFailed(
                "program commitment mismatch".to_string(),
            ));
        }
        if self.public_input_hash != expected.public_input_hash {
            return Err(CairoStarkError::VerificationFailed(
                "public input hash mismatch".to_string(),
            ));
        }
        if self.constraint_commitment != expected.constraint_commitment {
            return Err(CairoStarkError::VerificationFailed(
                "constraint commitment mismatch".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_static(&self) -> Result<(), CairoStarkError> {
        if !self.backend_id.starts_with("cairo-stark/") {
            return Err(CairoStarkError::VerificationFailed(format!(
                "Cairo backend id '{}' must be concrete cairo-stark/<adapter>",
                self.backend_id
            )));
        }
        self.program.validate_nonzero()?;
        for (name, hash) in [
            ("cairo_trace_hash", &self.cairo_trace_hash),
            ("public_input_hash", &self.public_input_hash),
            ("constraint_commitment", &self.constraint_commitment),
            ("statement_hash", &self.statement_hash),
            ("proof_hash", &self.proof_hash),
        ] {
            if hash.0 == [0u8; 32] {
                return Err(CairoStarkError::VerificationFailed(format!(
                    "{} must be non-zero",
                    name
                )));
            }
        }
        if self.proof_bytes.is_empty() {
            return Err(CairoStarkError::VerificationFailed(
                "Cairo proof bytes must be non-empty".to_string(),
            ));
        }

        let statement = CairoStatement {
            backend_id: self.backend_id.clone(),
            program: self.program.clone(),
            cairo_trace_hash: self.cairo_trace_hash.clone(),
            public_input_hash: self.public_input_hash.clone(),
            constraint_commitment: self.constraint_commitment.clone(),
        };
        let expected_statement_hash = statement.hash();
        if self.statement_hash != expected_statement_hash {
            return Err(CairoStarkError::VerificationFailed(
                "statement hash does not match artifact fields".to_string(),
            ));
        }

        let expected_proof_hash =
            hash_domain_bytes(b"vsel-cairo-proof-bytes-v1", &self.proof_bytes);
        if self.proof_hash != expected_proof_hash {
            return Err(CairoStarkError::VerificationFailed(
                "proof hash does not match proof bytes".to_string(),
            ));
        }

        if !self.verifier_certificate.validate_for_statement(
            &statement,
            &self.statement_hash,
            &self.proof_hash,
        ) {
            return Err(CairoStarkError::VerificationFailed(
                "verifier certificate is not bound to all artifact fields".to_string(),
            ));
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CAIRO_PROOF_MAGIC);
        buf.push(CAIRO_PROOF_VERSION);
        write_string(&mut buf, &self.backend_id);
        write_hash(&mut buf, &self.program.cairo_program_hash);
        write_hash(&mut buf, &self.program.sierra_program_hash);
        write_hash(&mut buf, &self.program.casm_program_hash);
        write_hash(&mut buf, &self.program.executable_program_hash);
        write_hash(&mut buf, &self.program.semantic_binding_hash);
        write_hash(&mut buf, &self.cairo_trace_hash);
        write_hash(&mut buf, &self.public_input_hash);
        write_hash(&mut buf, &self.constraint_commitment);
        write_hash(&mut buf, &self.statement_hash);
        write_hash(&mut buf, &self.proof_hash);
        write_bytes(&mut buf, &self.proof_bytes);
        write_string(&mut buf, &self.verifier_certificate.adapter_id);
        write_string(&mut buf, &self.verifier_certificate.verifier_version);
        write_hash(&mut buf, &self.verifier_certificate.verifier_binary_hash);
        write_string(&mut buf, &self.verifier_certificate.backend_id);
        write_hash(
            &mut buf,
            &self.verifier_certificate.program.cairo_program_hash,
        );
        write_hash(
            &mut buf,
            &self.verifier_certificate.program.sierra_program_hash,
        );
        write_hash(
            &mut buf,
            &self.verifier_certificate.program.casm_program_hash,
        );
        write_hash(
            &mut buf,
            &self.verifier_certificate.program.executable_program_hash,
        );
        write_hash(
            &mut buf,
            &self.verifier_certificate.program.semantic_binding_hash,
        );
        write_hash(&mut buf, &self.verifier_certificate.cairo_trace_hash);
        write_hash(&mut buf, &self.verifier_certificate.public_input_hash);
        write_hash(&mut buf, &self.verifier_certificate.constraint_commitment);
        write_hash(&mut buf, &self.verifier_certificate.statement_hash);
        write_hash(&mut buf, &self.verifier_certificate.proof_hash);
        write_hash(&mut buf, &self.verifier_certificate.transcript_hash);
        buf.push(u8::from(self.verifier_certificate.accepted));
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CairoStarkError> {
        let mut cursor = 0usize;
        let magic = read_exact(bytes, &mut cursor, 4)?;
        if magic != CAIRO_PROOF_MAGIC {
            return Err(CairoStarkError::DeserializationFailed(
                "invalid magic bytes: expected VCAI".to_string(),
            ));
        }
        let version = read_exact(bytes, &mut cursor, 1)?[0];
        if version != CAIRO_PROOF_VERSION {
            return Err(CairoStarkError::DeserializationFailed(format!(
                "unsupported Cairo proof version: {}",
                version
            )));
        }

        let backend_id = read_string(bytes, &mut cursor)?;
        let program = CairoProgramCommitments {
            cairo_program_hash: read_hash(bytes, &mut cursor)?,
            sierra_program_hash: read_hash(bytes, &mut cursor)?,
            casm_program_hash: read_hash(bytes, &mut cursor)?,
            executable_program_hash: read_hash(bytes, &mut cursor)?,
            semantic_binding_hash: read_hash(bytes, &mut cursor)?,
        };
        let cairo_trace_hash = read_hash(bytes, &mut cursor)?;
        let public_input_hash = read_hash(bytes, &mut cursor)?;
        let constraint_commitment = read_hash(bytes, &mut cursor)?;
        let statement_hash = read_hash(bytes, &mut cursor)?;
        let proof_hash = read_hash(bytes, &mut cursor)?;
        let proof_bytes = read_bytes(bytes, &mut cursor)?;
        let verifier_certificate = CairoVerifierCertificate {
            adapter_id: read_string(bytes, &mut cursor)?,
            verifier_version: read_string(bytes, &mut cursor)?,
            verifier_binary_hash: read_hash(bytes, &mut cursor)?,
            backend_id: read_string(bytes, &mut cursor)?,
            program: CairoProgramCommitments {
                cairo_program_hash: read_hash(bytes, &mut cursor)?,
                sierra_program_hash: read_hash(bytes, &mut cursor)?,
                casm_program_hash: read_hash(bytes, &mut cursor)?,
                executable_program_hash: read_hash(bytes, &mut cursor)?,
                semantic_binding_hash: read_hash(bytes, &mut cursor)?,
            },
            cairo_trace_hash: read_hash(bytes, &mut cursor)?,
            public_input_hash: read_hash(bytes, &mut cursor)?,
            constraint_commitment: read_hash(bytes, &mut cursor)?,
            statement_hash: read_hash(bytes, &mut cursor)?,
            proof_hash: read_hash(bytes, &mut cursor)?,
            transcript_hash: read_hash(bytes, &mut cursor)?,
            accepted: read_exact(bytes, &mut cursor, 1)?[0] == 1,
        };

        if cursor != bytes.len() {
            return Err(CairoStarkError::DeserializationFailed(
                "trailing bytes after Cairo proof decode".to_string(),
            ));
        }

        let proof = Self {
            backend_id,
            program,
            cairo_trace_hash,
            public_input_hash,
            constraint_commitment,
            statement_hash,
            proof_hash,
            proof_bytes,
            verifier_certificate,
            serialized: bytes.to_vec(),
        };
        proof.validate_static()?;
        if proof.to_bytes() != bytes {
            return Err(CairoStarkError::DeserializationFailed(
                "non-canonical Cairo proof serialization".to_string(),
            ));
        }
        Ok(proof)
    }
}

impl AsRef<[u8]> for CairoStarkProof {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

pub struct CairoProveRequest {
    pub expected: CairoExpectedStatement,
    pub witness_commitment: Hash,
    pub constraint_system_commitment: Hash,
}

pub struct CairoVerifyRequest {
    pub expected: CairoExpectedStatement,
    pub proof: CairoStarkProof,
}

pub trait CairoProofAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn prove(&self, request: &CairoProveRequest) -> Result<CairoStarkProof, CairoStarkError>;
    fn verify(
        &self,
        request: &CairoVerifyRequest,
    ) -> Result<CairoVerifierCertificate, CairoStarkError>;
}

pub struct CairoStarkBackend<A: CairoProofAdapter> {
    backend_id: String,
    program: CairoProgramCommitments,
    adapter: A,
}

impl<A: CairoProofAdapter> CairoStarkBackend<A> {
    pub fn new(program: CairoProgramCommitments, adapter: A) -> Self {
        Self {
            backend_id: format!("cairo-stark/{}", adapter.adapter_id()),
            program,
            adapter,
        }
    }

    fn expected_statement(
        &self,
        public_inputs: &PublicInputs,
        constraint_commitment: Hash,
    ) -> CairoExpectedStatement {
        CairoExpectedStatement {
            backend_id: self.backend_id.clone(),
            program: self.program.clone(),
            public_input_hash: public_inputs_commitment(public_inputs),
            constraint_commitment,
        }
    }
}

impl<A: CairoProofAdapter> ZkBackend for CairoStarkBackend<A> {
    type Proof = CairoStarkProof;
    type Error = CairoStarkError;

    fn prove(
        &self,
        witness: &Witness,
        constraints: &ConstraintSystem,
        public_inputs: &PublicInputs,
    ) -> Result<Self::Proof, Self::Error> {
        let constraint_commitment = canonical_constraint_commitment(constraints);
        let request = CairoProveRequest {
            expected: self.expected_statement(public_inputs, constraint_commitment.clone()),
            witness_commitment: canonical_witness_commitment(witness),
            constraint_system_commitment: constraint_commitment,
        };
        let proof = self.adapter.prove(&request)?;
        proof.validate_against(&request.expected)?;
        Ok(proof)
    }

    fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &PublicInputs,
        constraint_commitment: &Hash,
    ) -> bool {
        let expected = self.expected_statement(public_inputs, constraint_commitment.clone());
        if proof.validate_against(&expected).is_err() {
            return false;
        }

        let request = CairoVerifyRequest {
            expected,
            proof: proof.clone(),
        };
        let certificate = match self.adapter.verify(&request) {
            Ok(certificate) => certificate,
            Err(_) => return false,
        };

        let statement = CairoStatement {
            backend_id: proof.backend_id.clone(),
            program: proof.program.clone(),
            cairo_trace_hash: proof.cairo_trace_hash.clone(),
            public_input_hash: proof.public_input_hash.clone(),
            constraint_commitment: proof.constraint_commitment.clone(),
        };

        certificate == proof.verifier_certificate
            && certificate.validate_for_statement(
                &statement,
                &proof.statement_hash,
                &proof.proof_hash,
            )
    }

    fn backend_id(&self) -> &str {
        &self.backend_id
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn serialize_proof(&self, proof: &Self::Proof) -> Vec<u8> {
        proof.to_bytes()
    }

    fn deserialize_proof(&self, bytes: &[u8]) -> Result<Self::Proof, Self::Error> {
        CairoStarkProof::from_bytes(bytes)
    }
}

pub struct CommandCairoAdapter {
    adapter_id: String,
    prover_command: Option<PathBuf>,
    verifier_command: PathBuf,
}

impl CommandCairoAdapter {
    pub fn new(
        adapter_id: impl Into<String>,
        prover_command: Option<PathBuf>,
        verifier_command: PathBuf,
    ) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            prover_command,
            verifier_command,
        }
    }

    fn run_command(&self, command: &PathBuf, stdin: &str) -> Result<String, CairoStarkError> {
        let mut child = Command::new(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CairoStarkError::CommandFailed(e.to_string()))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| CairoStarkError::CommandFailed("stdin pipe unavailable".to_string()))?
            .write_all(stdin.as_bytes())
            .map_err(|e| CairoStarkError::CommandFailed(e.to_string()))?;

        let output = child
            .wait_with_output()
            .map_err(|e| CairoStarkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(CairoStarkError::CommandFailed(format!(
                "command exited with {}; stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        String::from_utf8(output.stdout).map_err(|e| CairoStarkError::CommandFailed(e.to_string()))
    }
}

impl CairoProofAdapter for CommandCairoAdapter {
    fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    fn prove(&self, request: &CairoProveRequest) -> Result<CairoStarkProof, CairoStarkError> {
        let command = self.prover_command.as_ref().ok_or_else(|| {
            CairoStarkError::ProofGenerationFailed(
                "no Cairo prover command configured for CommandCairoAdapter".to_string(),
            )
        })?;
        let stdout = self.run_command(command, &format_prove_request(request))?;
        let proof_hex = parse_field(&stdout, "proof_hex=")?;
        let proof_bytes = hex_decode(proof_hex)?;
        CairoStarkProof::from_bytes(&proof_bytes)
    }

    fn verify(
        &self,
        request: &CairoVerifyRequest,
    ) -> Result<CairoVerifierCertificate, CairoStarkError> {
        let stdout = self.run_command(&self.verifier_command, &format_verify_request(request))?;
        parse_certificate(&stdout)
    }
}

pub fn public_inputs_commitment(public_inputs: &PublicInputs) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"vsel-cairo-public-inputs-v1");
    update_hash(&mut hasher, &public_inputs.root_init);
    update_hash(&mut hasher, &public_inputs.root_final);
    update_hash(&mut hasher, &(public_inputs.domain.0));
    update_u32(&mut hasher, public_inputs.version.major);
    update_u32(&mut hasher, public_inputs.version.minor);
    update_u32(&mut hasher, public_inputs.version.patch);
    hasher.update(&(public_inputs.observables.len() as u64).to_le_bytes());
    for observable in &public_inputs.observables {
        hasher.update(&[transition_class_tag(observable.transition_class)]);
        hasher.update(&[match observable.status {
            TransitionStatus::Success => 0,
            TransitionStatus::Rejected => 1,
            TransitionStatus::Error => 2,
        }]);
        hasher.update(&observable.gas_used.to_le_bytes());
        hasher.update(&(observable.outputs.len() as u64).to_le_bytes());
        for output in &observable.outputs {
            update_string(&mut hasher, &output.event_type);
            hasher.update(&(output.data.len() as u64).to_le_bytes());
            hasher.update(&output.data);
        }
    }
    finalize_hash(hasher)
}

fn transition_class_tag(class: TransitionClass) -> u8 {
    match class {
        TransitionClass::Reject => 0,
        TransitionClass::Init => 1,
        TransitionClass::Error => 2,
        TransitionClass::Batch => 3,
        TransitionClass::Update => 4,
        TransitionClass::Noop => 5,
    }
}

fn format_prove_request(request: &CairoProveRequest) -> String {
    let mut out = format_expected("VSEL_CAIRO_PROVE_REQUEST_V1", &request.expected);
    out.push_str(&format!(
        "witness_commitment={}\nconstraint_system_commitment={}\nEND\n",
        hex_hash(&request.witness_commitment),
        hex_hash(&request.constraint_system_commitment)
    ));
    out
}

fn format_verify_request(request: &CairoVerifyRequest) -> String {
    let mut out = format_expected("VSEL_CAIRO_VERIFY_REQUEST_V1", &request.expected);
    out.push_str(&format!(
        "statement_hash={}\nproof_hash={}\nproof_hex={}\nEND\n",
        hex_hash(&request.proof.statement_hash),
        hex_hash(&request.proof.proof_hash),
        hex_encode(&request.proof.to_bytes())
    ));
    out
}

fn format_expected(header: &str, expected: &CairoExpectedStatement) -> String {
    format!(
        "{}\nbackend_id={}\ncairo_program_hash={}\nsierra_program_hash={}\ncasm_program_hash={}\nexecutable_program_hash={}\nsemantic_binding_hash={}\npublic_input_hash={}\nconstraint_commitment={}\n",
        header,
        expected.backend_id,
        hex_hash(&expected.program.cairo_program_hash),
        hex_hash(&expected.program.sierra_program_hash),
        hex_hash(&expected.program.casm_program_hash),
        hex_hash(&expected.program.executable_program_hash),
        hex_hash(&expected.program.semantic_binding_hash),
        hex_hash(&expected.public_input_hash),
        hex_hash(&expected.constraint_commitment)
    )
}

fn parse_certificate(text: &str) -> Result<CairoVerifierCertificate, CairoStarkError> {
    if !text
        .lines()
        .any(|line| line == "VSEL_CAIRO_VERIFIER_CERTIFICATE_V1")
    {
        return Err(CairoStarkError::VerificationFailed(
            "missing Cairo verifier certificate header".to_string(),
        ));
    }
    Ok(CairoVerifierCertificate {
        adapter_id: parse_field(text, "adapter_id=")?.to_string(),
        verifier_version: parse_field(text, "verifier_version=")?.to_string(),
        verifier_binary_hash: parse_hash_field(text, "verifier_binary_hash=")?,
        backend_id: parse_field(text, "backend_id=")?.to_string(),
        program: CairoProgramCommitments {
            cairo_program_hash: parse_hash_field(text, "cairo_program_hash=")?,
            sierra_program_hash: parse_hash_field(text, "sierra_program_hash=")?,
            casm_program_hash: parse_hash_field(text, "casm_program_hash=")?,
            executable_program_hash: parse_hash_field(text, "executable_program_hash=")?,
            semantic_binding_hash: parse_hash_field(text, "semantic_binding_hash=")?,
        },
        cairo_trace_hash: parse_hash_field(text, "cairo_trace_hash=")?,
        public_input_hash: parse_hash_field(text, "public_input_hash=")?,
        constraint_commitment: parse_hash_field(text, "constraint_commitment=")?,
        statement_hash: parse_hash_field(text, "statement_hash=")?,
        proof_hash: parse_hash_field(text, "proof_hash=")?,
        transcript_hash: parse_hash_field(text, "transcript_hash=")?,
        accepted: parse_bool_field(text, "accepted=")?,
    })
}

fn parse_bool_field(text: &str, key: &str) -> Result<bool, CairoStarkError> {
    match parse_field(text, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(CairoStarkError::VerificationFailed(format!(
            "field {} must be true or false, got {}",
            key, value
        ))),
    }
}

fn parse_field<'a>(text: &'a str, key: &str) -> Result<&'a str, CairoStarkError> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or_else(|| CairoStarkError::VerificationFailed(format!("missing field {}", key)))
}

fn parse_hash_field(text: &str, key: &str) -> Result<Hash, CairoStarkError> {
    let value = parse_field(text, key)?;
    let raw = hex_decode(value)?;
    if raw.len() != 32 {
        return Err(CairoStarkError::VerificationFailed(format!(
            "field {} must be 32 bytes",
            key
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(Hash(out))
}

fn valid_certificate_string(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'=')
}

fn update_hash(hasher: &mut Sha3_256, hash: &Hash) {
    hasher.update(&hash.0);
}

fn update_string(hasher: &mut Sha3_256, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn update_u32(hasher: &mut Sha3_256, value: u32) {
    hasher.update(&value.to_le_bytes());
}

fn finalize_hash(hasher: Sha3_256) -> Hash {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash(out)
}

fn hash_domain_bytes(domain: &[u8], data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    finalize_hash(hasher)
}

fn write_hash(buf: &mut Vec<u8>, hash: &Hash) {
    buf.extend_from_slice(&hash.0);
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    write_bytes(buf, value.as_bytes());
}

fn write_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

fn read_hash(bytes: &[u8], cursor: &mut usize) -> Result<Hash, CairoStarkError> {
    let raw = read_exact(bytes, cursor, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(Hash(out))
}

fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, CairoStarkError> {
    let raw = read_bytes(bytes, cursor)?;
    if raw.is_empty() {
        return Err(CairoStarkError::DeserializationFailed(
            "empty string field".to_string(),
        ));
    }
    String::from_utf8(raw)
        .map_err(|e| CairoStarkError::DeserializationFailed(format!("invalid UTF-8: {}", e)))
}

fn read_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, CairoStarkError> {
    let len_raw = read_exact(bytes, cursor, 4)?;
    let len = u32::from_le_bytes([len_raw[0], len_raw[1], len_raw[2], len_raw[3]]) as usize;
    Ok(read_exact(bytes, cursor, len)?.to_vec())
}

fn read_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], CairoStarkError> {
    if *cursor + len > bytes.len() {
        return Err(CairoStarkError::DeserializationFailed(format!(
            "truncated Cairo proof at byte {}; need {}, have {}",
            *cursor,
            len,
            bytes.len().saturating_sub(*cursor)
        )));
    }
    let out = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Ok(out)
}

fn hex_hash(hash: &Hash) -> String {
    hex_encode(&hash.0)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, CairoStarkError> {
    if value.len() % 2 != 0 {
        return Err(CairoStarkError::DeserializationFailed(
            "hex string has odd length".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[i])?;
        let low = hex_nibble(bytes[i + 1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, CairoStarkError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CairoStarkError::DeserializationFailed(
            "invalid hex character".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_core::observable::Observable;
    use vsel_core::types::{DomainTag, OutputEvent, ProtocolVersion};

    #[derive(Clone)]
    struct DeterministicTestAdapter;

    impl DeterministicTestAdapter {
        fn make_certificate(
            &self,
            statement: &CairoStatement,
            statement_hash: &Hash,
            proof_hash: &Hash,
        ) -> CairoVerifierCertificate {
            let verifier_binary_hash = hash_domain_bytes(
                b"vsel-cairo-test-verifier-binary-v1",
                self.adapter_id().as_bytes(),
            );
            let mut hasher = Sha3_256::new();
            hasher.update(b"vsel-cairo-test-certificate-v1");
            update_string(&mut hasher, self.adapter_id());
            update_string(&mut hasher, "deterministic-test/1");
            update_hash(&mut hasher, &verifier_binary_hash);
            update_string(&mut hasher, &statement.backend_id);
            update_hash(&mut hasher, &statement.program.cairo_program_hash);
            update_hash(&mut hasher, &statement.program.sierra_program_hash);
            update_hash(&mut hasher, &statement.program.casm_program_hash);
            update_hash(&mut hasher, &statement.program.executable_program_hash);
            update_hash(&mut hasher, &statement.program.semantic_binding_hash);
            update_hash(&mut hasher, &statement.cairo_trace_hash);
            update_hash(&mut hasher, &statement.public_input_hash);
            update_hash(&mut hasher, &statement.constraint_commitment);
            update_hash(&mut hasher, statement_hash);
            update_hash(&mut hasher, proof_hash);
            CairoVerifierCertificate {
                adapter_id: self.adapter_id().to_string(),
                verifier_version: "deterministic-test/1".to_string(),
                verifier_binary_hash,
                backend_id: statement.backend_id.clone(),
                program: statement.program.clone(),
                cairo_trace_hash: statement.cairo_trace_hash.clone(),
                public_input_hash: statement.public_input_hash.clone(),
                constraint_commitment: statement.constraint_commitment.clone(),
                statement_hash: statement_hash.clone(),
                proof_hash: proof_hash.clone(),
                transcript_hash: finalize_hash(hasher),
                accepted: true,
            }
        }
    }

    impl CairoProofAdapter for DeterministicTestAdapter {
        fn adapter_id(&self) -> &str {
            "deterministic-test"
        }

        fn prove(&self, request: &CairoProveRequest) -> Result<CairoStarkProof, CairoStarkError> {
            let mut trace_hasher = Sha3_256::new();
            trace_hasher.update(b"vsel-cairo-test-trace-v1");
            update_hash(&mut trace_hasher, &request.expected.public_input_hash);
            update_hash(&mut trace_hasher, &request.expected.constraint_commitment);
            let cairo_trace_hash = finalize_hash(trace_hasher);

            let statement =
                CairoStatement::from_expected(&request.expected, cairo_trace_hash.clone());
            let statement_hash = statement.hash();
            let mut proof_hasher = Sha3_256::new();
            proof_hasher.update(b"vsel-cairo-test-proof-v1");
            update_hash(&mut proof_hasher, &statement_hash);
            update_hash(&mut proof_hasher, &request.witness_commitment);
            let proof_bytes = proof_hasher.finalize().to_vec();
            let proof_hash = hash_domain_bytes(b"vsel-cairo-proof-bytes-v1", &proof_bytes);
            let certificate = self.make_certificate(&statement, &statement_hash, &proof_hash);

            CairoStarkProof::new(
                request.expected.backend_id.clone(),
                request.expected.program.clone(),
                cairo_trace_hash,
                request.expected.public_input_hash.clone(),
                request.expected.constraint_commitment.clone(),
                proof_bytes,
                certificate,
            )
        }

        fn verify(
            &self,
            request: &CairoVerifyRequest,
        ) -> Result<CairoVerifierCertificate, CairoStarkError> {
            request.proof.validate_against(&request.expected)?;
            let statement = CairoStatement {
                backend_id: request.proof.backend_id.clone(),
                program: request.proof.program.clone(),
                cairo_trace_hash: request.proof.cairo_trace_hash.clone(),
                public_input_hash: request.proof.public_input_hash.clone(),
                constraint_commitment: request.proof.constraint_commitment.clone(),
            };
            Ok(self.make_certificate(
                &statement,
                &request.proof.statement_hash,
                &request.proof.proof_hash,
            ))
        }
    }

    fn hash(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    fn program() -> CairoProgramCommitments {
        CairoProgramCommitments::new(hash(1), hash(2), hash(3), hash(4), hash(5))
    }

    fn public_inputs() -> PublicInputs {
        PublicInputs {
            root_init: hash(4),
            root_final: hash(5),
            observables: vec![Observable {
                transition_class: TransitionClass::Update,
                outputs: vec![OutputEvent {
                    event_type: "balance_change".to_string(),
                    data: vec![7, 8, 9],
                }],
                gas_used: 21_000,
                status: TransitionStatus::Success,
            }],
            domain: DomainTag(hash(6)),
            version: ProtocolVersion::default(),
        }
    }

    #[test]
    fn cairo_backend_round_trip_accepts_adapter_verified_artifact() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let public_inputs = public_inputs();

        let proof = backend
            .prove(&witness, &constraints, &public_inputs)
            .expect("adapter-backed proof");
        let commitment = canonical_constraint_commitment(&constraints);

        assert_eq!(backend.backend_id(), "cairo-stark/deterministic-test");
        assert!(backend.verify(&proof, &public_inputs, &commitment));
    }

    #[test]
    fn cairo_proof_serialization_is_canonical() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let proof = backend
            .prove(&witness, &constraints, &public_inputs())
            .expect("proof");

        let encoded = backend.serialize_proof(&proof);
        let decoded = backend.deserialize_proof(&encoded).expect("decode");
        assert_eq!(proof, decoded);
        assert_eq!(decoded.as_ref(), encoded.as_slice());
    }

    #[test]
    fn cairo_backend_rejects_wrong_public_inputs() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let public_inputs = public_inputs();
        let proof = backend
            .prove(&witness, &constraints, &public_inputs)
            .expect("proof");

        let mut mutated = public_inputs.clone();
        mutated.observables[0].gas_used += 1;
        let commitment = canonical_constraint_commitment(&constraints);

        assert!(!backend.verify(&proof, &mutated, &commitment));
    }

    #[test]
    fn cairo_backend_rejects_wrong_constraint_commitment() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let proof = backend
            .prove(&witness, &constraints, &public_inputs())
            .expect("proof");

        assert!(!backend.verify(&proof, &public_inputs(), &hash(99)));
    }

    #[test]
    fn cairo_certificate_must_bind_all_explicit_artifact_fields() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let proof = backend
            .prove(&witness, &constraints, &public_inputs())
            .expect("proof");

        let mut wrong_program = proof.clone();
        wrong_program
            .verifier_certificate
            .program
            .cairo_program_hash = hash(0xaa);
        assert!(wrong_program.validate_static().is_err());

        let mut wrong_executable_program = proof.clone();
        wrong_executable_program
            .verifier_certificate
            .program
            .executable_program_hash = hash(0xab);
        assert!(wrong_executable_program.validate_static().is_err());

        let mut wrong_semantic_binding = proof.clone();
        wrong_semantic_binding
            .verifier_certificate
            .program
            .semantic_binding_hash = hash(0xac);
        assert!(wrong_semantic_binding.validate_static().is_err());

        let mut wrong_trace = proof.clone();
        wrong_trace.verifier_certificate.cairo_trace_hash = hash(0xbb);
        assert!(wrong_trace.validate_static().is_err());

        let mut wrong_public_input = proof.clone();
        wrong_public_input.verifier_certificate.public_input_hash = hash(0xcc);
        assert!(wrong_public_input.validate_static().is_err());

        let mut wrong_constraints = proof.clone();
        wrong_constraints.verifier_certificate.constraint_commitment = hash(0xdd);
        assert!(wrong_constraints.validate_static().is_err());

        let mut missing_verifier_hash = proof.clone();
        missing_verifier_hash
            .verifier_certificate
            .verifier_binary_hash = Hash([0u8; 32]);
        assert!(missing_verifier_hash.validate_static().is_err());
    }

    #[test]
    fn cairo_certificate_parser_requires_complete_v1_fields() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let proof = backend
            .prove(&witness, &constraints, &public_inputs())
            .expect("proof");
        let cert = &proof.verifier_certificate;
        let text = format!(
            "VSEL_CAIRO_VERIFIER_CERTIFICATE_V1\nadapter_id={}\nverifier_version={}\nverifier_binary_hash={}\nbackend_id={}\ncairo_program_hash={}\nsierra_program_hash={}\ncasm_program_hash={}\nexecutable_program_hash={}\nsemantic_binding_hash={}\ncairo_trace_hash={}\npublic_input_hash={}\nconstraint_commitment={}\nstatement_hash={}\nproof_hash={}\ntranscript_hash={}\naccepted=true\n",
            cert.adapter_id,
            cert.verifier_version,
            hex_hash(&cert.verifier_binary_hash),
            cert.backend_id,
            hex_hash(&cert.program.cairo_program_hash),
            hex_hash(&cert.program.sierra_program_hash),
            hex_hash(&cert.program.casm_program_hash),
            hex_hash(&cert.program.executable_program_hash),
            hex_hash(&cert.program.semantic_binding_hash),
            hex_hash(&cert.cairo_trace_hash),
            hex_hash(&cert.public_input_hash),
            hex_hash(&cert.constraint_commitment),
            hex_hash(&cert.statement_hash),
            hex_hash(&cert.proof_hash),
            hex_hash(&cert.transcript_hash),
        );
        assert_eq!(parse_certificate(&text).expect("certificate"), *cert);

        let missing_verifier_hash = text
            .lines()
            .filter(|line| !line.starts_with("verifier_binary_hash="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_certificate(&missing_verifier_hash).is_err());

        let invalid_accepted = text.replace("accepted=true", "accepted=yes");
        assert!(parse_certificate(&invalid_accepted).is_err());
    }

    #[test]
    fn cairo_deserializer_rejects_legacy_text_envelope() {
        let legacy = b"VSEL-CAIRO-STARK-V1\ncairo_program_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        assert!(CairoStarkProof::from_bytes(legacy).is_err());
    }

    #[test]
    fn cairo_static_validation_rejects_bare_backend_id() {
        let backend = CairoStarkBackend::new(program(), DeterministicTestAdapter);
        let constraints = ConstraintSystem::new("1.0.0");
        let witness = Witness {
            intermediate_states: Vec::new(),
            input_sequence: Vec::new(),
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let mut proof = backend
            .prove(&witness, &constraints, &public_inputs())
            .expect("proof");
        proof.backend_id = "cairo-stark".to_string();

        assert!(proof.validate_static().is_err());
    }
}

#[cfg(all(test, feature = "cairo-stark-backend"))]
mod cairo_stark_backend_e2e_tests {
    use super::*;
    use crate::cairo_native::{NativeCairoCommandConfig, PinnedNativeCairoAdapter};
    use crate::prover::{BackendProver, Proof, ProofCommitments, ProofMetadata, Prover};
    use crate::public_inputs::PublicInputs;
    use crate::verifier::{
        BackendCryptographicVerifier, CryptographicVerifier, Lean4SemanticVerifier,
        VerificationPipeline,
    };
    use crate::witness::construct_witness;

    use std::collections::BTreeMap;
    use std::env;
    use std::path::PathBuf;

    use vsel_constraints::{
        Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
    };
    use vsel_core::input::{Authorization, Input};
    use vsel_core::observable::obs;
    use vsel_core::state::{
        derive, derive_economic, AccountData, CanonicalState, Environment, State, TraceMetadata,
    };
    use vsel_core::transition::apply;
    use vsel_core::types::{
        AccountId, AuxiliaryData, DomainTag, Hash, HybridPublicKey, Payload, ProtocolVersion,
        SystemData,
    };
    use vsel_crypto::domain::proof_tag;
    use vsel_trace::engine::{Trace, TraceEngine};

    const NATIVE_TEST_ADAPTER_ID: &str = "native-command-e2e";
    const STONE_PREFIX: &str = "VSEL_STONE_CAIRO";
    const STWO_PREFIX: &str = "VSEL_STWO_CAIRO";
    const SCARB_PREFIX: &str = "VSEL_SCARB_CAIRO";
    const REQUIRED_NATIVE_SUFFIXES: [&str; 5] = [
        "VERSION",
        "PROVER",
        "PROVER_SHA3_256",
        "VERIFIER",
        "VERIFIER_SHA3_256",
    ];

    #[test]
    fn cairo_stark_backend_rejects_unconfigured_native_commands() {
        let trace = executable_trace();
        let constraints = covered_constraint_system();
        let witness = construct_witness(&trace);
        let public_inputs = PublicInputs::from_trace(&trace);
        let program = deterministic_program();
        let missing_command = env::temp_dir().join(format!(
            "vsel-missing-cairo-verifier-{}",
            std::process::id()
        ));

        let prover_backend = CairoStarkBackend::new(
            program.clone(),
            CommandCairoAdapter::new(NATIVE_TEST_ADAPTER_ID, None, missing_command.clone()),
        );
        let prover = BackendProver::new("cairo-native-e2e", prover_backend);
        let err = prover
            .prove(&trace, &constraints)
            .expect_err("unconfigured Cairo prover must fail closed");
        assert!(
            err.to_string()
                .contains("no Cairo prover command configured"),
            "unexpected proof-generation error: {}",
            err
        );

        let forged_proof = syntactically_valid_forged_cairo_proof(&trace, &constraints, &program);
        let verifier_backend = CairoStarkBackend::new(
            program.clone(),
            CommandCairoAdapter::new(NATIVE_TEST_ADAPTER_ID, None, missing_command.clone()),
        );
        let verifier =
            BackendCryptographicVerifier::new(ProtocolVersion::default(), verifier_backend);
        let crypto = verifier.verify_cryptographic(&forged_proof, &public_inputs);
        assert!(
            crypto.is_failed(),
            "self-contained VCAI certificate must not bypass native verifier: {:?}",
            crypto
        );

        let pipeline = VerificationPipeline::new(
            BackendCryptographicVerifier::new(
                ProtocolVersion::default(),
                CairoStarkBackend::new(
                    program,
                    CommandCairoAdapter::new(NATIVE_TEST_ADAPTER_ID, None, missing_command),
                ),
            ),
            Lean4SemanticVerifier::new(ProtocolVersion::default())
                .with_formal_spec_path(formal_spec_path())
                .with_timeout(120_000)
                .requiring_stark_proof_system(),
        );

        let result = pipeline.verify_strict_trace(
            &forged_proof,
            &public_inputs,
            &witness,
            &constraints,
            &trace,
        );
        assert!(
            result.is_rejected(),
            "strict final acceptance must fail closed without native Cairo verifier: {:?}",
            result
        );
        assert!(!result.is_fully_verified());
    }

    #[test]
    fn cairo_stark_backend_runs_native_command_e2e_when_configured() {
        let Some((program, prover_adapter, verifier_adapter)) = configured_native_e2e() else {
            eprintln!(
                "skipping positive Cairo/STARK E2E: no complete pinned \
                 VSEL_STONE_CAIRO_*, VSEL_STWO_CAIRO_*, or VSEL_SCARB_CAIRO_* adapter configuration"
            );
            return;
        };

        let trace = executable_trace();
        let constraints = covered_constraint_system();
        let witness = construct_witness(&trace);

        let prover_backend = CairoStarkBackend::new(program.clone(), prover_adapter);
        let proof = BackendProver::new("cairo-native-e2e", prover_backend)
            .prove(&trace, &constraints)
            .expect("native Cairo/STARK adapter must produce VCAI/v1 proof");

        let crypto_verifier = BackendCryptographicVerifier::new(
            ProtocolVersion::default(),
            CairoStarkBackend::new(program.clone(), verifier_adapter),
        );
        let crypto = crypto_verifier.verify_cryptographic(&proof, &proof.public_inputs);
        assert!(
            crypto.is_consistent(),
            "native Cairo/STARK cryptographic verification failed: {:?}",
            crypto
        );

        let pipeline = VerificationPipeline::new(
            BackendCryptographicVerifier::new(
                ProtocolVersion::default(),
                CairoStarkBackend::new(
                    program,
                    configured_native_adapter().expect("same pinned native adapter"),
                ),
            ),
            Lean4SemanticVerifier::new(ProtocolVersion::default())
                .with_formal_spec_path(formal_spec_path())
                .with_timeout(120_000)
                .requiring_stark_proof_system(),
        );

        let result = pipeline.verify_strict_trace(
            &proof,
            &proof.public_inputs,
            &witness,
            &constraints,
            &trace,
        );
        assert!(
            result.is_fully_verified(),
            "native Cairo/STARK proof did not reach strict final acceptance: {:?}",
            result
        );
    }

    fn configured_native_e2e() -> Option<(
        CairoProgramCommitments,
        PinnedNativeCairoAdapter,
        PinnedNativeCairoAdapter,
    )> {
        let adapter = configured_native_adapter()?;
        let verifier_adapter = configured_native_adapter().expect("deterministic env config");
        Some((program_from_env(), adapter, verifier_adapter))
    }

    fn configured_native_adapter() -> Option<PinnedNativeCairoAdapter> {
        let states = [
            (STONE_PREFIX, prefix_state(STONE_PREFIX)),
            (STWO_PREFIX, prefix_state(STWO_PREFIX)),
            (SCARB_PREFIX, prefix_state(SCARB_PREFIX)),
        ];

        for (_, state) in states {
            if let NativeEnvState::Partial(prefix) = state {
                panic!(
                    "partial native Cairo/STARK adapter configuration for {}; \
                     either set all required variables or none",
                    prefix
                );
            }
        }

        let complete = states
            .iter()
            .filter(|(_, state)| matches!(state, NativeEnvState::Complete))
            .map(|(prefix, _)| *prefix)
            .collect::<Vec<_>>();

        match complete.as_slice() {
            [] => None,
            [STONE_PREFIX] => Some(
                NativeCairoCommandConfig::stone_from_env()
                    .and_then(NativeCairoCommandConfig::into_adapter)
                    .expect("complete Stone Cairo adapter config must validate"),
            ),
            [STWO_PREFIX] => Some(
                NativeCairoCommandConfig::stwo_from_env()
                    .and_then(NativeCairoCommandConfig::into_adapter)
                    .expect("complete Stwo Cairo adapter config must validate"),
            ),
            [SCARB_PREFIX] => Some(
                NativeCairoCommandConfig::scarb_from_env()
                    .and_then(NativeCairoCommandConfig::into_adapter)
                    .expect("complete Scarb Cairo adapter config must validate"),
            ),
            _ => {
                panic!(
                    "ambiguous native Cairo/STARK config: configure exactly one of Stone, Stwo, or Scarb"
                );
            }
        }
    }

    #[derive(Clone, Copy)]
    enum NativeEnvState {
        Absent,
        Complete,
        Partial(&'static str),
    }

    fn prefix_state(prefix: &'static str) -> NativeEnvState {
        let present = REQUIRED_NATIVE_SUFFIXES
            .iter()
            .filter(|suffix| env::var(format!("{}_{}", prefix, suffix)).is_ok())
            .count();
        if present == 0 {
            NativeEnvState::Absent
        } else if present == REQUIRED_NATIVE_SUFFIXES.len() {
            NativeEnvState::Complete
        } else {
            NativeEnvState::Partial(prefix)
        }
    }

    fn program_from_env() -> CairoProgramCommitments {
        CairoProgramCommitments::new(
            env_hash("VSEL_CAIRO_PROGRAM_HASH"),
            env_hash("VSEL_CAIRO_SIERRA_PROGRAM_HASH"),
            env_hash("VSEL_CAIRO_CASM_PROGRAM_HASH"),
            env_hash("VSEL_CAIRO_EXECUTABLE_PROGRAM_HASH"),
            env_hash("VSEL_CAIRO_SEMANTIC_BINDING_HASH"),
        )
    }

    fn env_hash(key: &str) -> Hash {
        let value = env::var(key).unwrap_or_else(|_| {
            panic!(
                "positive Cairo/STARK E2E requires {} bound to the real artifact hash",
                key
            )
        });
        parse_hash_hex(key, &value)
    }

    fn parse_hash_hex(name: &str, value: &str) -> Hash {
        let raw = hex_decode(value)
            .unwrap_or_else(|err| panic!("{} must be a valid 32-byte hex digest: {}", name, err));
        assert_eq!(
            raw.len(),
            32,
            "{} must decode to exactly 32 bytes, got {}",
            name,
            raw.len()
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Hash(out)
    }

    fn syntactically_valid_forged_cairo_proof(
        trace: &Trace,
        constraints: &ConstraintSystem,
        program: &CairoProgramCommitments,
    ) -> Proof {
        let witness = construct_witness(trace);
        let public_inputs = PublicInputs::from_trace(trace);
        let constraint_commitment = canonical_constraint_commitment(constraints);
        let commitments = ProofCommitments {
            trace_commitment: trace.commitment.clone(),
            witness_commitment: canonical_witness_commitment(&witness),
            constraint_commitment: constraint_commitment.clone(),
        };
        let backend_id = format!("cairo-stark/{}", NATIVE_TEST_ADAPTER_ID);
        let expected = CairoExpectedStatement {
            backend_id: backend_id.clone(),
            program: program.clone(),
            public_input_hash: public_inputs_commitment(&public_inputs),
            constraint_commitment: constraint_commitment.clone(),
        };
        let cairo_trace_hash = domain_hash(b"vsel-forged-cairo-trace", &trace.commitment.0);
        let statement = CairoStatement::from_expected(&expected, cairo_trace_hash.clone());
        let statement_hash = statement.hash();
        let proof_bytes = b"forged-vcai-proof-without-native-verifier".to_vec();
        let proof_hash = hash_domain_bytes(b"vsel-cairo-proof-bytes-v1", &proof_bytes);
        let verifier_binary_hash = domain_hash(
            b"vsel-forged-cairo-verifier-binary",
            NATIVE_TEST_ADAPTER_ID.as_bytes(),
        );
        let verifier_certificate = CairoVerifierCertificate {
            adapter_id: NATIVE_TEST_ADAPTER_ID.to_string(),
            verifier_version: "forged-native/0".to_string(),
            verifier_binary_hash,
            backend_id: backend_id.clone(),
            program: program.clone(),
            cairo_trace_hash: cairo_trace_hash.clone(),
            public_input_hash: expected.public_input_hash.clone(),
            constraint_commitment: constraint_commitment.clone(),
            statement_hash: statement_hash.clone(),
            proof_hash: proof_hash.clone(),
            transcript_hash: domain_hash(b"vsel-forged-cairo-transcript", &proof_bytes),
            accepted: true,
        };
        let cairo_proof = CairoStarkProof::new(
            backend_id.clone(),
            program.clone(),
            cairo_trace_hash,
            expected.public_input_hash,
            constraint_commitment,
            proof_bytes,
            verifier_certificate,
        )
        .expect("syntactically valid forged VCAI artifact");

        Proof {
            commitments,
            proof_data: cairo_proof.to_bytes(),
            public_inputs,
            metadata: ProofMetadata {
                prover_version: "cairo-native-e2e-negative".to_string(),
                timestamp: 0,
                domain: proof_tag(),
                proof_system: backend_id,
            },
        }
    }

    fn executable_trace() -> Trace {
        let initial_state = executable_state();
        let input = executable_input();
        let post_state = apply(&initial_state, &input);
        let observable = obs(&initial_state, &input, &post_state);
        let mut engine = TraceEngine::new();
        let entry = engine.record_transition(&initial_state, &input, &post_state, &observable);
        Trace {
            entries: vec![entry.clone()],
            initial_state,
            commitment: entry.chain_hash,
        }
    }

    fn executable_state() -> State {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            AccountId([0x11; 32]),
            AccountData {
                balance: 1_000,
                nonce: 0,
                data: Vec::new(),
            },
        );
        let canonical = CanonicalState {
            accounts,
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion::default(),
                total_supply: 1_000,
                parameters: BTreeMap::new(),
            },
        };
        let environment = Environment {
            timestamp: 1_000,
            block_height: 1,
            execution_domain: DomainTag(hash(0x33)),
        };
        State {
            derived: derive(&canonical),
            economic: derive_economic(&canonical, &environment),
            canonical,
            environment,
            metadata: TraceMetadata {
                sequence_index: 0,
                previous_commitment: Hash([0u8; 32]),
                epoch: 0,
                timestamp: 1_000,
            },
        }
    }

    fn executable_input() -> Input {
        Input {
            payload: Payload {
                payload_type: "init".to_string(),
                data: vec![1],
            },
            auth: Authorization {
                classical_sig: vec![1; 64],
                pqc_sig: vec![2; 128],
                public_key: HybridPublicKey {
                    classical: vec![3; 32],
                    pqc: vec![4; 64],
                },
                nonce: 1,
                domain: DomainTag(hash(0x33)),
            },
            aux: AuxiliaryData { data: Vec::new() },
        }
    }

    fn covered_constraint_system() -> ConstraintSystem {
        let mut constraints = ConstraintSystem::new("cairo-native-e2e");
        constraints.add(Constraint {
            id: ConstraintId(10),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("input_count".to_string())),
                Box::new(ConstraintExpr::Constant(1)),
            ),
            category: ConstraintCategory::Semantic,
            description: "semantic input count binding".to_string(),
        });
        constraints.add(Constraint {
            id: ConstraintId(11),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::PublicInputRef(
                    "observables_count".to_string(),
                )),
                Box::new(ConstraintExpr::Constant(1)),
            ),
            category: ConstraintCategory::Invariant,
            description: "invariant observable count binding".to_string(),
        });
        constraints
    }

    fn deterministic_program() -> CairoProgramCommitments {
        CairoProgramCommitments::new(hash(0x41), hash(0x42), hash(0x43), hash(0x44), hash(0x45))
    }

    fn hash(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        finalize_hash(hasher)
    }

    fn formal_spec_path() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../formal")
            .canonicalize()
            .expect("formal spec path")
            .to_string_lossy()
            .into_owned()
    }
}
