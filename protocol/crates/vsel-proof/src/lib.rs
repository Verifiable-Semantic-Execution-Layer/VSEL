//! vsel-proof: Prover, verifier, witness construction, recursive proof composition.
//! Derived from PROOF_LAYER.md, VERIFICATION_LAYER.md.
//!
//! # Two-Phase Verification System (Task A.2)
//!
//! This crate implements the VSEL proof system with explicit separation between
//! cryptographic and semantic verification. This separation addresses
//! [VSEL-ADV-001: Core Verification Overclaim](https://github.com/vsel/docs/adversarial/FINDINGS_REGISTER.md).
//!
//! ## Quick Start
//!
//! ### Basic Usage (Backward Compatible)
//! ```rust
//! use vsel_proof::verifier::{DefaultVerifier, VerificationResult};
//! use vsel_proof::prover::{DefaultProver, Prover};
//!
//! let prover = DefaultProver::new("1.0.0");
//! let proof = prover.prove(&trace, &constraints).expect("proof");
//!
//! let verifier = DefaultVerifier::default();
//! let result = verifier.verify(&proof, &proof.public_inputs);
//!
//! // NOTE: CryptographicallyConsistent does NOT imply semantic validity
//! assert!(result.is_cryptographically_consistent());
//! ```
//!
//! ### Two-Phase Verification (Recommended)
//! ```rust
//! use vsel_proof::verifier::{
//!     VerificationPipeline, GenericVerifier, DefaultSemanticVerifier,
//!     ComprehensiveVerificationResult
//! };
//! use vsel_proof::hash_backend::HashBackend;
//! use vsel_core::types::ProtocolVersion;
//!
//! // Create two-phase verification pipeline
//! let pipeline = VerificationPipeline::new(
//!     GenericVerifier::<HashBackend>::new(ProtocolVersion::default()),
//!     DefaultSemanticVerifier::new(ProtocolVersion::default()),
//! );
//!
//! // Execute both phases
//! let comprehensive = pipeline.verify(&proof, &public_inputs);
//!
//! // Check both phases separately
//! assert!(comprehensive.cryptographic.is_consistent());
//! assert!(comprehensive.semantic.is_valid());
//! assert!(comprehensive.is_fully_verified()); // Both phases passed
//! ```
//!
//! ### With Lean 4 Formal Verification
//! ```rust
//! use vsel_proof::verifier::Lean4SemanticVerifier;
//!
//! let pipeline = VerificationPipeline::new(
//!     GenericVerifier::<HashBackend>::new(version),
//!     Lean4SemanticVerifier::new(version)
//!         .with_lean_executable("/usr/local/bin/lake")
//!         .with_formal_spec_path("/opt/vsel/formal"),
//! );
//! ```
//!
//! ## Module Overview
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`verifier`] | Two-phase verification pipeline and traits |
//! | [`prover`] | Proof generation |
//! | [`witness`] | Witness construction |
//! | [`public_inputs`] | Public input types |
//! | [`backend`] | ZK backend abstraction |
//! | [`hash_backend`] | Hash-based proof backend |
//! | [`recursive`] | Recursive proof composition |
//! | [`replay`] | Replay protection |
//!
//! ## Security Warnings
//!
//! ⚠️ **CRITICAL**: `VerificationResult::CryptographicallyConsistent` indicates cryptographic
//! validity ONLY. It does NOT imply semantic validity. A proof can be cryptographically
//! correct but semantically invalid. Always use `ComprehensiveVerificationResult` with
//! both phases for security-critical applications.
//!
//! ## Migration Guide
//!
//! ### From Legacy API
//! ```rust
//! // Old API (still works, but deprecated)
//! let result = verifier.verify(&proof, &pub_inputs);
//! if result.is_accepted() { // Deprecated
//!     // ...
//! }
//!
//! // New API (recommended)
//! let pipeline = VerificationPipeline::new(crypto_verifier, semantic_verifier);
//! let comprehensive = pipeline.verify(&proof, &pub_inputs);
//! if comprehensive.is_fully_verified() {
//!     // Both cryptographic AND semantic validation passed
//! }
//! ```

pub mod backend;
pub mod circuit;
pub mod hash_backend;
#[cfg(feature = "plonky3-backend")]
pub mod plonky3_backend;
#[cfg(feature = "plonky3-backend")]
pub mod plonky3_circuit;
pub mod prover;
pub mod public_inputs;
pub mod recursive;
#[cfg(feature = "plonky3-backend")]
pub mod recursive_air;
pub mod replay;
#[cfg(feature = "plonky3-backend")]
pub mod trace_gen;
pub mod verifier;
#[cfg(feature = "plonky3-backend")]
pub mod vsel_air;
pub mod witness;

// Re-export key types for convenience
pub use verifier::{
    AssumeGuaranteeContract, AttackPattern, BuchiAutomaton, ComprehensiveSemanticVerifier,
    ComprehensiveVerificationResult, ContractCondition, ContractError, ContractVerificationResult,
    CryptographicVerificationResult, CryptographicVerifier, DefaultSemanticVerifier,
    DifferentialAnalysisResult, DifferentialError, DifferentialSemanticAnalyzer,
    IntegratedFormalVerificationResult, IntegratedFormalVerificationStatus,
    IntegratedFormalVerifier, InterpretationError, Lean4SemanticVerifier, LtlProperty,
    ProofCarryingWitness, ProofWitness, RealTimeModelChecker, RefinementError, RefinementLayer,
    RefinementProof, RefinementProofVerifier, RefinementVerificationResult, SemanticAmbiguity,
    SemanticConstraintSolver, SemanticDrift, SemanticInterpretation, SemanticMeaning,
    SemanticProof, SemanticValidationError, SemanticVerificationResult, SemanticVerifier,
    SimulationRelation, Solution, SolverBackend, SolverError, SymbolicConstraint,
    SymbolicExecutionEngine, SymbolicExecutionError, SymbolicExecutionResult, SymbolicValue,
    TrustAssumption, VerificationCertificate, VerificationPipeline, VerificationResult,
    VerificationStatus, VerificationTimeout,
};
