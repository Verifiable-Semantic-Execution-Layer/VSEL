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
//! ```text
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
//! `DefaultProver` and `DefaultVerifier` use the legacy hash-placeholder
//! proof shape. STARK-backed claims require `BackendProver<B>` paired with
//! `BackendCryptographicVerifier<B>` over the same concrete `ZkBackend`.
//!
//! ### Final Verification (Fail Closed)
//! ```text
//! use vsel_proof::verifier::{
//!     VerificationPipeline, GenericVerifier, DefaultSemanticVerifier
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
//! // Execute legacy two-phase inspection. This cannot produce final semantic
//! // acceptance because it does not include witness/constraint evidence and the
//! // default semantic verifier is non-authoritative.
//! let comprehensive = pipeline.verify(&proof, &public_inputs);
//!
//! assert!(comprehensive.cryptographic.is_consistent());
//! assert!(!comprehensive.is_fully_verified());
//! ```
//!
//! ### With Lean 4 Formal Verification Adapter
//! ```text
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
//! | [`cairo_stark`] | Cairo/STARK proof adapter contract and VCAI artifact binding |
//! | [`cairo_native`] | Fail-closed Stone/Stwo command adapter constructors (`cairo-stark-backend`) |
//! | [`hash_backend`] | Hash-based proof backend |
//! | [`recursive`] | Recursive proof composition |
//! | [`replay`] | Replay protection |
//!
//! ## Security Warnings
//!
//! ⚠️ **CRITICAL**: `VerificationResult::CryptographicallyConsistent` indicates cryptographic
//! validity ONLY. It does NOT imply semantic validity. A proof can be cryptographically
//! correct but semantically invalid. Security-critical applications must use
//! `VerificationPipeline::verify_strict_trace` with witness, constraints, the
//! complete execution trace, and an authoritative executable/mechanized semantic
//! verifier.
//!
//! ## Migration Guide
//!
//! ### From Legacy API
//! ```text
//! // Old API (still works, but deprecated)
//! let result = verifier.verify(&proof, &pub_inputs);
//! if result.is_accepted() { // Deprecated
//!     // ...
//! }
//!
//! // Inspection API: exposes phases but is not final acceptance.
//! let pipeline = VerificationPipeline::new(crypto_verifier, semantic_verifier);
//! let comprehensive = pipeline.verify(&proof, &pub_inputs);
//! if comprehensive.is_fully_verified() {
//!     // This branch is unreachable for non-strict verification.
//! }
//! ```

pub mod backend;
#[cfg(feature = "cairo-stark-backend")]
pub mod cairo_native;
pub mod cairo_stark;
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
    AssumeGuaranteeContract, AttackPattern, BackendCryptographicVerifier, BuchiAutomaton,
    ComprehensiveSemanticVerifier, ComprehensiveVerificationResult, ConstraintWitnessVerifier,
    ContractCondition, ContractError, ContractVerificationResult, CryptographicVerificationResult,
    CryptographicVerifier, DefaultSemanticVerifier, DifferentialAnalysisResult, DifferentialError,
    DifferentialSemanticAnalyzer, IntegratedFormalVerificationResult,
    IntegratedFormalVerificationStatus, IntegratedFormalVerifier, InterpretationError,
    Lean4SemanticVerifier, LtlProperty, ProofCarryingWitness, ProofWitness, RealTimeModelChecker,
    RefinementError, RefinementLayer, RefinementProof, RefinementProofVerifier,
    RefinementVerificationResult, SemanticAmbiguity, SemanticConstraintSolver, SemanticDrift,
    SemanticInterpretation, SemanticMeaning, SemanticProof, SemanticValidationError,
    SemanticVerificationEvidence, SemanticVerificationMode, SemanticVerificationResult,
    SemanticVerifier, SimulationRelation, Solution, SolverBackend, SolverError, SymbolicConstraint,
    SymbolicExecutionEngine, SymbolicExecutionError, SymbolicExecutionResult, SymbolicValue,
    TraceSemanticVerifier, TrustAssumption, VerificationCertificate, VerificationPipeline,
    VerificationResult, VerificationStatus, VerificationTimeout,
};
