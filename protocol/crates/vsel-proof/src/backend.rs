//! ZkBackend trait — pluggable ZK proof backend abstraction.
//!
//! Derived from: ZK_BACKEND_INTEGRATION.md, PROOF_LAYER.md §2,
//! Requirements 1.1, 1.7.
//!
//! The `ZkBackend` trait defines the interface for ZK proof backends.
//! All proof generation and verification flows through this trait,
//! enabling pluggable backends (HashBackend for backward compatibility,
//! Plonky3Backend for production STARK proofs) without modifying
//! semantic verification logic.
//!
//! Design invariants:
//! - Prove-verify round-trip: if `prove` succeeds, `verify` returns true
//!   (Property 1 from design document).
//! - Error propagation: errors include `backend_id()` — no silent fallback
//!   (Requirement 1.8).
//! - Serialization round-trip: `deserialize(serialize(proof))` is
//!   byte-equivalent to the original (Property 5).

use vsel_constraints::ConstraintSystem;
use vsel_core::types::Hash;

use crate::public_inputs::PublicInputs;
use crate::witness::Witness;

// ---------------------------------------------------------------------------
// ZkBackend — pluggable proof backend trait
// ---------------------------------------------------------------------------

/// Trait for ZK proof backends.
///
/// The backend receives a witness, constraint system, and public inputs,
/// and produces an opaque proof that can be verified. All other components
/// interact with the backend exclusively through this interface.
///
/// # Associated Types
///
/// - `Proof`: The opaque proof type. Must be cloneable, convertible to
///   bytes via `AsRef<[u8]>`, and safe to send across threads.
/// - `Error`: The error type for proof generation and deserialization
///   failures. Must implement `std::error::Error` for composability.
///
/// # Contract
///
/// - **Prove-verify round-trip** (Property 1): For any valid witness,
///   constraint system, and public inputs, if `prove` succeeds producing
///   proof π, then `verify(π, public_inputs, constraint_commitment)`
///   returns `true`.
/// - **No silent fallback** (Requirement 1.8): If `prove` returns an
///   error, the error message must contain `backend_id()`. No fallback
///   to another backend is permitted.
/// - **Serialization round-trip** (Property 5): For any proof π,
///   `deserialize_proof(serialize_proof(π))` produces a proof that is
///   byte-equivalent to the original.
///
/// # Implementors
///
/// - `HashBackend`: SHA3-256 commitment-based backend (backward compatible).
/// - `Plonky3Backend`: Production STARK backend over Goldilocks field
///   (behind `plonky3-backend` feature flag).
///
/// Requirements 1.1, 1.7.
pub trait ZkBackend: Send + Sync {
    /// Opaque proof type produced by this backend.
    ///
    /// Must be cloneable for composition, convertible to bytes for
    /// serialization, and thread-safe for parallel verification.
    type Proof: Clone + AsRef<[u8]> + Send + Sync;

    /// Error type for proof generation and deserialization failures.
    ///
    /// Must implement `std::error::Error` for composability with
    /// the `ProverError` chain. The `'static` bound enables
    /// `Box<dyn Error>` usage.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Generate a ZK proof from witness, constraints, and public inputs.
    ///
    /// The backend translates the VSEL constraint system into its native
    /// representation, assigns the witness, and produces a proof that
    /// the witness satisfies all constraints with respect to the public
    /// inputs.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if:
    /// - The witness is incompatible with the constraint system
    /// - The constraint system contains unsupported expressions
    /// - Internal proof generation fails
    ///
    /// The error message MUST contain `backend_id()` (Requirement 1.8).
    fn prove(
        &self,
        witness: &Witness,
        constraints: &ConstraintSystem,
        public_inputs: &PublicInputs,
    ) -> Result<Self::Proof, Self::Error>;

    /// Verify a ZK proof against public inputs and constraint commitment.
    ///
    /// Returns `true` if the proof is valid — the prover demonstrated
    /// knowledge of a witness satisfying the constraints with respect
    /// to the given public inputs and constraint commitment.
    ///
    /// Returns `false` if the proof is invalid, malformed, or does not
    /// match the provided public inputs / constraint commitment.
    ///
    /// This method MUST be deterministic: the same inputs always produce
    /// the same result.
    fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &PublicInputs,
        constraint_commitment: &Hash,
    ) -> bool;

    /// Return the backend identifier.
    ///
    /// A unique string identifying this backend implementation.
    /// Used in error messages, proof metadata, and audit logs.
    ///
    /// Examples: `"hash-sha3"`, `"plonky3-stark"`.
    ///
    /// Requirement 1.7.
    fn backend_id(&self) -> &str;

    /// Return whether this backend provides post-quantum security.
    ///
    /// - `true`: The proof system is secure against quantum adversaries
    ///   (e.g., STARK-based backends with transparent setup).
    /// - `false`: The proof system relies on classical hardness assumptions
    ///   (e.g., hash-based commitments without algebraic proofs).
    ///
    /// Requirement 1.7.
    fn is_post_quantum(&self) -> bool;

    /// Serialize a proof to bytes for storage or transmission.
    ///
    /// The serialization MUST be deterministic: the same proof always
    /// produces the same byte sequence. This is required for:
    /// - Proof comparison in differential testing
    /// - Audit evidence archival
    /// - Reproducible verification
    fn serialize_proof(&self, proof: &Self::Proof) -> Vec<u8>;

    /// Deserialize a proof from bytes.
    ///
    /// Reconstructs a proof from its serialized byte representation.
    /// Returns an error if the bytes are malformed or do not represent
    /// a valid proof for this backend.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` if:
    /// - The byte sequence is too short or too long
    /// - The bytes do not represent a valid proof structure
    /// - The proof was serialized by a different backend
    fn deserialize_proof(&self, bytes: &[u8]) -> Result<Self::Proof, Self::Error>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal mock backend for testing the trait definition compiles
    /// and can be implemented. This is NOT used in production — it exists
    /// solely to verify the trait is well-formed and object-safe enough
    /// for our use cases.
    #[derive(Clone)]
    struct MockProof(Vec<u8>);

    impl AsRef<[u8]> for MockProof {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug)]
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock-backend: {}", self.0)
        }
    }

    impl std::error::Error for MockError {}

    struct MockBackend;

    impl ZkBackend for MockBackend {
        type Proof = MockProof;
        type Error = MockError;

        fn prove(
            &self,
            _witness: &Witness,
            _constraints: &ConstraintSystem,
            _public_inputs: &PublicInputs,
        ) -> Result<Self::Proof, Self::Error> {
            Ok(MockProof(vec![0xDE, 0xAD]))
        }

        fn verify(
            &self,
            proof: &Self::Proof,
            _public_inputs: &PublicInputs,
            _constraint_commitment: &Hash,
        ) -> bool {
            // Accept any non-empty proof.
            !proof.0.is_empty()
        }

        fn backend_id(&self) -> &str {
            "mock-test"
        }

        fn is_post_quantum(&self) -> bool {
            false
        }

        fn serialize_proof(&self, proof: &Self::Proof) -> Vec<u8> {
            proof.0.clone()
        }

        fn deserialize_proof(&self, bytes: &[u8]) -> Result<Self::Proof, Self::Error> {
            if bytes.is_empty() {
                return Err(MockError("mock-test: empty proof bytes".to_string()));
            }
            Ok(MockProof(bytes.to_vec()))
        }
    }

    #[test]
    fn test_mock_backend_id() {
        let backend = MockBackend;
        assert_eq!(backend.backend_id(), "mock-test");
    }

    #[test]
    fn test_mock_backend_is_not_post_quantum() {
        let backend = MockBackend;
        assert!(!backend.is_post_quantum());
    }

    #[test]
    fn test_mock_backend_serialize_deserialize_round_trip() {
        let backend = MockBackend;
        let proof = MockProof(vec![1, 2, 3, 4]);

        let serialized = backend.serialize_proof(&proof);
        let deserialized = backend
            .deserialize_proof(&serialized)
            .expect("deserialization should succeed");

        assert_eq!(proof.as_ref(), deserialized.as_ref());
    }

    #[test]
    fn test_mock_backend_deserialize_empty_fails() {
        let backend = MockBackend;
        let result = backend.deserialize_proof(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_backend_verify_non_empty_proof() {
        let backend = MockBackend;
        let proof = MockProof(vec![0xDE, 0xAD]);
        let hash = Hash([0u8; 32]);

        // We need minimal PublicInputs for the verify call.
        // Use a simple construction since we're just testing the trait.
        let public_inputs = PublicInputs {
            root_init: Hash([1u8; 32]),
            root_final: Hash([2u8; 32]),
            observables: vec![],
            domain: vsel_core::types::DomainTag(Hash([3u8; 32])),
            version: vsel_core::types::ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };

        assert!(backend.verify(&proof, &public_inputs, &hash));
    }

    #[test]
    fn test_mock_backend_verify_empty_proof_rejected() {
        let backend = MockBackend;
        let proof = MockProof(vec![]);
        let hash = Hash([0u8; 32]);

        let public_inputs = PublicInputs {
            root_init: Hash([1u8; 32]),
            root_final: Hash([2u8; 32]),
            observables: vec![],
            domain: vsel_core::types::DomainTag(Hash([3u8; 32])),
            version: vsel_core::types::ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };

        assert!(!backend.verify(&proof, &public_inputs, &hash));
    }

    /// Verify the trait can be used as a generic bound.
    fn _generic_prove<B: ZkBackend>(
        backend: &B,
        witness: &Witness,
        constraints: &ConstraintSystem,
        public_inputs: &PublicInputs,
    ) -> Result<B::Proof, B::Error> {
        backend.prove(witness, constraints, public_inputs)
    }

    #[test]
    fn test_trait_usable_as_generic_bound() {
        // This test verifies the trait works as a generic parameter.
        // The function above compiles, which is the real test.
        let backend = MockBackend;
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let constraints = ConstraintSystem::new("1.0.0");
        let public_inputs = PublicInputs {
            root_init: Hash([1u8; 32]),
            root_final: Hash([2u8; 32]),
            observables: vec![],
            domain: vsel_core::types::DomainTag(Hash([3u8; 32])),
            version: vsel_core::types::ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };

        let result = _generic_prove(&backend, &witness, &constraints, &public_inputs);
        assert!(result.is_ok());
    }
}
