//! vsel-proof: Prover, verifier, witness construction, recursive proof composition.
//! Derived from PROOF_LAYER.md, VERIFICATION_LAYER.md.

pub mod backend;
pub mod circuit;
pub mod hash_backend;
#[cfg(feature = "plonky3-backend")]
pub mod plonky3_backend;
#[cfg(feature = "plonky3-backend")]
pub mod plonky3_circuit;
#[cfg(feature = "plonky3-backend")]
pub mod trace_gen;
#[cfg(feature = "plonky3-backend")]
pub mod vsel_air;
#[cfg(feature = "plonky3-backend")]
pub mod recursive_air;
pub mod prover;
pub mod public_inputs;
pub mod recursive;
pub mod replay;
pub mod verifier;
pub mod witness;
