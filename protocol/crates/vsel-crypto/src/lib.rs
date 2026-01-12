//! vsel-crypto: Hybrid cryptography (classical + PQC), domain separation, key lifecycle.
//! Derived from CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.

pub mod domain;

pub use domain::{
    create_domain_tag, domain_hash, domain_hash_blake3, verify_domain_separation,
    state_commitment_tag, trace_commitment_tag, proof_tag, signature_tag,
    DOMAIN_KEY_DERIVATION, DOMAIN_PROOF, DOMAIN_SIGNATURE,
    DOMAIN_STATE_COMMITMENT, DOMAIN_TRACE_COMMITMENT, DOMAIN_WITNESS,
};
