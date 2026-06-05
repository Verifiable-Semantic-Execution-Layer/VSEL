//! vsel-crypto: Hybrid cryptography (classical + PQC), domain separation, key lifecycle.
//! Derived from CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.

pub mod domain;
pub mod goldilocks;
pub mod hash;
pub mod keys;
#[cfg(feature = "poseidon-legacy")]
#[cfg_attr(not(test), deprecated(note = "Use poseidon_goldilocks for production"))]
pub mod legacy_poseidon;
pub mod migration;
pub mod poseidon_goldilocks;
pub mod signatures;

pub use goldilocks::reduce128;
pub use goldilocks::GoldilocksField;

pub use domain::{
    create_domain_tag, domain_hash, domain_hash_blake3, proof_tag, signature_tag,
    state_commitment_tag, trace_commitment_tag, verify_domain_separation, DOMAIN_KEY_DERIVATION,
    DOMAIN_PROOF, DOMAIN_SIGNATURE, DOMAIN_STATE_COMMITMENT, DOMAIN_TRACE_COMMITMENT,
    DOMAIN_WITNESS,
};

pub use hash::{
    commit_canonical_state, domain_hash_with_algorithm, hash_with_algorithm, recommended_algorithm,
    HashAlgorithm, TemporalClass,
};

pub use signatures::{
    combine_shared_secrets, generate_hybrid_keypair, generate_hybrid_keypair_with_pqc,
    hybrid_key_exchange, hybrid_sign, hybrid_sign_with_pqc, hybrid_verify, hybrid_verify_with_pqc,
    sign_classical, verify_classical, HmacSha3PqcSigner, HybridSharedSecret, HybridSigner,
    PqcSigner, SignatureError,
};

pub use keys::{
    derive_key_id, generate_managed_key, is_expired, KeyError, KeyId, KeyMetadata, KeyStatus,
    KeyStore, ManagedKey,
};

pub use migration::{
    migrate_commitment, migrate_proof_commitment, migrate_signature, verify_commitment_migration,
    CommitmentMigration, CryptoAgility, MigrationError, MigrationPolicy, ProofMigration,
    SignatureMigration, WitnessArchive, WitnessArchiveStore,
};
