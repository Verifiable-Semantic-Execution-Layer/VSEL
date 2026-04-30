//! vsel-crypto: Hybrid cryptography (classical + PQC), domain separation, key lifecycle.
//! Derived from CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.

pub mod domain;
pub mod goldilocks;
pub mod hash;
pub mod keys;
#[cfg(feature = "poseidon-legacy")]
#[deprecated(note = "Use poseidon_goldilocks for production")]
pub mod legacy_poseidon;
pub mod migration;
pub mod poseidon_goldilocks;
pub mod signatures;

pub use goldilocks::GoldilocksField;
pub use goldilocks::reduce128;

pub use domain::{
    create_domain_tag, domain_hash, domain_hash_blake3, verify_domain_separation,
    state_commitment_tag, trace_commitment_tag, proof_tag, signature_tag,
    DOMAIN_KEY_DERIVATION, DOMAIN_PROOF, DOMAIN_SIGNATURE,
    DOMAIN_STATE_COMMITMENT, DOMAIN_TRACE_COMMITMENT, DOMAIN_WITNESS,
};

pub use hash::{
    HashAlgorithm, TemporalClass,
    hash_with_algorithm, domain_hash_with_algorithm,
    commit_canonical_state, recommended_algorithm,
};

pub use signatures::{
    SignatureError, PqcSigner, HmacSha3PqcSigner, HybridSigner,
    HybridSharedSecret,
    sign_classical, verify_classical,
    hybrid_sign, hybrid_verify,
    hybrid_sign_with_pqc, hybrid_verify_with_pqc,
    generate_hybrid_keypair, generate_hybrid_keypair_with_pqc,
    combine_shared_secrets, hybrid_key_exchange,
};

pub use keys::{
    KeyId, KeyStatus, KeyMetadata, ManagedKey, KeyError, KeyStore,
    derive_key_id, is_expired, generate_managed_key,
};

pub use migration::{
    MigrationError, MigrationPolicy, CommitmentMigration,
    SignatureMigration, WitnessArchive, WitnessArchiveStore,
    ProofMigration, CryptoAgility,
    migrate_commitment, verify_commitment_migration,
    migrate_signature, migrate_proof_commitment,
};
