//! Cryptographic migration protocols for the VSEL protocol.
//!
//! Derived from: CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.
//!
//! Provides:
//! - Commitment migration when hash primitives are threatened
//! - Signature migration to new key material
//! - Proof migration with witness archival for re-proving
//! - Cryptographic agility: primitive replacement without breaking state validity
//!
//! Requirements: 10.8 (migration protocols), 10.9 (witness archival), 10.10 (cryptographic agility).

use std::collections::BTreeMap;

use thiserror::Error;
use vsel_core::types::{DomainTag, Hash, HybridSignature, HybridSigningKey};

use crate::domain::create_domain_tag;
use crate::hash::{domain_hash_with_algorithm, HashAlgorithm};
use crate::keys::KeyId;
use crate::signatures::{hybrid_sign, SignatureError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors arising from cryptographic migration operations.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// The source commitment does not match the expected value.
    #[error("invalid source commitment")]
    InvalidSourceCommitment,

    /// Signature verification or re-signing failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(#[from] SignatureError),

    /// The requested algorithm is not supported.
    #[error("algorithm not supported: {0}")]
    AlgorithmNotSupported(String),

    /// Witness archive operation failed.
    #[error("witness archive error: {0}")]
    WitnessArchiveError(String),

    /// General migration failure.
    #[error("migration failed: {0}")]
    MigrationFailed(String),
}

// ---------------------------------------------------------------------------
// Migration policy
// ---------------------------------------------------------------------------

/// Policy describing a cryptographic migration — why, from what, to what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPolicy {
    /// Hash algorithm being migrated FROM.
    pub source_algorithm: HashAlgorithm,
    /// Hash algorithm being migrated TO.
    pub target_algorithm: HashAlgorithm,
    /// Human-readable reason for the migration.
    pub reason: String,
    /// Timestamp when the migration was initiated.
    pub initiated_at: u64,
    /// Optional deadline for completing the migration.
    pub deadline: Option<u64>,
}

// ---------------------------------------------------------------------------
// Commitment migration
// ---------------------------------------------------------------------------

/// Record of a commitment migration from one hash algorithm to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentMigration {
    /// Commitment computed under the source (old) algorithm.
    pub original_commitment: Hash,
    /// Commitment computed under the target (new) algorithm.
    pub migrated_commitment: Hash,
    /// The policy governing this migration.
    pub policy: MigrationPolicy,
    /// Whether the migration has been verified.
    pub verified: bool,
}

/// Migrate a commitment from one hash algorithm to another.
///
/// Computes the commitment under both the source and target algorithms,
/// returning a `CommitmentMigration` record for verification.
pub fn migrate_commitment(
    data: &[u8],
    domain: &DomainTag,
    policy: &MigrationPolicy,
) -> Result<CommitmentMigration, MigrationError> {
    let original = domain_hash_with_algorithm(policy.source_algorithm, domain, data);
    let migrated = domain_hash_with_algorithm(policy.target_algorithm, domain, data);

    Ok(CommitmentMigration {
        original_commitment: original,
        migrated_commitment: migrated,
        policy: policy.clone(),
        verified: false,
    })
}

/// Verify a commitment migration by recomputing both commitments.
///
/// Returns `true` if both the original and migrated commitments match
/// the recomputed values from the raw data.
pub fn verify_commitment_migration(
    data: &[u8],
    domain: &DomainTag,
    migration: &CommitmentMigration,
) -> bool {
    let recomputed_original =
        domain_hash_with_algorithm(migration.policy.source_algorithm, domain, data);
    let recomputed_migrated =
        domain_hash_with_algorithm(migration.policy.target_algorithm, domain, data);

    recomputed_original == migration.original_commitment
        && recomputed_migrated == migration.migrated_commitment
}

// ---------------------------------------------------------------------------
// Signature migration
// ---------------------------------------------------------------------------

/// Record of a signature migration from one key to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureMigration {
    /// Signature produced by the old signing key.
    pub original_signature: HybridSignature,
    /// Signature produced by the new signing key.
    pub migrated_signature: HybridSignature,
    /// Identifier of the new signing key used.
    pub signing_key_id: KeyId,
    /// The policy governing this migration.
    pub policy: MigrationPolicy,
}

/// Migrate a signature by re-signing the message with a new key.
///
/// The original signature (under the old key) and the new signature
/// (under the new key) are both returned for audit and verification.
pub fn migrate_signature(
    message: &[u8],
    domain: &DomainTag,
    old_signing_key: &HybridSigningKey,
    new_signing_key: &HybridSigningKey,
    new_key_id: KeyId,
    policy: MigrationPolicy,
) -> Result<SignatureMigration, MigrationError> {
    let original_signature = hybrid_sign(old_signing_key, message, domain)?;
    let migrated_signature = hybrid_sign(new_signing_key, message, domain)?;

    Ok(SignatureMigration {
        original_signature,
        migrated_signature,
        signing_key_id: new_key_id,
        policy,
    })
}

// ---------------------------------------------------------------------------
// Witness archive
// ---------------------------------------------------------------------------

/// Archived witness data for re-proving under new proof systems.
///
/// Witness data is archived for the lifetime of proof relevance so that
/// proofs can be regenerated if the original proof system is deprecated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessArchive {
    /// Unique identifier for this archive entry (hash of witness data).
    pub witness_id: Hash,
    /// Serialized witness data.
    pub witness_data: Vec<u8>,
    /// The proof commitment this witness relates to.
    pub proof_commitment: Hash,
    /// Timestamp when the witness was archived.
    pub archived_at: u64,
    /// Hash algorithm used when the proof was originally generated.
    pub algorithm_used: HashAlgorithm,
    /// Optional expiry timestamp — when the archive can be purged.
    pub expiry: Option<u64>,
}

/// Domain tag for witness archive identifiers.
const DOMAIN_WITNESS_ARCHIVE: &[u8] = b"VSEL::v1::migration::witness_archive";

/// In-memory store for archived witness data.
#[derive(Clone, Debug, Default)]
pub struct WitnessArchiveStore {
    archives: BTreeMap<Hash, WitnessArchive>,
}

impl WitnessArchiveStore {
    /// Create an empty witness archive store.
    pub fn new() -> Self {
        Self {
            archives: BTreeMap::new(),
        }
    }

    /// Archive witness data and return its unique identifier.
    ///
    /// The witness ID is computed as a domain-separated hash of the witness data.
    pub fn archive(
        &mut self,
        witness_data: Vec<u8>,
        proof_commitment: Hash,
        algorithm: HashAlgorithm,
        timestamp: u64,
        expiry: Option<u64>,
    ) -> Hash {
        let tag = create_domain_tag(DOMAIN_WITNESS_ARCHIVE);
        let witness_id = domain_hash_with_algorithm(HashAlgorithm::Blake3, &tag, &witness_data);

        let entry = WitnessArchive {
            witness_id: witness_id.clone(),
            witness_data,
            proof_commitment,
            archived_at: timestamp,
            algorithm_used: algorithm,
            expiry,
        };

        self.archives.insert(witness_id.clone(), entry);
        witness_id
    }

    /// Retrieve an archived witness by its ID.
    pub fn get(&self, witness_id: &Hash) -> Option<&WitnessArchive> {
        self.archives.get(witness_id)
    }

    /// Purge expired archives. Returns the number of entries removed.
    pub fn purge_expired(&mut self, current_time: u64) -> usize {
        let before = self.archives.len();
        self.archives.retain(|_, entry| {
            match entry.expiry {
                Some(exp) => current_time < exp,
                None => true, // no expiry — keep forever
            }
        });
        before - self.archives.len()
    }

    /// Return the number of archived entries.
    pub fn len(&self) -> usize {
        self.archives.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.archives.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Proof migration
// ---------------------------------------------------------------------------

/// Record of a proof commitment migration with witness archival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMigration {
    /// Original proof commitment under the source algorithm.
    pub original_proof_commitment: Hash,
    /// Migrated proof commitment under the target algorithm.
    pub migrated_proof_commitment: Hash,
    /// Reference to the archived witness for re-proving.
    pub witness_archive_id: Hash,
    /// The policy governing this migration.
    pub policy: MigrationPolicy,
}

/// Migrate a proof commitment, archiving the witness data for re-proving.
///
/// 1. Archives the witness data in the store.
/// 2. Computes the original proof commitment under the source algorithm.
/// 3. Computes the migrated proof commitment under the target algorithm.
/// 4. Returns a `ProofMigration` record linking both commitments to the archive.
pub fn migrate_proof_commitment(
    proof_data: &[u8],
    domain: &DomainTag,
    witness_data: Vec<u8>,
    archive: &mut WitnessArchiveStore,
    policy: &MigrationPolicy,
    timestamp: u64,
) -> Result<ProofMigration, MigrationError> {
    let original = domain_hash_with_algorithm(policy.source_algorithm, domain, proof_data);

    // Archive witness for re-proving under new proof system
    let witness_archive_id = archive.archive(
        witness_data,
        original.clone(),
        policy.source_algorithm,
        timestamp,
        None, // no expiry — keep for lifetime of proof relevance
    );

    let migrated = domain_hash_with_algorithm(policy.target_algorithm, domain, proof_data);

    Ok(ProofMigration {
        original_proof_commitment: original,
        migrated_proof_commitment: migrated,
        witness_archive_id,
        policy: policy.clone(),
    })
}

// ---------------------------------------------------------------------------
// Cryptographic agility
// ---------------------------------------------------------------------------

/// Cryptographic agility manager — tracks supported algorithms, defaults,
/// and active migration policies.
///
/// Enables primitive replacement without breaking state validity by
/// maintaining a registry of supported algorithms and migration paths.
#[derive(Clone, Debug)]
pub struct CryptoAgility {
    /// Algorithms currently supported by the system.
    pub supported_algorithms: Vec<HashAlgorithm>,
    /// The current default algorithm for new operations.
    pub current_default: HashAlgorithm,
    /// Active migration policies.
    pub migration_policies: Vec<MigrationPolicy>,
}

impl CryptoAgility {
    /// Create a new `CryptoAgility` manager with the given default algorithm.
    ///
    /// The default algorithm is automatically added to the supported set.
    pub fn new(default: HashAlgorithm) -> Self {
        Self {
            supported_algorithms: vec![default],
            current_default: default,
            migration_policies: Vec::new(),
        }
    }

    /// Add an algorithm to the supported set.
    ///
    /// Duplicate additions are ignored.
    pub fn add_algorithm(&mut self, algo: HashAlgorithm) {
        if !self.supported_algorithms.contains(&algo) {
            self.supported_algorithms.push(algo);
        }
    }

    /// Set a new default algorithm.
    ///
    /// Returns an error if the algorithm is not in the supported set.
    pub fn set_default(&mut self, algo: HashAlgorithm) -> Result<(), MigrationError> {
        if !self.supported_algorithms.contains(&algo) {
            return Err(MigrationError::AlgorithmNotSupported(format!(
                "{:?} is not in the supported algorithm set",
                algo
            )));
        }
        self.current_default = algo;
        Ok(())
    }

    /// Check whether an algorithm is supported.
    pub fn is_supported(&self, algo: &HashAlgorithm) -> bool {
        self.supported_algorithms.contains(algo)
    }

    /// Add a migration policy.
    pub fn add_migration_policy(&mut self, policy: MigrationPolicy) {
        self.migration_policies.push(policy);
    }

    /// Return a slice of all active migration policies.
    pub fn active_migrations(&self) -> &[MigrationPolicy] {
        &self.migration_policies
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::create_domain_tag;
    use crate::keys::derive_key_id;
    use crate::signatures::generate_hybrid_keypair;

    fn test_domain() -> DomainTag {
        create_domain_tag(b"test::migration")
    }

    fn test_policy(source: HashAlgorithm, target: HashAlgorithm) -> MigrationPolicy {
        MigrationPolicy {
            source_algorithm: source,
            target_algorithm: target,
            reason: "test migration".to_string(),
            initiated_at: 1000,
            deadline: None,
        }
    }

    // -- Commitment migration ------------------------------------------------

    #[test]
    fn test_commitment_migration_produces_valid_commitments() {
        let data = b"important state data";
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_commitment(data, &domain, &policy).unwrap();

        // Both commitments should be valid 32-byte hashes
        assert_eq!(migration.original_commitment.0.len(), 32);
        assert_eq!(migration.migrated_commitment.0.len(), 32);
        // They should differ (different algorithms)
        assert_ne!(migration.original_commitment, migration.migrated_commitment);
        assert!(!migration.verified);
    }

    #[test]
    fn test_commitment_migration_original_matches_source_algorithm() {
        let data = b"test data";
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_commitment(data, &domain, &policy).unwrap();

        let expected_original = domain_hash_with_algorithm(HashAlgorithm::Sha3_256, &domain, data);
        let expected_migrated = domain_hash_with_algorithm(HashAlgorithm::Blake3, &domain, data);

        assert_eq!(migration.original_commitment, expected_original);
        assert_eq!(migration.migrated_commitment, expected_migrated);
    }

    #[test]
    fn test_commitment_migration_verification_succeeds() {
        let data = b"verify me";
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_commitment(data, &domain, &policy).unwrap();
        assert!(verify_commitment_migration(data, &domain, &migration));
    }

    #[test]
    fn test_commitment_migration_verification_fails_for_tampered_data() {
        let data = b"original data";
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_commitment(data, &domain, &policy).unwrap();
        // Verify with different data — should fail
        assert!(!verify_commitment_migration(
            b"tampered data",
            &domain,
            &migration
        ));
    }

    #[test]
    fn test_commitment_migration_verification_fails_for_wrong_domain() {
        let data = b"domain test";
        let domain = test_domain();
        let other_domain = create_domain_tag(b"other::domain");
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_commitment(data, &domain, &policy).unwrap();
        assert!(!verify_commitment_migration(
            data,
            &other_domain,
            &migration
        ));
    }

    // -- Signature migration -------------------------------------------------

    #[test]
    fn test_signature_migration_re_signs_correctly() {
        let old_kp = generate_hybrid_keypair();
        let new_kp = generate_hybrid_keypair();
        let new_key_id = derive_key_id(&new_kp.public_key);
        let domain = test_domain();
        let message = b"migrate this signature";
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_signature(
            message,
            &domain,
            &old_kp.signing_key,
            &new_kp.signing_key,
            new_key_id.clone(),
            policy,
        )
        .unwrap();

        // Both signatures should be present and different (different keys)
        assert_ne!(
            migration.original_signature.classical_sig,
            migration.migrated_signature.classical_sig
        );
        assert_eq!(migration.signing_key_id, new_key_id);
    }

    #[test]
    fn test_signature_migration_preserves_key_id() {
        let old_kp = generate_hybrid_keypair();
        let new_kp = generate_hybrid_keypair();
        let new_key_id = derive_key_id(&new_kp.public_key);
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_signature(
            b"msg",
            &domain,
            &old_kp.signing_key,
            &new_kp.signing_key,
            new_key_id.clone(),
            policy,
        )
        .unwrap();

        assert_eq!(migration.signing_key_id, new_key_id);
    }

    // -- Witness archive store -----------------------------------------------

    #[test]
    fn test_witness_archive_store_and_retrieve() {
        let mut store = WitnessArchiveStore::new();
        let witness = b"witness data bytes".to_vec();
        let proof_commit = Hash([1u8; 32]);

        let id = store.archive(
            witness.clone(),
            proof_commit.clone(),
            HashAlgorithm::Sha3_256,
            5000,
            None,
        );

        let entry = store.get(&id).unwrap();
        assert_eq!(entry.witness_data, witness);
        assert_eq!(entry.proof_commitment, proof_commit);
        assert_eq!(entry.algorithm_used, HashAlgorithm::Sha3_256);
        assert_eq!(entry.archived_at, 5000);
        assert_eq!(entry.expiry, None);
    }

    #[test]
    fn test_witness_archive_deterministic_id() {
        let mut store = WitnessArchiveStore::new();
        let witness = b"same data".to_vec();
        let commit = Hash([2u8; 32]);

        let id1 = store.archive(
            witness.clone(),
            commit.clone(),
            HashAlgorithm::Blake3,
            100,
            None,
        );
        let id2 = store.archive(witness, commit, HashAlgorithm::Blake3, 200, None);

        // Same witness data produces same ID (deterministic hash)
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_witness_archive_purge_expired() {
        let mut store = WitnessArchiveStore::new();
        let commit = Hash([3u8; 32]);

        // Archive with expiry at t=1000
        store.archive(
            b"expires".to_vec(),
            commit.clone(),
            HashAlgorithm::Sha3_256,
            0,
            Some(1000),
        );
        // Archive with no expiry
        store.archive(
            b"permanent".to_vec(),
            commit.clone(),
            HashAlgorithm::Blake3,
            0,
            None,
        );
        // Archive with expiry at t=2000
        store.archive(
            b"later".to_vec(),
            commit,
            HashAlgorithm::Poseidon,
            0,
            Some(2000),
        );

        assert_eq!(store.len(), 3);

        // Purge at t=1500 — should remove the first entry
        let purged = store.purge_expired(1500);
        assert_eq!(purged, 1);
        assert_eq!(store.len(), 2);

        // Purge at t=3000 — should remove the third entry
        let purged = store.purge_expired(3000);
        assert_eq!(purged, 1);
        assert_eq!(store.len(), 1); // only the permanent one remains
    }

    #[test]
    fn test_witness_archive_get_nonexistent() {
        let store = WitnessArchiveStore::new();
        assert!(store.get(&Hash([0u8; 32])).is_none());
    }

    #[test]
    fn test_witness_archive_empty() {
        let store = WitnessArchiveStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    // -- Proof migration -----------------------------------------------------

    #[test]
    fn test_proof_migration_archives_witness_and_produces_commitments() {
        let mut archive = WitnessArchiveStore::new();
        let domain = test_domain();
        let proof_data = b"proof bytes";
        let witness_data = b"witness for re-proving".to_vec();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_proof_commitment(
            proof_data,
            &domain,
            witness_data.clone(),
            &mut archive,
            &policy,
            2000,
        )
        .unwrap();

        // Witness should be archived
        assert_eq!(archive.len(), 1);
        let archived = archive.get(&migration.witness_archive_id).unwrap();
        assert_eq!(archived.witness_data, witness_data);

        // Commitments should differ (different algorithms)
        assert_ne!(
            migration.original_proof_commitment,
            migration.migrated_proof_commitment
        );

        // Original commitment should match direct computation
        let expected_original =
            domain_hash_with_algorithm(HashAlgorithm::Sha3_256, &domain, proof_data);
        assert_eq!(migration.original_proof_commitment, expected_original);
    }

    #[test]
    fn test_proof_migration_witness_has_no_expiry() {
        let mut archive = WitnessArchiveStore::new();
        let domain = test_domain();
        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);

        let migration = migrate_proof_commitment(
            b"proof",
            &domain,
            b"witness".to_vec(),
            &mut archive,
            &policy,
            3000,
        )
        .unwrap();

        let archived = archive.get(&migration.witness_archive_id).unwrap();
        assert_eq!(
            archived.expiry, None,
            "witness archives should have no expiry"
        );
    }

    // -- CryptoAgility -------------------------------------------------------

    #[test]
    fn test_crypto_agility_new_includes_default() {
        let agility = CryptoAgility::new(HashAlgorithm::Blake3);
        assert!(agility.is_supported(&HashAlgorithm::Blake3));
        assert_eq!(agility.current_default, HashAlgorithm::Blake3);
    }

    #[test]
    fn test_crypto_agility_add_algorithm() {
        let mut agility = CryptoAgility::new(HashAlgorithm::Sha3_256);
        assert!(!agility.is_supported(&HashAlgorithm::Blake3));

        agility.add_algorithm(HashAlgorithm::Blake3);
        assert!(agility.is_supported(&HashAlgorithm::Blake3));
    }

    #[test]
    fn test_crypto_agility_add_duplicate_ignored() {
        let mut agility = CryptoAgility::new(HashAlgorithm::Sha3_256);
        agility.add_algorithm(HashAlgorithm::Sha3_256);
        assert_eq!(agility.supported_algorithms.len(), 1);
    }

    #[test]
    fn test_crypto_agility_set_default_supported() {
        let mut agility = CryptoAgility::new(HashAlgorithm::Sha3_256);
        agility.add_algorithm(HashAlgorithm::Blake3);

        assert!(agility.set_default(HashAlgorithm::Blake3).is_ok());
        assert_eq!(agility.current_default, HashAlgorithm::Blake3);
    }

    #[test]
    fn test_crypto_agility_set_default_unsupported_fails() {
        let mut agility = CryptoAgility::new(HashAlgorithm::Sha3_256);

        let result = agility.set_default(HashAlgorithm::Poseidon);
        assert!(result.is_err());
        // Default should remain unchanged
        assert_eq!(agility.current_default, HashAlgorithm::Sha3_256);
    }

    #[test]
    fn test_crypto_agility_migration_policies() {
        let mut agility = CryptoAgility::new(HashAlgorithm::Sha3_256);
        assert!(agility.active_migrations().is_empty());

        let policy = test_policy(HashAlgorithm::Sha3_256, HashAlgorithm::Blake3);
        agility.add_migration_policy(policy);

        assert_eq!(agility.active_migrations().len(), 1);
        assert_eq!(agility.active_migrations()[0].reason, "test migration");
    }

    #[test]
    fn test_crypto_agility_is_supported_false_for_unknown() {
        let agility = CryptoAgility::new(HashAlgorithm::Sha3_256);
        assert!(!agility.is_supported(&HashAlgorithm::Poseidon));
    }
}
