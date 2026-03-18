//! Key lifecycle management for the VSEL protocol.
//!
//! Derived from: CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md.
//!
//! Provides:
//! - Secure key generation with entropy backing (OS randomness via `ed25519-dalek`)
//! - Domain-separated key generation using `DomainTag`
//! - Explicit traceable key rotation with successor chaining
//! - Enforceable observable key revocation
//! - Temporal sensitivity classification: T1 ephemeral, T2 session, T3 archival, T4 permanent
//!
//! Requirements: 10.6 (key lifecycle management), 10.7 (temporal classification).

use std::collections::BTreeMap;

use thiserror::Error;
use vsel_core::types::{DomainTag, Hash, HybridKeyPair, HybridPublicKey};

use crate::domain::{create_domain_tag, domain_hash, DOMAIN_KEY_DERIVATION};
use crate::hash::TemporalClass;
use crate::signatures::generate_hybrid_keypair;

// ---------------------------------------------------------------------------
// Key identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a managed key, derived from public key material.
pub type KeyId = Hash;

// ---------------------------------------------------------------------------
// Key status
// ---------------------------------------------------------------------------

/// Lifecycle status of a managed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is active and may be used for signing/verification.
    Active,
    /// Key has been rotated; `successor` is the replacement key.
    Rotated { successor: KeyId },
    /// Key has been revoked with a reason and timestamp.
    Revoked { reason: String, timestamp: u64 },
    /// Key has expired based on its temporal class.
    Expired,
}

// ---------------------------------------------------------------------------
// Key metadata
// ---------------------------------------------------------------------------

/// Metadata associated with a managed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Unique identifier derived from public key material.
    pub key_id: KeyId,
    /// Temporal sensitivity classification (T1–T4).
    pub temporal_class: TemporalClass,
    /// Creation timestamp (seconds since epoch).
    pub created_at: u64,
    /// Domain this key was generated for.
    pub domain: DomainTag,
    /// Current lifecycle status.
    pub status: KeyStatus,
    /// Rotation generation counter (starts at 0).
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// Managed key
// ---------------------------------------------------------------------------

/// A key pair bundled with lifecycle metadata.
#[derive(Clone, Debug)]
pub struct ManagedKey {
    /// The underlying hybrid key pair.
    pub keypair: HybridKeyPair,
    /// Lifecycle metadata.
    pub metadata: KeyMetadata,
}

// ---------------------------------------------------------------------------
// Key errors
// ---------------------------------------------------------------------------

/// Errors arising from key lifecycle operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// The requested key was not found in the store.
    #[error("key not found")]
    KeyNotFound,
    /// The key has already been revoked.
    #[error("key already revoked")]
    KeyAlreadyRevoked,
    /// The key has already been rotated.
    #[error("key already rotated")]
    KeyAlreadyRotated,
    /// The key has expired.
    #[error("key expired")]
    KeyExpired,
}

// ---------------------------------------------------------------------------
// Temporal expiration constants
// ---------------------------------------------------------------------------

/// T1 ephemeral: expires after 1 hour (3600 seconds).
const T1_LIFETIME_SECS: u64 = 3_600;
/// T2 session: expires after 24 hours (86400 seconds).
const T2_LIFETIME_SECS: u64 = 86_400;
/// T3 archival: expires after 365 days (31_536_000 seconds).
const T3_LIFETIME_SECS: u64 = 365 * 24 * 3_600;

// ---------------------------------------------------------------------------
// Key ID derivation
// ---------------------------------------------------------------------------

/// Derive a `KeyId` from hybrid public key material using domain-separated hashing.
///
/// `KeyId = DomainHash(DOMAIN_KEY_DERIVATION, classical_pk || pqc_pk)`
pub fn derive_key_id(public_key: &HybridPublicKey) -> KeyId {
    let tag = create_domain_tag(DOMAIN_KEY_DERIVATION);
    let mut material = Vec::with_capacity(public_key.classical.len() + public_key.pqc.len());
    material.extend_from_slice(&public_key.classical);
    material.extend_from_slice(&public_key.pqc);
    domain_hash(&tag, &material)
}

// ---------------------------------------------------------------------------
// Temporal expiration
// ---------------------------------------------------------------------------

/// Check whether a key has expired based on its temporal class and the current time.
///
/// - T1 ephemeral: expires after 1 hour
/// - T2 session: expires after 24 hours
/// - T3 archival: expires after 365 days
/// - T4 permanent: never expires
pub fn is_expired(metadata: &KeyMetadata, current_time: u64) -> bool {
    let lifetime = match metadata.temporal_class {
        TemporalClass::T1Ephemeral => Some(T1_LIFETIME_SECS),
        TemporalClass::T2Session => Some(T2_LIFETIME_SECS),
        TemporalClass::T3Archival => Some(T3_LIFETIME_SECS),
        TemporalClass::T4Permanent => None,
    };
    match lifetime {
        Some(max) => current_time.saturating_sub(metadata.created_at) > max,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Managed key generation
// ---------------------------------------------------------------------------

/// Generate a new managed key with domain separation and temporal classification.
///
/// Uses OS entropy via `generate_hybrid_keypair()` for secure key generation.
pub fn generate_managed_key(
    temporal_class: TemporalClass,
    domain: &DomainTag,
    timestamp: u64,
) -> ManagedKey {
    let keypair = generate_hybrid_keypair();
    let key_id = derive_key_id(&keypair.public_key);
    let metadata = KeyMetadata {
        key_id,
        temporal_class,
        created_at: timestamp,
        domain: domain.clone(),
        status: KeyStatus::Active,
        generation: 0,
    };
    ManagedKey { keypair, metadata }
}

// ---------------------------------------------------------------------------
// Key store
// ---------------------------------------------------------------------------

/// In-memory key store managing key lifecycle operations.
#[derive(Debug, Default)]
pub struct KeyStore {
    keys: BTreeMap<KeyId, ManagedKey>,
}

impl KeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Generate a new managed key and insert it into the store.
    /// Returns the `KeyId` of the newly generated key.
    pub fn generate(
        &mut self,
        temporal_class: TemporalClass,
        domain: &DomainTag,
        timestamp: u64,
    ) -> KeyId {
        let managed = generate_managed_key(temporal_class, domain, timestamp);
        let id = managed.metadata.key_id.clone();
        self.keys.insert(id.clone(), managed);
        id
    }

    /// Rotate a key: generate a new successor and mark the old key as `Rotated`.
    ///
    /// The new key inherits the temporal class and domain of the predecessor,
    /// with its generation counter incremented.
    pub fn rotate(&mut self, key_id: &KeyId, timestamp: u64) -> Result<KeyId, KeyError> {
        let old = self.keys.get(key_id).ok_or(KeyError::KeyNotFound)?;
        match &old.metadata.status {
            KeyStatus::Revoked { .. } => return Err(KeyError::KeyAlreadyRevoked),
            KeyStatus::Rotated { .. } => return Err(KeyError::KeyAlreadyRotated),
            KeyStatus::Expired => return Err(KeyError::KeyExpired),
            KeyStatus::Active => {}
        }

        let temporal_class = old.metadata.temporal_class;
        let domain = old.metadata.domain.clone();
        let old_generation = old.metadata.generation;

        // Generate successor
        let keypair = generate_hybrid_keypair();
        let new_id = derive_key_id(&keypair.public_key);
        let new_metadata = KeyMetadata {
            key_id: new_id.clone(),
            temporal_class,
            created_at: timestamp,
            domain,
            status: KeyStatus::Active,
            generation: old_generation + 1,
        };
        let new_managed = ManagedKey {
            keypair,
            metadata: new_metadata,
        };

        // Mark old key as rotated
        self.keys.get_mut(key_id).unwrap().metadata.status = KeyStatus::Rotated {
            successor: new_id.clone(),
        };

        self.keys.insert(new_id.clone(), new_managed);
        Ok(new_id)
    }

    /// Revoke a key with a reason and timestamp.
    pub fn revoke(
        &mut self,
        key_id: &KeyId,
        reason: String,
        timestamp: u64,
    ) -> Result<(), KeyError> {
        let key = self.keys.get_mut(key_id).ok_or(KeyError::KeyNotFound)?;
        match &key.metadata.status {
            KeyStatus::Revoked { .. } => return Err(KeyError::KeyAlreadyRevoked),
            KeyStatus::Rotated { .. } => return Err(KeyError::KeyAlreadyRotated),
            KeyStatus::Expired => return Err(KeyError::KeyExpired),
            KeyStatus::Active => {}
        }
        key.metadata.status = KeyStatus::Revoked { reason, timestamp };
        Ok(())
    }

    /// Look up a key by its ID.
    pub fn get(&self, key_id: &KeyId) -> Option<&ManagedKey> {
        self.keys.get(key_id)
    }

    /// Look up a key only if it is currently `Active`.
    pub fn get_active(&self, key_id: &KeyId) -> Option<&ManagedKey> {
        self.keys
            .get(key_id)
            .filter(|k| k.metadata.status == KeyStatus::Active)
    }

    /// Check whether a key is active.
    pub fn is_active(&self, key_id: &KeyId) -> bool {
        self.get_active(key_id).is_some()
    }

    /// Trace the full rotation chain starting from a given key.
    ///
    /// Returns a vector of `KeyId`s beginning with the provided key and
    /// following successor links until a non-rotated key is reached.
    pub fn rotation_chain(&self, key_id: &KeyId) -> Vec<KeyId> {
        let mut chain = Vec::new();
        let mut current = key_id.clone();
        loop {
            chain.push(current.clone());
            match self.keys.get(&current) {
                Some(k) => match &k.metadata.status {
                    KeyStatus::Rotated { successor } => {
                        current = successor.clone();
                    }
                    _ => break,
                },
                None => break,
            }
        }
        chain
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::create_domain_tag;

    fn test_domain() -> DomainTag {
        create_domain_tag(b"test::key_lifecycle")
    }

    // -- Key generation ------------------------------------------------------

    #[test]
    fn test_generate_managed_key_produces_active_key() {
        let domain = test_domain();
        let mk = generate_managed_key(TemporalClass::T2Session, &domain, 1000);
        assert_eq!(mk.metadata.status, KeyStatus::Active);
        assert_eq!(mk.metadata.temporal_class, TemporalClass::T2Session);
        assert_eq!(mk.metadata.created_at, 1000);
        assert_eq!(mk.metadata.generation, 0);
        assert_eq!(mk.metadata.domain, domain);
    }

    #[test]
    fn test_generate_managed_key_id_matches_public_key() {
        let mk = generate_managed_key(TemporalClass::T1Ephemeral, &test_domain(), 0);
        let expected_id = derive_key_id(&mk.keypair.public_key);
        assert_eq!(mk.metadata.key_id, expected_id);
    }

    #[test]
    fn test_generate_two_keys_have_different_ids() {
        let domain = test_domain();
        let mk1 = generate_managed_key(TemporalClass::T1Ephemeral, &domain, 0);
        let mk2 = generate_managed_key(TemporalClass::T1Ephemeral, &domain, 0);
        assert_ne!(mk1.metadata.key_id, mk2.metadata.key_id);
    }

    // -- derive_key_id -------------------------------------------------------

    #[test]
    fn test_derive_key_id_deterministic() {
        let kp = generate_hybrid_keypair();
        let id1 = derive_key_id(&kp.public_key);
        let id2 = derive_key_id(&kp.public_key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_key_id_different_keys_differ() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        assert_ne!(derive_key_id(&kp1.public_key), derive_key_id(&kp2.public_key));
    }

    // -- KeyStore generate ---------------------------------------------------

    #[test]
    fn test_keystore_generate_and_get() {
        let mut store = KeyStore::new();
        let domain = test_domain();
        let id = store.generate(TemporalClass::T3Archival, &domain, 500);
        let key = store.get(&id).unwrap();
        assert_eq!(key.metadata.status, KeyStatus::Active);
        assert_eq!(key.metadata.temporal_class, TemporalClass::T3Archival);
    }

    // -- Key rotation --------------------------------------------------------

    #[test]
    fn test_rotate_creates_successor() {
        let mut store = KeyStore::new();
        let domain = test_domain();
        let old_id = store.generate(TemporalClass::T2Session, &domain, 100);
        let new_id = store.rotate(&old_id, 200).unwrap();

        // Old key is now Rotated
        let old = store.get(&old_id).unwrap();
        assert_eq!(
            old.metadata.status,
            KeyStatus::Rotated {
                successor: new_id.clone()
            }
        );

        // New key is Active with incremented generation
        let new_key = store.get(&new_id).unwrap();
        assert_eq!(new_key.metadata.status, KeyStatus::Active);
        assert_eq!(new_key.metadata.generation, 1);
        assert_eq!(new_key.metadata.created_at, 200);
    }

    #[test]
    fn test_rotate_inherits_temporal_class_and_domain() {
        let mut store = KeyStore::new();
        let domain = test_domain();
        let old_id = store.generate(TemporalClass::T4Permanent, &domain, 0);
        let new_id = store.rotate(&old_id, 100).unwrap();
        let new_key = store.get(&new_id).unwrap();
        assert_eq!(new_key.metadata.temporal_class, TemporalClass::T4Permanent);
        assert_eq!(new_key.metadata.domain, domain);
    }

    #[test]
    fn test_cannot_rotate_revoked_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T1Ephemeral, &test_domain(), 0);
        store.revoke(&id, "compromised".into(), 10).unwrap();
        assert_eq!(store.rotate(&id, 20), Err(KeyError::KeyAlreadyRevoked));
    }

    #[test]
    fn test_cannot_rotate_already_rotated_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T1Ephemeral, &test_domain(), 0);
        store.rotate(&id, 10).unwrap();
        assert_eq!(store.rotate(&id, 20), Err(KeyError::KeyAlreadyRotated));
    }

    #[test]
    fn test_rotate_nonexistent_key() {
        let mut store = KeyStore::new();
        let fake_id = Hash([0u8; 32]);
        assert_eq!(store.rotate(&fake_id, 0), Err(KeyError::KeyNotFound));
    }

    // -- Key revocation ------------------------------------------------------

    #[test]
    fn test_revoke_marks_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        store.revoke(&id, "policy change".into(), 50).unwrap();
        let key = store.get(&id).unwrap();
        assert_eq!(
            key.metadata.status,
            KeyStatus::Revoked {
                reason: "policy change".into(),
                timestamp: 50
            }
        );
    }

    #[test]
    fn test_cannot_revoke_already_revoked_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T1Ephemeral, &test_domain(), 0);
        store.revoke(&id, "first".into(), 10).unwrap();
        assert_eq!(
            store.revoke(&id, "second".into(), 20),
            Err(KeyError::KeyAlreadyRevoked)
        );
    }

    #[test]
    fn test_revoke_nonexistent_key() {
        let mut store = KeyStore::new();
        let fake_id = Hash([0u8; 32]);
        assert_eq!(
            store.revoke(&fake_id, "reason".into(), 0),
            Err(KeyError::KeyNotFound)
        );
    }

    // -- get_active ----------------------------------------------------------

    #[test]
    fn test_get_active_returns_active_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        assert!(store.get_active(&id).is_some());
    }

    #[test]
    fn test_get_active_returns_none_for_rotated() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        store.rotate(&id, 10).unwrap();
        assert!(store.get_active(&id).is_none());
    }

    #[test]
    fn test_get_active_returns_none_for_revoked() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        store.revoke(&id, "gone".into(), 10).unwrap();
        assert!(store.get_active(&id).is_none());
    }

    #[test]
    fn test_is_active() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        assert!(store.is_active(&id));
        store.revoke(&id, "bye".into(), 10).unwrap();
        assert!(!store.is_active(&id));
    }

    // -- Rotation chain ------------------------------------------------------

    #[test]
    fn test_rotation_chain_single_key() {
        let mut store = KeyStore::new();
        let id = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        let chain = store.rotation_chain(&id);
        assert_eq!(chain, vec![id]);
    }

    #[test]
    fn test_rotation_chain_multiple_rotations() {
        let mut store = KeyStore::new();
        let id0 = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        let id1 = store.rotate(&id0, 10).unwrap();
        let id2 = store.rotate(&id1, 20).unwrap();

        let chain = store.rotation_chain(&id0);
        assert_eq!(chain, vec![id0, id1, id2]);
    }

    #[test]
    fn test_rotation_chain_from_middle() {
        let mut store = KeyStore::new();
        let id0 = store.generate(TemporalClass::T2Session, &test_domain(), 0);
        let id1 = store.rotate(&id0, 10).unwrap();
        let id2 = store.rotate(&id1, 20).unwrap();

        // Starting from id1 should give [id1, id2]
        let chain = store.rotation_chain(&id1);
        assert_eq!(chain, vec![id1, id2]);
    }

    // -- Temporal expiration -------------------------------------------------

    #[test]
    fn test_t1_ephemeral_expires_after_1_hour() {
        let meta = KeyMetadata {
            key_id: Hash([0u8; 32]),
            temporal_class: TemporalClass::T1Ephemeral,
            created_at: 1000,
            domain: test_domain(),
            status: KeyStatus::Active,
            generation: 0,
        };
        // Not expired at creation + 3600
        assert!(!is_expired(&meta, 1000 + T1_LIFETIME_SECS));
        // Expired after 3600
        assert!(is_expired(&meta, 1000 + T1_LIFETIME_SECS + 1));
    }

    #[test]
    fn test_t2_session_expires_after_24_hours() {
        let meta = KeyMetadata {
            key_id: Hash([0u8; 32]),
            temporal_class: TemporalClass::T2Session,
            created_at: 0,
            domain: test_domain(),
            status: KeyStatus::Active,
            generation: 0,
        };
        assert!(!is_expired(&meta, T2_LIFETIME_SECS));
        assert!(is_expired(&meta, T2_LIFETIME_SECS + 1));
    }

    #[test]
    fn test_t3_archival_expires_after_365_days() {
        let meta = KeyMetadata {
            key_id: Hash([0u8; 32]),
            temporal_class: TemporalClass::T3Archival,
            created_at: 0,
            domain: test_domain(),
            status: KeyStatus::Active,
            generation: 0,
        };
        assert!(!is_expired(&meta, T3_LIFETIME_SECS));
        assert!(is_expired(&meta, T3_LIFETIME_SECS + 1));
    }

    #[test]
    fn test_t4_permanent_never_expires() {
        let meta = KeyMetadata {
            key_id: Hash([0u8; 32]),
            temporal_class: TemporalClass::T4Permanent,
            created_at: 0,
            domain: test_domain(),
            status: KeyStatus::Active,
            generation: 0,
        };
        assert!(!is_expired(&meta, u64::MAX));
    }

    // -- Domain metadata -----------------------------------------------------

    #[test]
    fn test_keys_with_different_domains_have_different_metadata() {
        let domain_a = create_domain_tag(b"domain_alpha");
        let domain_b = create_domain_tag(b"domain_beta");
        let mk_a = generate_managed_key(TemporalClass::T2Session, &domain_a, 0);
        let mk_b = generate_managed_key(TemporalClass::T2Session, &domain_b, 0);
        assert_ne!(mk_a.metadata.domain, mk_b.metadata.domain);
    }
}
