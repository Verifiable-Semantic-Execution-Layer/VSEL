//! Shared type definitions for the VSEL protocol.
//!
//! Derived from: FORMAL_SPECIFICATION.md §2-§3, STATE_MACHINE.md §2,
//! ECONOMIC_INVARIANTS.md §3, CRYPTOGRAPHIC_MODEL.md, AUDIT_EVIDENCE_MODEL.md.
//!
//! All types use `BTreeMap` for deterministic ordering.
//! All types derive `Clone`, `Debug`, `PartialEq`, `Eq` unless otherwise noted.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Base types
// ---------------------------------------------------------------------------

/// 32-byte account identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(pub [u8; 32]);

/// Byte-vector storage key (deterministic ordering via `Ord`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageKey(pub Vec<u8>);

/// Byte-vector storage value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StorageValue(pub Vec<u8>);

/// 32-byte cryptographic hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

/// Domain separation tag — wraps a `Hash` for domain-separated cryptographic operations.
/// Used in `Hash(domain | data)` to prevent cross-protocol attacks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainTag(pub Hash);

/// Protocol version with semantic versioning.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

// ---------------------------------------------------------------------------
// Cryptographic types — hybrid classical + PQC
// Derived from: CRYPTOGRAPHIC_MODEL.md, LONG_TERM_SECURITY_MODEL.md
// ---------------------------------------------------------------------------

/// Hybrid public key — both classical (Ed25519) and PQC (ML-DSA/Falcon) components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// Ed25519 public key bytes.
    pub classical: Vec<u8>,
    /// ML-DSA/Falcon public key bytes.
    pub pqc: Vec<u8>,
}

/// Hybrid signing key — mirrors the public key structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSigningKey {
    /// Ed25519 signing key bytes.
    pub classical: Vec<u8>,
    /// ML-DSA/Falcon signing key bytes.
    pub pqc: Vec<u8>,
}

/// Hybrid signature — both classical and PQC signatures must verify for acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature bytes.
    pub classical_sig: Vec<u8>,
    /// ML-DSA/Falcon signature bytes.
    pub pqc_sig: Vec<u8>,
}

/// Hybrid key pair — bundles signing and public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKeyPair {
    pub signing_key: HybridSigningKey,
    pub public_key: HybridPublicKey,
}

// ---------------------------------------------------------------------------
// Economic types — ECONOMIC_INVARIANTS.md §3
// ---------------------------------------------------------------------------

/// Asset pair for price oracle lookups (e.g. "ETH"/"USD").
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetPair {
    pub base: String,
    pub quote: String,
}

/// Price value (u128 for precision without floating-point).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Price(pub u128);

/// 32-byte entity identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId(pub [u8; 32]);

/// Exposure limit for an entity (u128).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExposureLimit(pub u128);

/// 32-byte pool identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PoolId(pub [u8; 32]);

/// Liquidity threshold for a pool (u128).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiquidityThreshold(pub u128);

/// Position type for collateral requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PositionType {
    Long,
    Short,
    Neutral,
}

/// Collateral ratio in basis points (u128).
/// 10_000 basis points = 100%.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CollateralRatio(pub u128);

// ---------------------------------------------------------------------------
// Audit types — AUDIT_EVIDENCE_MODEL.md
// ---------------------------------------------------------------------------

/// Severity classification for audit findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Immediate halt.
    Critical,
    /// Block phase.
    High,
    /// Remediate before phase completion.
    Medium,
    /// Track.
    Low,
    /// Document.
    Info,
}

/// Evidence category — the six audit evidence categories (CAT-1 through CAT-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceCategory {
    /// CAT-1: Formal verification evidence.
    FormalVerification,
    /// CAT-2: Differential testing evidence.
    DifferentialTesting,
    /// CAT-3: Constraint analysis evidence.
    ConstraintAnalysis,
    /// CAT-4: Adversarial testing evidence.
    AdversarialTesting,
    /// CAT-5: Code review evidence.
    CodeReview,
    /// CAT-6: Compliance evidence.
    Compliance,
}

/// Verification method used to produce audit evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationMethod {
    /// TLA+ / Lean 4 model checking.
    ModelChecking,
    /// Lean 4 theorem proving.
    TheoremProving,
    /// Differential testing (Rust vs SIR interpreter).
    DifferentialTesting,
    /// Adversarial / fuzz testing.
    AdversarialTesting,
    /// Manual code review.
    CodeReview,
    /// Property-based testing (proptest).
    PropertyTesting,
}

// ---------------------------------------------------------------------------
// Supporting types used by other modules
// ---------------------------------------------------------------------------

/// System-wide data stored in canonical state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemData {
    /// Current protocol version.
    pub protocol_version: ProtocolVersion,
    /// Total supply tracked at the system level.
    pub total_supply: u128,
    /// Additional system-level parameters.
    pub parameters: BTreeMap<String, Vec<u8>>,
}

/// Fee schedule for economic context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSchedule {
    /// Base fee per transaction.
    pub base_fee: u128,
    /// Fee rate in basis points.
    pub fee_rate_bps: u128,
    /// Per-transition-class fee overrides.
    pub overrides: BTreeMap<String, u128>,
}

/// Epoch-level accounting data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochAccounting {
    /// Current epoch number.
    pub epoch: u64,
    /// Total fees collected in this epoch.
    pub total_fees_collected: u128,
    /// Total transactions processed in this epoch.
    pub total_transactions: u64,
}

/// Economic parameters for the system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicParameters {
    /// Maximum leverage ratio (basis points).
    pub max_leverage_bps: u128,
    /// Minimum collateral ratio (basis points).
    pub min_collateral_ratio_bps: u128,
    /// Dust threshold — minimum meaningful value.
    pub dust_threshold: u128,
    /// Additional named parameters.
    pub extra: BTreeMap<String, u128>,
}

/// Output event produced by a transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputEvent {
    /// Event type identifier.
    pub event_type: String,
    /// Serialized event data.
    pub data: Vec<u8>,
}

/// Semantic payload of an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Payload type identifier.
    pub payload_type: String,
    /// Serialized payload data.
    pub data: Vec<u8>,
}

/// Auxiliary data attached to an input.
/// Must NOT influence semantic outcome (THM-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxiliaryData {
    /// Opaque auxiliary bytes — ignored by execution semantics.
    pub data: Vec<u8>,
}
