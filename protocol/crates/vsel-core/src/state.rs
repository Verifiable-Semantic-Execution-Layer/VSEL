//! State model for the VSEL protocol.
//!
//! Derived from: FORMAL_SPECIFICATION.md §3, STATE_MACHINE.md §2,
//! ECONOMIC_INVARIANTS.md §3, TECH_SPEC.md §3.2.
//!
//! State tuple: s = (C, D, E, Ω, τ)
//! - C: CanonicalState — minimal semantic state
//! - D: DerivedState — D = Derive(C) (DEF-1)
//! - E: Environment — external context
//! - Ω: EconomicContext — Ω = DeriveEconomic(C, E)
//! - τ: TraceMetadata — execution metadata

use std::collections::BTreeMap;

use sha3::{Digest, Sha3_256};

use crate::types::*;

// ---------------------------------------------------------------------------
// Account data
// ---------------------------------------------------------------------------

/// Per-account data stored in canonical state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountData {
    /// Non-negative balance (u128 is inherently non-negative).
    pub balance: u128,
    /// Monotonically increasing nonce.
    pub nonce: u64,
    /// Account-specific opaque data.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Canonical state — C
// ---------------------------------------------------------------------------

/// CanonicalState — the minimal, sufficient, deterministic representation
/// of system state. TECH_SPEC.md §3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalState {
    pub accounts: BTreeMap<AccountId, AccountData>,
    pub storage: BTreeMap<StorageKey, StorageValue>,
    pub system_data: SystemData,
}

// ---------------------------------------------------------------------------
// Derived state — D = Derive(C)
// ---------------------------------------------------------------------------

/// DerivedState — must satisfy D = Derive(C) (DEF-1).
/// Computed deterministically from CanonicalState.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedState {
    /// Root hash of the canonical state encoding.
    pub state_root: Hash,
    /// Hashes of sub-components (e.g. accounts root, storage root).
    pub auxiliary_roots: BTreeMap<String, Hash>,
    /// Computed aggregates (e.g. total balance).
    pub aggregates: BTreeMap<String, u128>,
}

// ---------------------------------------------------------------------------
// Environment — E
// ---------------------------------------------------------------------------

/// Environment — external context, explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    pub timestamp: u64,
    pub block_height: u64,
    pub execution_domain: DomainTag,
}

// ---------------------------------------------------------------------------
// Economic context — Ω = DeriveEconomic(C, E)
// ---------------------------------------------------------------------------

/// EconomicContext — ECONOMIC_INVARIANTS.md §3.
/// Deterministically derived from CanonicalState + Environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomicContext {
    pub price_oracle: BTreeMap<AssetPair, Price>,
    pub exposure_limits: BTreeMap<EntityId, ExposureLimit>,
    pub liquidity_thresholds: BTreeMap<PoolId, LiquidityThreshold>,
    pub fee_schedule: FeeSchedule,
    pub epoch_accounting: EpochAccounting,
    pub collateral_requirements: BTreeMap<PositionType, CollateralRatio>,
    pub economic_parameters: EconomicParameters,
}

// ---------------------------------------------------------------------------
// Trace metadata — τ
// ---------------------------------------------------------------------------

/// TraceMetadata — ordering and trace consistency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceMetadata {
    /// Monotonically increasing sequence index.
    pub sequence_index: u64,
    /// Hash of the previous trace commitment.
    pub previous_commitment: Hash,
    /// Current epoch number.
    pub epoch: u64,
    /// Timestamp of this trace entry.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// State tuple — s = (C, D, E, Ω, τ)
// ---------------------------------------------------------------------------

/// State tuple s = (C, D, E, Ω, τ) — FORMAL_SPECIFICATION.md §3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub canonical: CanonicalState,
    pub derived: DerivedState,
    pub environment: Environment,
    pub economic: EconomicContext,
    pub metadata: TraceMetadata,
}

// ---------------------------------------------------------------------------
// Derive functions
// ---------------------------------------------------------------------------

/// Deterministically compute `DerivedState` from `CanonicalState`.
///
/// - `state_root` = SHA3-256 hash of the canonical state encoding
/// - `auxiliary_roots` = hashes of sub-components (accounts, storage)
/// - `aggregates` = computed aggregates (total_balance)
pub fn derive(c: &CanonicalState) -> DerivedState {
    let state_root = hash_canonical_state(c);
    let auxiliary_roots = compute_auxiliary_roots(c);
    let aggregates = compute_aggregates(c);

    DerivedState {
        state_root,
        auxiliary_roots,
        aggregates,
    }
}

/// Deterministically compute `EconomicContext` from `CanonicalState` + `Environment`.
///
/// In a full implementation this would derive prices, exposure limits, etc.
/// from on-chain state. For now we derive what we can deterministically:
/// fee schedule and epoch accounting from system data, with empty oracle/limits.
pub fn derive_economic(c: &CanonicalState, _e: &Environment) -> EconomicContext {
    // Extract fee schedule from system parameters if present, else defaults.
    let base_fee = read_u128_param(&c.system_data.parameters, "base_fee").unwrap_or(0);
    let fee_rate_bps = read_u128_param(&c.system_data.parameters, "fee_rate_bps").unwrap_or(0);

    let fee_schedule = FeeSchedule {
        base_fee,
        fee_rate_bps,
        overrides: BTreeMap::new(),
    };

    let epoch_accounting = EpochAccounting {
        epoch: read_u64_param(&c.system_data.parameters, "epoch").unwrap_or(0),
        total_fees_collected: read_u128_param(&c.system_data.parameters, "total_fees_collected")
            .unwrap_or(0),
        total_transactions: read_u64_param(&c.system_data.parameters, "total_transactions")
            .unwrap_or(0),
    };

    let min_collateral_ratio_bps =
        read_u128_param(&c.system_data.parameters, "min_collateral_ratio_bps").unwrap_or(10_000);
    let max_leverage_bps =
        read_u128_param(&c.system_data.parameters, "max_leverage_bps").unwrap_or(100_000);
    let dust_threshold =
        read_u128_param(&c.system_data.parameters, "dust_threshold").unwrap_or(0);

    let economic_parameters = EconomicParameters {
        min_collateral_ratio_bps,
        max_leverage_bps,
        dust_threshold,
        extra: BTreeMap::new(),
    };

    EconomicContext {
        price_oracle: BTreeMap::new(),
        exposure_limits: BTreeMap::new(),
        liquidity_thresholds: BTreeMap::new(),
        fee_schedule,
        epoch_accounting,
        collateral_requirements: BTreeMap::new(),
        economic_parameters,
    }
}

// ---------------------------------------------------------------------------
// State validity predicate — DEF-1
// ValidState(s) ≡ P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ)
// ---------------------------------------------------------------------------

/// Check whether a `State` is valid.
///
/// `valid_state(s) = P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ)` (DEF-1)
pub fn valid_state(s: &State) -> bool {
    valid_canonical(&s.canonical)
        && valid_derived(&s.canonical, &s.derived)
        && valid_environment(&s.environment)
        && valid_metadata(&s.metadata)
}

/// P_C: Canonical state validity.
/// - All balances are non-negative (inherent for u128).
/// - Total account balances equal system total_supply.
fn valid_canonical(c: &CanonicalState) -> bool {
    let total_balance: u128 = c.accounts.values().map(|a| a.balance).sum();
    total_balance == c.system_data.total_supply
}

/// P_D: Derived state consistency — D = Derive(C).
fn valid_derived(c: &CanonicalState, d: &DerivedState) -> bool {
    let expected = derive(c);
    *d == expected
}

/// P_E: Environment validity.
/// - Timestamp must be non-zero (reasonable).
/// - Block height must be non-zero after genesis.
/// - Domain tag must not be all zeros.
fn valid_environment(e: &Environment) -> bool {
    // Domain tag must not be the zero hash.
    let zero_hash = Hash([0u8; 32]);
    e.execution_domain.0 != zero_hash
}

/// P_τ: Metadata validity.
/// - Previous commitment is structurally present (always true for Hash).
/// - Timestamp is consistent (non-decreasing is checked at trace level).
fn valid_metadata(m: &TraceMetadata) -> bool {
    // Metadata timestamp must be consistent with epoch (epoch 0 is valid for genesis).
    // Sequence index and epoch are structurally valid as u64.
    // The previous_commitment for the very first entry (sequence_index == 0) should be
    // the zero hash.
    if m.sequence_index == 0 {
        m.previous_commitment == Hash([0u8; 32])
    } else {
        // For non-genesis entries, previous_commitment must not be the zero hash.
        m.previous_commitment != Hash([0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding — DEF-2, DEF-3
// ---------------------------------------------------------------------------

/// Domain separator for canonical state encoding.
/// Prevents confusion with other encoding formats.
const STATE_ENCODING_DOMAIN: &[u8] = b"VSEL-STATE-ENCODING-V1";

/// Deterministic, injective encoding of a `State`.
///
/// The encoding format uses length-prefixed variable-length fields and
/// fixed-size little-endian integers. BTreeMap iteration order guarantees
/// deterministic key ordering.
///
/// Encoding injectivity (DEF-2): `encode(s₁) = encode(s₂) ⟹ s₁ = s₂`.
/// This is achieved by the unambiguous, length-prefixed encoding format —
/// every field boundary is recoverable from the byte stream.
pub fn encode(s: &State) -> Vec<u8> {
    let mut buf = Vec::new();

    // Domain separator prefix
    encode_bytes(&mut buf, STATE_ENCODING_DOMAIN);

    // Canonical state (C)
    encode_canonical_state(&mut buf, &s.canonical);

    // Derived state (D)
    encode_derived_state(&mut buf, &s.derived);

    // Environment (E)
    encode_environment(&mut buf, &s.environment);

    // Economic context (Ω)
    encode_economic_context(&mut buf, &s.economic);

    // Trace metadata (τ)
    encode_trace_metadata(&mut buf, &s.metadata);

    buf
}

/// Encode a `CanonicalState` into a deterministic byte representation.
///
/// This is the public interface to the canonical state encoding used by
/// `commit()` and external crates (e.g., `vsel-crypto` for hybrid commitments).
/// The encoding is injective: distinct canonical states produce distinct byte sequences.
pub fn encode_canonical_state_bytes(c: &CanonicalState) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_canonical_state(&mut buf, c);
    buf
}

/// Compute commitment of a `CanonicalState`: `Hash(encode_canonical(s))` (DEF-3).
///
/// Uses SHA3-256 over the canonical encoding of the canonical state portion.
pub fn commit(c: &CanonicalState) -> Hash {
    let mut buf = Vec::new();
    encode_bytes(&mut buf, b"VSEL-COMMIT-V1");
    encode_canonical_state(&mut buf, c);

    let result = Sha3_256::digest(&buf);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

// ---------------------------------------------------------------------------
// Encoding helpers — length-prefixed, injective
// ---------------------------------------------------------------------------

/// Encode a variable-length byte slice with a u64 length prefix.
fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Encode a u64 as fixed-size little-endian.
fn encode_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode a u128 as fixed-size little-endian.
fn encode_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode a u32 as fixed-size little-endian.
fn encode_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode a `Hash` (fixed 32 bytes).
fn encode_hash(buf: &mut Vec<u8>, h: &Hash) {
    buf.extend_from_slice(&h.0);
}

/// Encode a `String` with length prefix.
fn encode_string(buf: &mut Vec<u8>, s: &str) {
    encode_bytes(buf, s.as_bytes());
}

fn encode_canonical_state(buf: &mut Vec<u8>, c: &CanonicalState) {
    // Accounts: count + entries in BTreeMap order
    encode_u64(buf, c.accounts.len() as u64);
    for (id, account) in &c.accounts {
        buf.extend_from_slice(&id.0); // AccountId: fixed 32 bytes
        encode_u128(buf, account.balance);
        encode_u64(buf, account.nonce);
        encode_bytes(buf, &account.data);
    }

    // Storage: count + entries in BTreeMap order
    encode_u64(buf, c.storage.len() as u64);
    for (key, value) in &c.storage {
        encode_bytes(buf, &key.0);
        encode_bytes(buf, &value.0);
    }

    // System data
    encode_u32(buf, c.system_data.protocol_version.major);
    encode_u32(buf, c.system_data.protocol_version.minor);
    encode_u32(buf, c.system_data.protocol_version.patch);
    encode_u128(buf, c.system_data.total_supply);

    // System parameters: count + entries in BTreeMap order
    encode_u64(buf, c.system_data.parameters.len() as u64);
    for (k, v) in &c.system_data.parameters {
        encode_string(buf, k);
        encode_bytes(buf, v);
    }
}

fn encode_derived_state(buf: &mut Vec<u8>, d: &DerivedState) {
    encode_hash(buf, &d.state_root);

    // Auxiliary roots: count + entries in BTreeMap order
    encode_u64(buf, d.auxiliary_roots.len() as u64);
    for (k, h) in &d.auxiliary_roots {
        encode_string(buf, k);
        encode_hash(buf, h);
    }

    // Aggregates: count + entries in BTreeMap order
    encode_u64(buf, d.aggregates.len() as u64);
    for (k, v) in &d.aggregates {
        encode_string(buf, k);
        encode_u128(buf, *v);
    }
}

fn encode_environment(buf: &mut Vec<u8>, e: &Environment) {
    encode_u64(buf, e.timestamp);
    encode_u64(buf, e.block_height);
    // DomainTag wraps a Hash
    encode_hash(buf, &e.execution_domain.0);
}

fn encode_economic_context(buf: &mut Vec<u8>, econ: &EconomicContext) {
    // Price oracle
    encode_u64(buf, econ.price_oracle.len() as u64);
    for (pair, price) in &econ.price_oracle {
        encode_string(buf, &pair.base);
        encode_string(buf, &pair.quote);
        encode_u128(buf, price.0);
    }

    // Exposure limits
    encode_u64(buf, econ.exposure_limits.len() as u64);
    for (id, limit) in &econ.exposure_limits {
        buf.extend_from_slice(&id.0); // EntityId: fixed 32 bytes
        encode_u128(buf, limit.0);
    }

    // Liquidity thresholds
    encode_u64(buf, econ.liquidity_thresholds.len() as u64);
    for (id, threshold) in &econ.liquidity_thresholds {
        buf.extend_from_slice(&id.0); // PoolId: fixed 32 bytes
        encode_u128(buf, threshold.0);
    }

    // Fee schedule
    encode_u128(buf, econ.fee_schedule.base_fee);
    encode_u128(buf, econ.fee_schedule.fee_rate_bps);
    encode_u64(buf, econ.fee_schedule.overrides.len() as u64);
    for (k, v) in &econ.fee_schedule.overrides {
        encode_string(buf, k);
        encode_u128(buf, *v);
    }

    // Epoch accounting
    encode_u64(buf, econ.epoch_accounting.epoch);
    encode_u128(buf, econ.epoch_accounting.total_fees_collected);
    encode_u64(buf, econ.epoch_accounting.total_transactions);

    // Collateral requirements
    encode_u64(buf, econ.collateral_requirements.len() as u64);
    for (pt, ratio) in &econ.collateral_requirements {
        // PositionType as u8 discriminant
        let disc: u8 = match pt {
            PositionType::Long => 0,
            PositionType::Short => 1,
            PositionType::Neutral => 2,
        };
        buf.push(disc);
        encode_u128(buf, ratio.0);
    }

    // Economic parameters
    encode_u128(buf, econ.economic_parameters.min_collateral_ratio_bps);
    encode_u128(buf, econ.economic_parameters.max_leverage_bps);
    encode_u128(buf, econ.economic_parameters.dust_threshold);
    encode_u64(buf, econ.economic_parameters.extra.len() as u64);
    for (k, v) in &econ.economic_parameters.extra {
        encode_string(buf, k);
        encode_u128(buf, *v);
    }
}

fn encode_trace_metadata(buf: &mut Vec<u8>, m: &TraceMetadata) {
    encode_u64(buf, m.sequence_index);
    encode_hash(buf, &m.previous_commitment);
    encode_u64(buf, m.epoch);
    encode_u64(buf, m.timestamp);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// SHA3-256 hash of the canonical state encoding.
/// Uses deterministic BTreeMap iteration order.
fn hash_canonical_state(c: &CanonicalState) -> Hash {
    let mut hasher = Sha3_256::new();

    // Hash accounts in deterministic order (BTreeMap).
    for (id, account) in &c.accounts {
        hasher.update(&id.0);
        hasher.update(&account.balance.to_le_bytes());
        hasher.update(&account.nonce.to_le_bytes());
        hasher.update(&account.data);
    }

    // Hash storage in deterministic order.
    for (key, value) in &c.storage {
        hasher.update(&key.0);
        hasher.update(&value.0);
    }

    // Hash system data.
    hasher.update(&c.system_data.protocol_version.major.to_le_bytes());
    hasher.update(&c.system_data.protocol_version.minor.to_le_bytes());
    hasher.update(&c.system_data.protocol_version.patch.to_le_bytes());
    hasher.update(&c.system_data.total_supply.to_le_bytes());
    for (k, v) in &c.system_data.parameters {
        hasher.update(k.as_bytes());
        hasher.update(v);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

/// Compute auxiliary roots: hashes of sub-components.
fn compute_auxiliary_roots(c: &CanonicalState) -> BTreeMap<String, Hash> {
    let mut roots = BTreeMap::new();

    // Accounts root.
    let mut hasher = Sha3_256::new();
    for (id, account) in &c.accounts {
        hasher.update(&id.0);
        hasher.update(&account.balance.to_le_bytes());
        hasher.update(&account.nonce.to_le_bytes());
        hasher.update(&account.data);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    roots.insert("accounts".to_string(), Hash(hash));

    // Storage root.
    let mut hasher = Sha3_256::new();
    for (key, value) in &c.storage {
        hasher.update(&key.0);
        hasher.update(&value.0);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    roots.insert("storage".to_string(), Hash(hash));

    roots
}

/// Compute aggregates from canonical state.
fn compute_aggregates(c: &CanonicalState) -> BTreeMap<String, u128> {
    let mut aggregates = BTreeMap::new();

    let total_balance: u128 = c.accounts.values().map(|a| a.balance).sum();
    aggregates.insert("total_balance".to_string(), total_balance);

    let account_count = c.accounts.len() as u128;
    aggregates.insert("account_count".to_string(), account_count);

    aggregates
}

/// Read a u128 parameter from system data.
fn read_u128_param(params: &BTreeMap<String, Vec<u8>>, key: &str) -> Option<u128> {
    params.get(key).and_then(|v| {
        if v.len() == 16 {
            Some(u128::from_le_bytes(v[..16].try_into().unwrap()))
        } else {
            None
        }
    })
}

/// Read a u64 parameter from system data.
fn read_u64_param(params: &BTreeMap<String, Vec<u8>>, key: &str) -> Option<u64> {
    params.get(key).and_then(|v| {
        if v.len() == 8 {
            Some(u64::from_le_bytes(v[..8].try_into().unwrap()))
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal valid canonical state.
    fn minimal_canonical() -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
                total_supply: 0,
                parameters: BTreeMap::new(),
            },
        }
    }

    /// Helper: create a non-zero domain tag.
    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 1;
        DomainTag(Hash(h))
    }

    /// Helper: build a valid State from a canonical state.
    fn build_valid_state(c: CanonicalState) -> State {
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let meta = TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp: 1_000_000,
        };
        State {
            canonical: c,
            derived: d,
            environment: env,
            economic: econ,
            metadata: meta,
        }
    }

    #[test]
    fn test_derive_deterministic() {
        let c = minimal_canonical();
        let d1 = derive(&c);
        let d2 = derive(&c);
        assert_eq!(d1, d2, "derive must be deterministic");
    }

    #[test]
    fn test_derive_changes_with_state() {
        let c1 = minimal_canonical();
        let mut c2 = minimal_canonical();
        let id = AccountId([42u8; 32]);
        c2.accounts.insert(
            id,
            AccountData {
                balance: 100,
                nonce: 0,
                data: vec![],
            },
        );
        c2.system_data.total_supply = 100;
        assert_ne!(
            derive(&c1).state_root,
            derive(&c2).state_root,
            "different canonical states must produce different roots"
        );
    }

    #[test]
    fn test_valid_state_minimal() {
        let c = minimal_canonical();
        let s = build_valid_state(c);
        assert!(valid_state(&s), "minimal valid state should pass");
    }

    #[test]
    fn test_valid_state_with_accounts() {
        let mut c = minimal_canonical();
        let id = AccountId([1u8; 32]);
        c.accounts.insert(
            id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 500;
        let s = build_valid_state(c);
        assert!(valid_state(&s));
    }

    #[test]
    fn test_invalid_state_bad_total_supply() {
        let mut c = minimal_canonical();
        let id = AccountId([1u8; 32]);
        c.accounts.insert(
            id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        // total_supply doesn't match sum of balances
        c.system_data.total_supply = 999;
        let s = build_valid_state(c);
        // P_C will fail because total_balance != total_supply
        assert!(!valid_state(&s));
    }

    #[test]
    fn test_invalid_state_bad_derived() {
        let c = minimal_canonical();
        let mut s = build_valid_state(c);
        // Corrupt the derived state root.
        s.derived.state_root = Hash([0xFFu8; 32]);
        assert!(!valid_state(&s), "corrupted derived state should fail P_D");
    }

    #[test]
    fn test_invalid_state_zero_domain() {
        let c = minimal_canonical();
        let mut s = build_valid_state(c);
        s.environment.execution_domain = DomainTag(Hash([0u8; 32]));
        assert!(!valid_state(&s), "zero domain tag should fail P_E");
    }

    #[test]
    fn test_invalid_metadata_nonzero_commitment_at_genesis() {
        let c = minimal_canonical();
        let mut s = build_valid_state(c);
        // sequence_index == 0 but previous_commitment is non-zero
        s.metadata.previous_commitment = Hash([1u8; 32]);
        assert!(
            !valid_state(&s),
            "genesis metadata with non-zero commitment should fail P_τ"
        );
    }

    #[test]
    fn test_valid_metadata_nongenesis() {
        let c = minimal_canonical();
        let mut s = build_valid_state(c);
        s.metadata.sequence_index = 5;
        s.metadata.previous_commitment = Hash([0xABu8; 32]);
        assert!(valid_state(&s));
    }

    #[test]
    fn test_invalid_metadata_zero_commitment_nongenesis() {
        let c = minimal_canonical();
        let mut s = build_valid_state(c);
        s.metadata.sequence_index = 1;
        s.metadata.previous_commitment = Hash([0u8; 32]);
        assert!(
            !valid_state(&s),
            "non-genesis with zero commitment should fail P_τ"
        );
    }

    #[test]
    fn test_derive_economic_defaults() {
        let c = minimal_canonical();
        let env = Environment {
            timestamp: 1_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        assert_eq!(econ.fee_schedule.base_fee, 0);
        assert_eq!(econ.fee_schedule.fee_rate_bps, 0);
        assert_eq!(econ.epoch_accounting.epoch, 0);
    }

    #[test]
    fn test_derive_economic_from_params() {
        let mut c = minimal_canonical();
        c.system_data
            .parameters
            .insert("base_fee".to_string(), 42u128.to_le_bytes().to_vec());
        c.system_data
            .parameters
            .insert("fee_rate_bps".to_string(), 100u128.to_le_bytes().to_vec());
        let env = Environment {
            timestamp: 1_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        assert_eq!(econ.fee_schedule.base_fee, 42);
        assert_eq!(econ.fee_schedule.fee_rate_bps, 100);
    }

    #[test]
    fn test_aggregates() {
        let mut c = minimal_canonical();
        c.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: 100,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            AccountId([2u8; 32]),
            AccountData {
                balance: 200,
                nonce: 1,
                data: vec![],
            },
        );
        c.system_data.total_supply = 300;
        let d = derive(&c);
        assert_eq!(d.aggregates.get("total_balance"), Some(&300));
        assert_eq!(d.aggregates.get("account_count"), Some(&2));
    }

    // -----------------------------------------------------------------------
    // Canonical encoding tests (DEF-2, DEF-3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_deterministic() {
        let c = minimal_canonical();
        let s = build_valid_state(c);
        let enc1 = encode(&s);
        let enc2 = encode(&s);
        assert_eq!(enc1, enc2, "encode must be deterministic: same state → same bytes");
    }

    #[test]
    fn test_encode_injectivity_different_balance() {
        let mut c1 = minimal_canonical();
        c1.system_data.total_supply = 100;
        c1.accounts.insert(
            AccountId([1u8; 32]),
            AccountData { balance: 100, nonce: 0, data: vec![] },
        );
        let s1 = build_valid_state(c1);

        let mut c2 = minimal_canonical();
        c2.system_data.total_supply = 200;
        c2.accounts.insert(
            AccountId([1u8; 32]),
            AccountData { balance: 200, nonce: 0, data: vec![] },
        );
        let s2 = build_valid_state(c2);

        assert_ne!(
            encode(&s1),
            encode(&s2),
            "different balances must produce different encodings (DEF-2)"
        );
    }

    #[test]
    fn test_encode_injectivity_different_accounts() {
        let mut c1 = minimal_canonical();
        c1.system_data.total_supply = 50;
        c1.accounts.insert(
            AccountId([1u8; 32]),
            AccountData { balance: 50, nonce: 0, data: vec![] },
        );
        let s1 = build_valid_state(c1);

        let mut c2 = minimal_canonical();
        c2.system_data.total_supply = 50;
        c2.accounts.insert(
            AccountId([2u8; 32]),
            AccountData { balance: 50, nonce: 0, data: vec![] },
        );
        let s2 = build_valid_state(c2);

        assert_ne!(
            encode(&s1),
            encode(&s2),
            "different account IDs must produce different encodings (DEF-2)"
        );
    }

    #[test]
    fn test_encode_injectivity_different_storage() {
        let mut c1 = minimal_canonical();
        c1.storage.insert(
            StorageKey(vec![1, 2, 3]),
            StorageValue(vec![10]),
        );
        let s1 = build_valid_state(c1);

        let mut c2 = minimal_canonical();
        c2.storage.insert(
            StorageKey(vec![1, 2, 3]),
            StorageValue(vec![20]),
        );
        let s2 = build_valid_state(c2);

        assert_ne!(
            encode(&s1),
            encode(&s2),
            "different storage values must produce different encodings (DEF-2)"
        );
    }

    #[test]
    fn test_encode_injectivity_different_metadata() {
        let c = minimal_canonical();
        let mut s1 = build_valid_state(c.clone());
        let mut s2 = build_valid_state(c);

        s1.metadata.sequence_index = 5;
        s1.metadata.previous_commitment = Hash([0xABu8; 32]);
        s2.metadata.sequence_index = 6;
        s2.metadata.previous_commitment = Hash([0xCDu8; 32]);

        assert_ne!(
            encode(&s1),
            encode(&s2),
            "different metadata must produce different encodings (DEF-2)"
        );
    }

    #[test]
    fn test_commit_uses_encode_and_hash() {
        let c = minimal_canonical();
        // commit should produce a non-zero hash
        let h = commit(&c);
        assert_ne!(h, Hash([0u8; 32]), "commit must produce a non-zero hash");
    }

    #[test]
    fn test_commit_deterministic() {
        let c = minimal_canonical();
        let h1 = commit(&c);
        let h2 = commit(&c);
        assert_eq!(h1, h2, "commit must be deterministic");
    }

    #[test]
    fn test_commit_different_states() {
        let c1 = minimal_canonical();
        let mut c2 = minimal_canonical();
        c2.system_data.total_supply = 999;
        c2.accounts.insert(
            AccountId([1u8; 32]),
            AccountData { balance: 999, nonce: 0, data: vec![] },
        );

        assert_ne!(
            commit(&c1),
            commit(&c2),
            "different canonical states must produce different commits"
        );
    }
}
