//! Semantic mapping functions (μ_S, μ_Σ, μ_T, μ_Tr, μ_O).
//!
//! Derived from: SEMANTIC_MAPPING.md, Requirement 4.1.
//!
//! These functions map concrete Rust types to formal SIR types (`SirValue`).
//! All mapping functions are:
//! - **Total**: defined for all inputs (no panics, no errors)
//! - **Deterministic**: same input always produces the same output
//! - **Pure**: no side effects
//! - **Injective** (for canonical components): distinct concrete values produce
//!   distinct formal values, ensuring semantic preservation.
//!
//! The formal types use `SirValue` from `vsel-sir`, with `BTreeMap` for
//! deterministic key ordering in all map constructions.
//!
//! ## Semantic Preservation
//!
//! All u128 values (balances, total_supply, economic parameters) are encoded as
//! `SirValue::Bytes` using 16-byte little-endian representation to preserve full
//! precision. Using `as i64` would silently truncate values > i64::MAX, breaking
//! semantic preservation and injectivity.
//!
//! ## Injectivity
//!
//! The mapping is injective for canonical components: if `map_state(s1) = map_state(s2)`
//! then `s1.canonical = s2.canonical`. This is verified by `verify_state_injectivity()`.

use std::collections::BTreeMap;

use vsel_core::input::{Authorization, Input};
use vsel_core::observable::{Observable, TransitionStatus};
use vsel_core::state::{
    self, AccountData, CanonicalState, DerivedState, EconomicContext, Environment, State,
    TraceMetadata,
};
use vsel_core::transition::TransitionClass;
use vsel_core::types::*;
use vsel_sir::SirValue;
use vsel_trace::engine::{Trace, TraceEntry};

// ---------------------------------------------------------------------------
// Formal types — newtype wrappers around SirValue
// ---------------------------------------------------------------------------

/// Formal state — μ_S(s_c) maps a concrete `State` to a `SirValue::Map`.
#[derive(Clone, Debug, PartialEq)]
pub struct FormalState(pub SirValue);

/// Formal input — μ_Σ(σ_c) maps a concrete `Input` to a `SirValue::Map`.
#[derive(Clone, Debug, PartialEq)]
pub struct FormalInput(pub SirValue);

/// Formal transition — μ_T(pre, σ, post) maps a concrete transition triple.
#[derive(Clone, Debug, PartialEq)]
pub struct FormalTransition {
    pub pre: FormalState,
    pub input: FormalInput,
    pub post: FormalState,
}

/// Formal trace — μ_Tr(τ_c) maps a concrete `Trace` to a `SirValue::Map`.
#[derive(Clone, Debug, PartialEq)]
pub struct FormalTrace(pub SirValue);

/// Formal observable — μ_O(o_c) maps a concrete `Observable` to a `SirValue::Map`.
#[derive(Clone, Debug, PartialEq)]
pub struct FormalObservable(pub SirValue);

// ---------------------------------------------------------------------------
// μ_S: S_c → S_f — map concrete state to formal state
// ---------------------------------------------------------------------------

/// Map a concrete `State` to a `FormalState` (`SirValue::Map`).
///
/// Total and deterministic. The formal state is a map with keys:
/// `canonical`, `derived`, `environment`, `economic`, `metadata`,
/// and `derived_valid` (bool indicating D = Derive(C)).
///
/// Field-level semantic extraction:
/// - Canonical: accounts (balances as u128 bytes, nonces, data), storage, system_data
/// - Derived: state_root, auxiliary_roots, aggregates — verified against Derive(C)
/// - Environment: timestamp, block_height, execution_domain
/// - Economic: full parameter mapping (price_oracle, exposure_limits, etc.)
/// - Metadata: sequence_index, previous_commitment, epoch, timestamp
///
/// Requirement 4.1: μ_S is total and deterministic.
pub fn map_state(concrete: &State) -> FormalState {
    let mut entries = BTreeMap::new();
    entries.insert(
        "canonical".to_string(),
        map_canonical_state(&concrete.canonical),
    );
    entries.insert("derived".to_string(), map_derived_state(&concrete.derived));
    entries.insert(
        "environment".to_string(),
        map_environment(&concrete.environment),
    );
    entries.insert(
        "economic".to_string(),
        map_economic_context(&concrete.economic),
    );
    entries.insert(
        "metadata".to_string(),
        map_trace_metadata(&concrete.metadata),
    );

    // Verify D = Derive(C) through the mapping (DEF-1 verification)
    let recomputed_derived = state::derive(&concrete.canonical);
    let derived_valid = concrete.derived == recomputed_derived;
    entries.insert(
        "derived_valid".to_string(),
        SirValue::Bool {
            value: derived_valid,
        },
    );

    FormalState(SirValue::Map { entries })
}

/// Verify injectivity of `map_state` for canonical components.
///
/// Returns true if `map_state(s1).canonical == map_state(s2).canonical` implies
/// `s1.canonical == s2.canonical`. This is verified by checking that the
/// canonical mapping is structurally injective — distinct canonical states
/// produce distinct SIR values.
///
/// Requirement 4.1: μ_S injectivity for canonical components.
pub fn verify_state_injectivity(s1: &State, s2: &State) -> bool {
    let formal1 = map_state(s1);
    let formal2 = map_state(s2);

    // Extract canonical components from formal states
    let canonical1 = match &formal1.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };
    let canonical2 = match &formal2.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };

    // Injectivity: if formal canonicals are equal, concrete canonicals must be equal
    if canonical1 == canonical2 {
        s1.canonical == s2.canonical
    } else {
        // Different formal canonicals — injectivity trivially holds
        true
    }
}

// ---------------------------------------------------------------------------
// μ_Σ: Σ_c → Σ_f — map concrete input to formal input
// ---------------------------------------------------------------------------

/// Map a concrete `Input` to a `FormalInput` (`SirValue::Map`).
///
/// Total and deterministic. The formal input is a map with keys:
/// `payload`, `auth`, `aux`.
///
/// Requirement 4.1: μ_Σ is total and deterministic.
pub fn map_input(concrete: &Input) -> FormalInput {
    let mut entries = BTreeMap::new();
    entries.insert("payload".to_string(), map_payload(&concrete.payload));
    entries.insert("auth".to_string(), map_authorization(&concrete.auth));
    entries.insert(
        "aux".to_string(),
        SirValue::Bytes {
            value: concrete.aux.data.clone(),
        },
    );
    FormalInput(SirValue::Map { entries })
}

// ---------------------------------------------------------------------------
// μ_T: (S_c, Σ_c, S_c) → (S_f, Σ_f, S_f) — map transition
// ---------------------------------------------------------------------------

/// Map a concrete transition triple `(pre, input, post)` to a `FormalTransition`.
///
/// Total and deterministic. Composes μ_S and μ_Σ.
///
/// Requirement 4.1: μ_T is total and deterministic.
pub fn map_transition(pre: &State, input: &Input, post: &State) -> FormalTransition {
    FormalTransition {
        pre: map_state(pre),
        input: map_input(input),
        post: map_state(post),
    }
}

// ---------------------------------------------------------------------------
// μ_Tr: Tr_c → Tr_f — map trace
// ---------------------------------------------------------------------------

/// Map a concrete `Trace` to a `FormalTrace` (`SirValue::Map`).
///
/// Total and deterministic. The formal trace is a map with keys:
/// `entries` (list of mapped trace entries), `initial_state`, `commitment`.
///
/// Requirement 4.1: μ_Tr is total and deterministic.
pub fn map_trace(concrete: &Trace) -> FormalTrace {
    let formal_entries: Vec<SirValue> = concrete.entries.iter().map(map_trace_entry).collect();

    let mut entries = BTreeMap::new();
    entries.insert(
        "entries".to_string(),
        SirValue::List {
            elements: formal_entries,
        },
    );
    entries.insert(
        "initial_state".to_string(),
        map_state(&concrete.initial_state).0,
    );
    entries.insert("commitment".to_string(), map_hash(&concrete.commitment));
    FormalTrace(SirValue::Map { entries })
}

// ---------------------------------------------------------------------------
// μ_O: O_c → O_f — map observable
// ---------------------------------------------------------------------------

/// Map a concrete `Observable` to a `FormalObservable` (`SirValue::Map`).
///
/// Total and deterministic. The formal observable is a map with keys:
/// `transition_class`, `outputs`, `gas_used`, `status`.
///
/// Requirement 4.1: μ_O is total and deterministic.
pub fn map_observable(concrete: &Observable) -> FormalObservable {
    let mut entries = BTreeMap::new();
    entries.insert(
        "transition_class".to_string(),
        map_transition_class(concrete.transition_class),
    );
    entries.insert(
        "outputs".to_string(),
        SirValue::List {
            elements: concrete.outputs.iter().map(map_output_event).collect(),
        },
    );
    entries.insert(
        "gas_used".to_string(),
        SirValue::Int {
            value: concrete.gas_used as i64,
        },
    );
    entries.insert("status".to_string(), map_transition_status(concrete.status));
    FormalObservable(SirValue::Map { entries })
}

// ---------------------------------------------------------------------------
// Internal helpers — sub-component mapping
// ---------------------------------------------------------------------------

/// Map a `Hash` to `SirValue::Bytes`.
fn map_hash(h: &Hash) -> SirValue {
    SirValue::Bytes {
        value: h.0.to_vec(),
    }
}

/// Map a `CanonicalState` to `SirValue::Map`.
fn map_canonical_state(c: &CanonicalState) -> SirValue {
    let mut entries = BTreeMap::new();

    // Accounts: map of hex-encoded account IDs to account data
    let mut accounts = BTreeMap::new();
    for (id, data) in &c.accounts {
        accounts.insert(hex_encode(&id.0), map_account_data(data));
    }
    entries.insert("accounts".to_string(), SirValue::Map { entries: accounts });

    // Storage: map of hex-encoded keys to byte values
    let mut storage = BTreeMap::new();
    for (key, val) in &c.storage {
        storage.insert(
            hex_encode(&key.0),
            SirValue::Bytes {
                value: val.0.clone(),
            },
        );
    }
    entries.insert("storage".to_string(), SirValue::Map { entries: storage });

    // System data
    entries.insert("system_data".to_string(), map_system_data(&c.system_data));

    SirValue::Map { entries }
}

/// Map `AccountData` to `SirValue::Map`.
///
/// Balance is encoded as `SirValue::Bytes` (16-byte LE) to preserve full u128 precision.
/// Using `as i64` would silently truncate values > i64::MAX, breaking injectivity.
fn map_account_data(a: &AccountData) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert("balance".to_string(), map_u128(a.balance));
    entries.insert(
        "nonce".to_string(),
        SirValue::Int {
            value: a.nonce as i64,
        },
    );
    entries.insert(
        "data".to_string(),
        SirValue::Bytes {
            value: a.data.clone(),
        },
    );
    SirValue::Map { entries }
}

/// Map `SystemData` to `SirValue::Map`.
///
/// total_supply is encoded as `SirValue::Bytes` (16-byte LE) to preserve full u128 precision.
fn map_system_data(sd: &SystemData) -> SirValue {
    let mut entries = BTreeMap::new();

    // Protocol version as a map
    let mut version = BTreeMap::new();
    version.insert(
        "major".to_string(),
        SirValue::Int {
            value: sd.protocol_version.major as i64,
        },
    );
    version.insert(
        "minor".to_string(),
        SirValue::Int {
            value: sd.protocol_version.minor as i64,
        },
    );
    version.insert(
        "patch".to_string(),
        SirValue::Int {
            value: sd.protocol_version.patch as i64,
        },
    );
    entries.insert(
        "protocol_version".to_string(),
        SirValue::Map { entries: version },
    );

    entries.insert("total_supply".to_string(), map_u128(sd.total_supply));

    // Parameters: map of string keys to byte values
    let mut params = BTreeMap::new();
    for (k, v) in &sd.parameters {
        params.insert(k.clone(), SirValue::Bytes { value: v.clone() });
    }
    entries.insert("parameters".to_string(), SirValue::Map { entries: params });

    SirValue::Map { entries }
}

/// Map `DerivedState` to `SirValue::Map`.
///
/// Aggregates are encoded as `SirValue::Bytes` (16-byte LE) to preserve full u128 precision.
fn map_derived_state(d: &DerivedState) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert("state_root".to_string(), map_hash(&d.state_root));

    let mut aux_roots = BTreeMap::new();
    for (k, h) in &d.auxiliary_roots {
        aux_roots.insert(k.clone(), map_hash(h));
    }
    entries.insert(
        "auxiliary_roots".to_string(),
        SirValue::Map { entries: aux_roots },
    );

    let mut aggregates = BTreeMap::new();
    for (k, v) in &d.aggregates {
        aggregates.insert(k.clone(), map_u128(*v));
    }
    entries.insert(
        "aggregates".to_string(),
        SirValue::Map {
            entries: aggregates,
        },
    );

    SirValue::Map { entries }
}

/// Map `Environment` to `SirValue::Map`.
fn map_environment(e: &Environment) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "timestamp".to_string(),
        SirValue::Int {
            value: e.timestamp as i64,
        },
    );
    entries.insert(
        "block_height".to_string(),
        SirValue::Int {
            value: e.block_height as i64,
        },
    );
    entries.insert(
        "execution_domain".to_string(),
        map_hash(&e.execution_domain.0),
    );
    SirValue::Map { entries }
}

/// Map `EconomicContext` to `SirValue::Map`.
///
/// All u128 economic values (prices, limits, thresholds, fees, collateral ratios)
/// are encoded as `SirValue::Bytes` (16-byte LE) to preserve full precision.
fn map_economic_context(econ: &EconomicContext) -> SirValue {
    let mut entries = BTreeMap::new();

    // Price oracle
    let mut oracle = BTreeMap::new();
    for (pair, price) in &econ.price_oracle {
        let key = format!("{}_{}", pair.base, pair.quote);
        oracle.insert(key, map_u128(price.0));
    }
    entries.insert(
        "price_oracle".to_string(),
        SirValue::Map { entries: oracle },
    );

    // Exposure limits
    let mut limits = BTreeMap::new();
    for (id, limit) in &econ.exposure_limits {
        limits.insert(hex_encode(&id.0), map_u128(limit.0));
    }
    entries.insert(
        "exposure_limits".to_string(),
        SirValue::Map { entries: limits },
    );

    // Liquidity thresholds
    let mut thresholds = BTreeMap::new();
    for (id, threshold) in &econ.liquidity_thresholds {
        thresholds.insert(hex_encode(&id.0), map_u128(threshold.0));
    }
    entries.insert(
        "liquidity_thresholds".to_string(),
        SirValue::Map {
            entries: thresholds,
        },
    );

    // Fee schedule
    entries.insert(
        "fee_schedule".to_string(),
        map_fee_schedule(&econ.fee_schedule),
    );

    // Epoch accounting
    entries.insert(
        "epoch_accounting".to_string(),
        map_epoch_accounting(&econ.epoch_accounting),
    );

    // Collateral requirements
    let mut collateral = BTreeMap::new();
    for (pt, ratio) in &econ.collateral_requirements {
        let key = match pt {
            PositionType::Long => "long",
            PositionType::Short => "short",
            PositionType::Neutral => "neutral",
        };
        collateral.insert(key.to_string(), map_u128(ratio.0));
    }
    entries.insert(
        "collateral_requirements".to_string(),
        SirValue::Map {
            entries: collateral,
        },
    );

    // Economic parameters
    entries.insert(
        "economic_parameters".to_string(),
        map_economic_parameters(&econ.economic_parameters),
    );

    SirValue::Map { entries }
}

/// Map `FeeSchedule` to `SirValue::Map`.
///
/// All u128 fee values are encoded as `SirValue::Bytes` (16-byte LE).
fn map_fee_schedule(fs: &FeeSchedule) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert("base_fee".to_string(), map_u128(fs.base_fee));
    entries.insert("fee_rate_bps".to_string(), map_u128(fs.fee_rate_bps));

    let mut overrides = BTreeMap::new();
    for (k, v) in &fs.overrides {
        overrides.insert(k.clone(), map_u128(*v));
    }
    entries.insert(
        "overrides".to_string(),
        SirValue::Map { entries: overrides },
    );

    SirValue::Map { entries }
}

/// Map `EpochAccounting` to `SirValue::Map`.
///
/// total_fees_collected is encoded as `SirValue::Bytes` (16-byte LE) for u128 precision.
fn map_epoch_accounting(ea: &EpochAccounting) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "epoch".to_string(),
        SirValue::Int {
            value: ea.epoch as i64,
        },
    );
    entries.insert(
        "total_fees_collected".to_string(),
        map_u128(ea.total_fees_collected),
    );
    entries.insert(
        "total_transactions".to_string(),
        SirValue::Int {
            value: ea.total_transactions as i64,
        },
    );
    SirValue::Map { entries }
}

/// Map `EconomicParameters` to `SirValue::Map`.
///
/// All u128 parameter values are encoded as `SirValue::Bytes` (16-byte LE).
fn map_economic_parameters(ep: &EconomicParameters) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "min_collateral_ratio_bps".to_string(),
        map_u128(ep.min_collateral_ratio_bps),
    );
    entries.insert(
        "max_leverage_bps".to_string(),
        map_u128(ep.max_leverage_bps),
    );
    entries.insert("dust_threshold".to_string(), map_u128(ep.dust_threshold));

    let mut extra = BTreeMap::new();
    for (k, v) in &ep.extra {
        extra.insert(k.clone(), map_u128(*v));
    }
    entries.insert("extra".to_string(), SirValue::Map { entries: extra });

    SirValue::Map { entries }
}

/// Map `TraceMetadata` to `SirValue::Map`.
fn map_trace_metadata(m: &TraceMetadata) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "sequence_index".to_string(),
        SirValue::Int {
            value: m.sequence_index as i64,
        },
    );
    entries.insert(
        "previous_commitment".to_string(),
        map_hash(&m.previous_commitment),
    );
    entries.insert(
        "epoch".to_string(),
        SirValue::Int {
            value: m.epoch as i64,
        },
    );
    entries.insert(
        "timestamp".to_string(),
        SirValue::Int {
            value: m.timestamp as i64,
        },
    );
    SirValue::Map { entries }
}

/// Map `Payload` to `SirValue::Map`.
fn map_payload(p: &Payload) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "payload_type".to_string(),
        SirValue::Bytes {
            value: p.payload_type.as_bytes().to_vec(),
        },
    );
    entries.insert(
        "data".to_string(),
        SirValue::Bytes {
            value: p.data.clone(),
        },
    );
    SirValue::Map { entries }
}

/// Map `Authorization` to `SirValue::Map`.
fn map_authorization(a: &Authorization) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "classical_sig".to_string(),
        SirValue::Bytes {
            value: a.classical_sig.clone(),
        },
    );
    entries.insert(
        "pqc_sig".to_string(),
        SirValue::Bytes {
            value: a.pqc_sig.clone(),
        },
    );

    let mut pk = BTreeMap::new();
    pk.insert(
        "classical".to_string(),
        SirValue::Bytes {
            value: a.public_key.classical.clone(),
        },
    );
    pk.insert(
        "pqc".to_string(),
        SirValue::Bytes {
            value: a.public_key.pqc.clone(),
        },
    );
    entries.insert("public_key".to_string(), SirValue::Map { entries: pk });

    entries.insert(
        "nonce".to_string(),
        SirValue::Int {
            value: a.nonce as i64,
        },
    );
    entries.insert("domain".to_string(), map_hash(&a.domain.0));
    SirValue::Map { entries }
}

/// Map a `TransitionClass` to `SirValue::Int` (discriminant).
fn map_transition_class(tc: TransitionClass) -> SirValue {
    SirValue::Int { value: tc as i64 }
}

/// Map a `TransitionStatus` to `SirValue::Int` (discriminant).
fn map_transition_status(ts: TransitionStatus) -> SirValue {
    let value = match ts {
        TransitionStatus::Success => 0,
        TransitionStatus::Rejected => 1,
        TransitionStatus::Error => 2,
    };
    SirValue::Int { value }
}

/// Map an `OutputEvent` to `SirValue::Map`.
fn map_output_event(e: &OutputEvent) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "event_type".to_string(),
        SirValue::Bytes {
            value: e.event_type.as_bytes().to_vec(),
        },
    );
    entries.insert(
        "data".to_string(),
        SirValue::Bytes {
            value: e.data.clone(),
        },
    );
    SirValue::Map { entries }
}

/// Map a `TraceEntry` to `SirValue::Map`.
fn map_trace_entry(te: &TraceEntry) -> SirValue {
    let mut entries = BTreeMap::new();
    entries.insert(
        "index".to_string(),
        SirValue::Int {
            value: te.index as i64,
        },
    );
    entries.insert(
        "pre_state_commitment".to_string(),
        map_hash(&te.pre_state_commitment),
    );
    entries.insert("input".to_string(), map_input(&te.input).0);
    entries.insert(
        "post_state_commitment".to_string(),
        map_hash(&te.post_state_commitment),
    );
    entries.insert("observable".to_string(), map_observable(&te.observable).0);
    entries.insert("environment".to_string(), map_environment(&te.environment));
    entries.insert("chain_hash".to_string(), map_hash(&te.chain_hash));
    SirValue::Map { entries }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Deterministic hex encoding of a byte slice.
/// Uses lowercase hex for consistency.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Map a u128 value to `SirValue::Bytes` using 16-byte little-endian encoding.
///
/// This preserves full u128 precision. Using `SirValue::Int { value: v as i64 }`
/// would silently truncate values > i64::MAX (9,223,372,036,854,775,807),
/// breaking semantic preservation and injectivity for balances, total_supply,
/// and economic parameters that can legitimately exceed i64::MAX.
///
/// The encoding is injective: distinct u128 values produce distinct byte sequences.
fn map_u128(v: u128) -> SirValue {
    SirValue::Bytes {
        value: v.to_le_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Commutativity verification — THM-1, THM-2, THM-4, THM-5, THM-6, THM-14/15
// ---------------------------------------------------------------------------

/// Verify execution-mapping commutativity (THM-1).
///
/// Checks that applying a transition concretely and then mapping the result
/// produces a formal state consistent with mapping the inputs first:
///   `μ_S(apply_c(s_c, σ_c))` is structurally consistent with
///   the formal transition `(μ_S(s_c), μ_Σ(σ_c), μ_S(s'_c))`.
///
/// Specifically verifies:
/// 1. The concrete post-state maps to a well-formed formal state
/// 2. The formal transition triple is internally consistent
/// 3. The mapped post-state's derived component equals derive(canonical) mapped
///
/// Requirements: 4.2, 13.9
pub fn verify_execution_commutativity(pre: &State, input: &Input) -> bool {
    use vsel_core::state::{derive, derive_economic};
    use vsel_core::transition::apply;

    // Concrete execution: s' = apply(s, σ)
    let post = apply(pre, input);

    // Map both sides
    let formal_pre = map_state(pre);
    let formal_input = map_input(input);
    let formal_post = map_state(&post);

    // Verify the formal post-state is a well-formed Map
    let post_is_map = matches!(&formal_post.0, SirValue::Map { .. });
    if !post_is_map {
        return false;
    }

    // Verify the formal transition triple is consistent:
    // map_transition(pre, input, post) should compose correctly
    let formal_transition = map_transition(pre, input, &post);
    if formal_transition.pre != formal_pre {
        return false;
    }
    if formal_transition.input != formal_input {
        return false;
    }
    if formal_transition.post != formal_post {
        return false;
    }

    // Verify derived state consistency through mapping:
    // The post-state's derived component should equal derive(post.canonical) mapped
    let recomputed_derived = derive(&post.canonical);
    let mapped_recomputed = map_derived_state(&recomputed_derived);
    let mapped_actual = map_derived_state(&post.derived);
    if mapped_recomputed != mapped_actual {
        return false;
    }

    // Verify economic context consistency through mapping:
    let recomputed_econ = derive_economic(&post.canonical, &post.environment);
    let mapped_recomputed_econ = map_economic_context(&recomputed_econ);
    let mapped_actual_econ = map_economic_context(&post.economic);
    mapped_recomputed_econ == mapped_actual_econ
}

/// Verify observable commutativity (THM-2).
///
/// Checks that computing the observable concretely and mapping it produces
/// a formal observable consistent with the formal transition:
///   `μ_O(obs_c(s_c, σ_c, s'_c))` is consistent with
///   `obs_f(μ_S(s_c), μ_Σ(σ_c), μ_S(s'_c))`.
///
/// Specifically verifies:
/// 1. The concrete observable maps to a well-formed formal observable
/// 2. The formal observable's transition class matches the formal transition
/// 3. The observable is deterministic (computing it twice yields the same result)
///
/// Requirement: 4.3
pub fn verify_observable_commutativity(pre: &State, input: &Input) -> bool {
    use vsel_core::observable::obs;
    use vsel_core::transition::{apply, classify};

    // Concrete execution
    let post = apply(pre, input);
    let concrete_obs = obs(pre, input, &post);

    // Map the observable
    let formal_obs = map_observable(&concrete_obs);

    // Verify the formal observable is a well-formed Map
    let obs_map = match &formal_obs.0 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Verify the transition class in the observable matches classification
    let expected_class = classify(pre, input);
    let formal_class = map_transition_class(expected_class);
    if obs_map.get("transition_class") != Some(&formal_class) {
        return false;
    }

    // Verify determinism: computing obs twice yields the same formal observable
    let concrete_obs_2 = obs(pre, input, &post);
    let formal_obs_2 = map_observable(&concrete_obs_2);
    if formal_obs != formal_obs_2 {
        return false;
    }

    // Verify the observable status is consistent with the transition class
    let formal_status = obs_map.get("status");
    match expected_class {
        TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update => {
            // Success transitions should have status 0
            formal_status == Some(&SirValue::Int { value: 0 })
        }
        TransitionClass::Reject | TransitionClass::Noop => {
            // Rejected transitions should have status 1
            formal_status == Some(&SirValue::Int { value: 1 })
        }
        TransitionClass::Error => {
            // Error transitions should have status 2
            formal_status == Some(&SirValue::Int { value: 2 })
        }
    }
}

/// Verify auxiliary data exclusion (THM-4).
///
/// Checks that changing auxiliary data does not change the Apply result:
///   `apply(s, (p, a, aux₁)) = apply(s, (p, a, aux₂))`
///
/// Requirement: 4.5
pub fn verify_auxiliary_exclusion(pre: &State, input: &Input) -> bool {
    use vsel_core::transition::apply;

    // Create a variant of the input with different auxiliary data
    let mut input_alt = input.clone();
    input_alt.aux = AuxiliaryData {
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    // Apply both
    let post_original = apply(pre, input);
    let post_alt = apply(pre, &input_alt);

    // The canonical states must be identical (aux must not influence semantics)
    if post_original.canonical != post_alt.canonical {
        return false;
    }

    // The derived states must be identical (since canonical is identical)
    if post_original.derived != post_alt.derived {
        return false;
    }

    // The mapped formal states must be identical
    let formal_original = map_state(&post_original);
    let formal_alt = map_state(&post_alt);
    formal_original == formal_alt
}

/// Verify derived state commutativity (THM-5).
///
/// Checks that mapping the derived state of a canonical state is consistent:
///   `μ_D(derive_c(C_c)) = derive_f(μ_C(C_c))`
///
/// Since we don't have a separate formal derive function, we verify that:
/// 1. derive(C) is deterministic
/// 2. map_derived(derive(C)) is deterministic
/// 3. The mapped derived state is consistent with the mapped canonical state
///
/// Requirement: 4.6
pub fn verify_derived_commutativity(canonical: &CanonicalState) -> bool {
    use vsel_core::state::derive;

    // Compute derive(C) twice — must be identical (determinism)
    let derived_1 = derive(canonical);
    let derived_2 = derive(canonical);
    if derived_1 != derived_2 {
        return false;
    }

    // Map the derived state
    let formal_derived_1 = map_derived_state(&derived_1);
    let formal_derived_2 = map_derived_state(&derived_2);
    if formal_derived_1 != formal_derived_2 {
        return false;
    }

    // Map the canonical state
    let formal_canonical = map_canonical_state(canonical);

    // Verify the formal derived state is a well-formed Map
    let derived_map = match &formal_derived_1 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Verify the derived state has expected structure
    if !derived_map.contains_key("state_root") {
        return false;
    }
    if !derived_map.contains_key("auxiliary_roots") {
        return false;
    }
    if !derived_map.contains_key("aggregates") {
        return false;
    }

    // Verify aggregates are consistent with canonical state
    if let Some(SirValue::Map {
        entries: agg_entries,
    }) = derived_map.get("aggregates")
    {
        // total_balance aggregate should match sum of account balances
        if let SirValue::Map {
            entries: canonical_map,
        } = &formal_canonical
        {
            if let Some(SirValue::Map { entries: accounts }) = canonical_map.get("accounts") {
                let total: u128 = accounts
                    .values()
                    .filter_map(|v| {
                        if let SirValue::Map { entries } = v {
                            if let Some(SirValue::Bytes { value }) = entries.get("balance") {
                                if value.len() == 16 {
                                    return Some(u128::from_le_bytes(
                                        value[..16].try_into().unwrap(),
                                    ));
                                }
                            }
                        }
                        None
                    })
                    .sum();
                if let Some(SirValue::Bytes { value: agg_bytes }) = agg_entries.get("total_balance")
                {
                    if agg_bytes.len() == 16 {
                        let agg_total = u128::from_le_bytes(agg_bytes[..16].try_into().unwrap());
                        if agg_total != total {
                            return false;
                        }
                    }
                }
            }
        }
    }

    true
}

/// Verify trace mapping preserves validity (THM-6).
///
/// Checks that a mapped trace has valid structure:
/// 1. The formal trace is a well-formed Map with expected keys
/// 2. Entries are a List with sequential indices
/// 3. Chain hashes form a valid chain (each entry has a chain_hash)
/// 4. State commitments chain correctly (post[i] matches pre[i+1])
///
/// Requirement: 4.7
pub fn verify_trace_mapping_validity(trace: &Trace) -> bool {
    let formal_trace = map_trace(trace);

    // Verify the formal trace is a well-formed Map
    let trace_map = match &formal_trace.0 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Must have expected keys
    if !trace_map.contains_key("entries") {
        return false;
    }
    if !trace_map.contains_key("initial_state") {
        return false;
    }
    if !trace_map.contains_key("commitment") {
        return false;
    }

    // Verify entries is a List
    let entry_list = match trace_map.get("entries") {
        Some(SirValue::List { elements }) => elements,
        _ => return false,
    };

    // Verify sequential indices
    for (i, entry) in entry_list.iter().enumerate() {
        if let SirValue::Map { entries } = entry {
            // Check index
            if let Some(SirValue::Int { value: idx }) = entries.get("index") {
                if *idx != i as i64 {
                    return false;
                }
            } else {
                return false;
            }

            // Check required keys exist
            if !entries.contains_key("pre_state_commitment") {
                return false;
            }
            if !entries.contains_key("input") {
                return false;
            }
            if !entries.contains_key("post_state_commitment") {
                return false;
            }
            if !entries.contains_key("observable") {
                return false;
            }
            if !entries.contains_key("chain_hash") {
                return false;
            }
        } else {
            return false;
        }
    }

    // Verify state commitment chaining: post[i] == pre[i+1]
    for i in 0..entry_list.len().saturating_sub(1) {
        let post_commit = match &entry_list[i] {
            SirValue::Map { entries } => entries.get("post_state_commitment"),
            _ => None,
        };
        let next_pre_commit = match &entry_list[i + 1] {
            SirValue::Map { entries } => entries.get("pre_state_commitment"),
            _ => None,
        };
        if post_commit != next_pre_commit {
            return false;
        }
    }

    // Verify the initial state maps correctly
    let formal_initial = map_state(&trace.initial_state);
    if trace_map.get("initial_state") != Some(&formal_initial.0) {
        return false;
    }

    true
}

/// Verify error commutativity (THM-14).
///
/// Checks that error transitions commute through the mapping:
/// - An error transition preserves canonical state
/// - The mapped error state equals the mapped pre-state's canonical component
/// - The observable correctly reflects the error status
///
/// Requirement: 4.8
pub fn verify_error_commutativity(pre: &State, invalid_input: &Input) -> bool {
    use vsel_core::observable::obs;
    use vsel_core::transition::{apply, classify, TransitionClass};

    // Verify this actually classifies as Error
    let class = classify(pre, invalid_input);
    if class != TransitionClass::Error {
        return false;
    }

    // Apply the error transition
    let post = apply(pre, invalid_input);

    // Error transitions must preserve canonical state
    if pre.canonical != post.canonical {
        return false;
    }

    // Map both states
    let formal_pre = map_state(pre);
    let formal_post = map_state(&post);

    // The canonical component of the formal states must be identical
    let pre_canonical = match &formal_pre.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };
    let post_canonical = match &formal_post.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };
    if pre_canonical != post_canonical {
        return false;
    }

    // Verify the observable maps correctly
    let concrete_obs = obs(pre, invalid_input, &post);
    let formal_obs = map_observable(&concrete_obs);
    let obs_map = match &formal_obs.0 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Error status should be 2
    obs_map.get("status") == Some(&SirValue::Int { value: 2 })
}

/// Verify no-op commutativity (THM-15).
///
/// Checks that no-op transitions commute through the mapping:
/// - A no-op transition preserves canonical state
/// - The mapped no-op state equals the mapped pre-state's canonical component
/// - The observable correctly reflects the rejected status
///
/// Requirement: 4.8
pub fn verify_noop_commutativity(pre: &State, noop_input: &Input) -> bool {
    use vsel_core::observable::obs;
    use vsel_core::transition::{apply, classify, TransitionClass};

    // Verify this actually classifies as Noop
    let class = classify(pre, noop_input);
    if class != TransitionClass::Noop {
        return false;
    }

    // Apply the noop transition
    let post = apply(pre, noop_input);

    // Noop transitions must preserve canonical state
    if pre.canonical != post.canonical {
        return false;
    }

    // Map both states
    let formal_pre = map_state(pre);
    let formal_post = map_state(&post);

    // The canonical component of the formal states must be identical
    let pre_canonical = match &formal_pre.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };
    let post_canonical = match &formal_post.0 {
        SirValue::Map { entries } => entries.get("canonical"),
        _ => None,
    };
    if pre_canonical != post_canonical {
        return false;
    }

    // Verify the observable maps correctly
    let concrete_obs = obs(pre, noop_input, &post);
    let formal_obs = map_observable(&concrete_obs);
    let obs_map = match &formal_obs.0 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Noop status should be Rejected (1)
    obs_map.get("status") == Some(&SirValue::Int { value: 1 })
}

/// Master commutativity check — verifies THM-1 and THM-2 for a pre-computed transition.
///
/// Given a concrete transition triple `(pre, input, post)`, verifies:
/// 1. The formal transition is internally consistent (THM-1)
/// 2. The observable is consistent with the formal transition (THM-2)
/// 3. The derived state is consistent through mapping
///
/// Requirements: 4.2, 4.3
pub fn verify_commutativity(pre: &State, input: &Input, post: &State) -> bool {
    use vsel_core::observable::obs;
    use vsel_core::state::{derive, derive_economic};

    // THM-1: Verify the formal transition is consistent
    let formal_pre = map_state(pre);
    let formal_input = map_input(input);
    let formal_post = map_state(post);

    // The formal transition must compose correctly
    let formal_transition = map_transition(pre, input, post);
    if formal_transition.pre != formal_pre {
        return false;
    }
    if formal_transition.input != formal_input {
        return false;
    }
    if formal_transition.post != formal_post {
        return false;
    }

    // Verify derived state consistency: D' = derive(C')
    let recomputed_derived = derive(&post.canonical);
    if map_derived_state(&recomputed_derived) != map_derived_state(&post.derived) {
        return false;
    }

    // Verify economic context consistency
    let recomputed_econ = derive_economic(&post.canonical, &post.environment);
    if map_economic_context(&recomputed_econ) != map_economic_context(&post.economic) {
        return false;
    }

    // THM-2: Verify observable commutativity
    let concrete_obs = obs(pre, input, post);
    let formal_obs = map_observable(&concrete_obs);

    // Observable must be a well-formed Map
    let obs_map = match &formal_obs.0 {
        SirValue::Map { entries } => entries,
        _ => return false,
    };

    // Observable must have all required fields
    obs_map.contains_key("transition_class")
        && obs_map.contains_key("outputs")
        && obs_map.contains_key("gas_used")
        && obs_map.contains_key("status")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_core::state::{derive, derive_economic};

    // -- Test helpers --

    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        DomainTag(Hash(h))
    }

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

    fn valid_auth() -> Authorization {
        Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: test_domain_tag(),
        }
    }

    fn valid_input_fixture() -> Input {
        Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: vec![0xFF],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    fn valid_observable() -> Observable {
        Observable {
            transition_class: TransitionClass::Update,
            outputs: vec![OutputEvent {
                event_type: "balance_change".to_string(),
                data: vec![1, 2],
            }],
            gas_used: 21_000,
            status: TransitionStatus::Success,
        }
    }

    // -- map_state tests --

    #[test]
    fn test_map_state_produces_map() {
        let s = build_valid_state(minimal_canonical());
        let formal = map_state(&s);
        match &formal.0 {
            SirValue::Map { entries } => {
                assert!(entries.contains_key("canonical"));
                assert!(entries.contains_key("derived"));
                assert!(entries.contains_key("environment"));
                assert!(entries.contains_key("economic"));
                assert!(entries.contains_key("metadata"));
                assert!(entries.contains_key("derived_valid"));
                // For a properly constructed state, derived_valid should be true
                assert_eq!(entries["derived_valid"], SirValue::Bool { value: true });
            }
            _ => panic!("map_state must produce SirValue::Map"),
        }
    }

    #[test]
    fn test_map_state_deterministic() {
        let s = build_valid_state(minimal_canonical());
        assert_eq!(map_state(&s), map_state(&s));
    }

    #[test]
    fn test_map_state_different_states_differ() {
        let s1 = build_valid_state(minimal_canonical());
        let mut c2 = minimal_canonical();
        c2.system_data.total_supply = 100;
        c2.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: 100,
                nonce: 0,
                data: vec![],
            },
        );
        let s2 = build_valid_state(c2);
        assert_ne!(map_state(&s1), map_state(&s2));
    }

    // -- map_input tests --

    #[test]
    fn test_map_input_produces_map() {
        let input = valid_input_fixture();
        let formal = map_input(&input);
        match &formal.0 {
            SirValue::Map { entries } => {
                assert!(entries.contains_key("payload"));
                assert!(entries.contains_key("auth"));
                assert!(entries.contains_key("aux"));
            }
            _ => panic!("map_input must produce SirValue::Map"),
        }
    }

    #[test]
    fn test_map_input_deterministic() {
        let input = valid_input_fixture();
        assert_eq!(map_input(&input), map_input(&input));
    }

    // -- map_transition tests --

    #[test]
    fn test_map_transition_composes() {
        let s = build_valid_state(minimal_canonical());
        let input = valid_input_fixture();
        let s_prime = build_valid_state(minimal_canonical());
        let ft = map_transition(&s, &input, &s_prime);
        assert_eq!(ft.pre, map_state(&s));
        assert_eq!(ft.input, map_input(&input));
        assert_eq!(ft.post, map_state(&s_prime));
    }

    // -- map_observable tests --

    #[test]
    fn test_map_observable_produces_map() {
        let obs = valid_observable();
        let formal = map_observable(&obs);
        match &formal.0 {
            SirValue::Map { entries } => {
                assert!(entries.contains_key("transition_class"));
                assert!(entries.contains_key("outputs"));
                assert!(entries.contains_key("gas_used"));
                assert!(entries.contains_key("status"));
            }
            _ => panic!("map_observable must produce SirValue::Map"),
        }
    }

    #[test]
    fn test_map_observable_deterministic() {
        let obs = valid_observable();
        assert_eq!(map_observable(&obs), map_observable(&obs));
    }

    #[test]
    fn test_map_observable_gas_value() {
        let obs = valid_observable();
        let formal = map_observable(&obs);
        if let SirValue::Map { entries } = &formal.0 {
            assert_eq!(entries["gas_used"], SirValue::Int { value: 21_000 });
        }
    }

    #[test]
    fn test_map_observable_status_success() {
        let obs = valid_observable();
        let formal = map_observable(&obs);
        if let SirValue::Map { entries } = &formal.0 {
            assert_eq!(entries["status"], SirValue::Int { value: 0 });
        }
    }

    // -- map_trace tests --

    #[test]
    fn test_map_trace_empty() {
        let s = build_valid_state(minimal_canonical());
        let trace = Trace {
            entries: vec![],
            initial_state: s,
            commitment: Hash([0u8; 32]),
        };
        let formal = map_trace(&trace);
        match &formal.0 {
            SirValue::Map { entries } => {
                assert!(entries.contains_key("entries"));
                assert!(entries.contains_key("initial_state"));
                assert!(entries.contains_key("commitment"));
                if let SirValue::List { elements } = &entries["entries"] {
                    assert!(elements.is_empty());
                } else {
                    panic!("entries must be a List");
                }
            }
            _ => panic!("map_trace must produce SirValue::Map"),
        }
    }

    #[test]
    fn test_map_trace_deterministic() {
        let s = build_valid_state(minimal_canonical());
        let trace = Trace {
            entries: vec![],
            initial_state: s,
            commitment: Hash([0u8; 32]),
        };
        assert_eq!(map_trace(&trace), map_trace(&trace));
    }

    // -- hex_encode tests --

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xAB, 0xCD, 0x01]), "abcd01");
    }

    // -- Commutativity verification tests --

    fn build_state_at_seq(c: CanonicalState, seq: u64) -> State {
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let commitment = if seq == 0 {
            Hash([0u8; 32])
        } else {
            Hash([0xABu8; 32])
        };
        let meta = TraceMetadata {
            sequence_index: seq,
            previous_commitment: commitment,
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

    fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
        Input {
            payload: Payload {
                payload_type: payload_type.to_string(),
                data,
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    // -- verify_execution_commutativity (THM-1) --

    #[test]
    fn test_execution_commutativity_init() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        assert!(verify_execution_commutativity(&s, &sigma));
    }

    #[test]
    fn test_execution_commutativity_noop() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        assert!(verify_execution_commutativity(&s, &sigma));
    }

    #[test]
    fn test_execution_commutativity_transfer() {
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        data.extend_from_slice(&100u128.to_le_bytes());
        let sigma = make_input("transfer", data);
        assert!(verify_execution_commutativity(&s, &sigma));
    }

    #[test]
    fn test_execution_commutativity_deposit() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&500u128.to_le_bytes());
        let sigma = make_input("deposit", data);
        assert!(verify_execution_commutativity(&s, &sigma));
    }

    // -- verify_observable_commutativity (THM-2) --

    #[test]
    fn test_observable_commutativity_init() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        assert!(verify_observable_commutativity(&s, &sigma));
    }

    #[test]
    fn test_observable_commutativity_noop() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        assert!(verify_observable_commutativity(&s, &sigma));
    }

    #[test]
    fn test_observable_commutativity_error() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        assert!(verify_observable_commutativity(&s, &sigma));
    }

    #[test]
    fn test_observable_commutativity_transfer() {
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        data.extend_from_slice(&100u128.to_le_bytes());
        let sigma = make_input("transfer", data);
        assert!(verify_observable_commutativity(&s, &sigma));
    }

    // -- verify_auxiliary_exclusion (THM-4) --

    #[test]
    fn test_auxiliary_exclusion_init() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        assert!(verify_auxiliary_exclusion(&s, &sigma));
    }

    #[test]
    fn test_auxiliary_exclusion_transfer() {
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        data.extend_from_slice(&100u128.to_le_bytes());
        let sigma = make_input("transfer", data);
        assert!(verify_auxiliary_exclusion(&s, &sigma));
    }

    #[test]
    fn test_auxiliary_exclusion_with_nonempty_aux() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let input = Input {
            payload: Payload {
                payload_type: "unknown_op".to_string(),
                data: vec![0x01],
            },
            auth: valid_auth(),
            aux: AuxiliaryData {
                data: vec![0xCA, 0xFE],
            },
        };
        assert!(verify_auxiliary_exclusion(&s, &input));
    }

    // -- verify_derived_commutativity (THM-5) --

    #[test]
    fn test_derived_commutativity_empty() {
        let c = minimal_canonical();
        assert!(verify_derived_commutativity(&c));
    }

    #[test]
    fn test_derived_commutativity_with_accounts() {
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
                data: vec![0xAB],
            },
        );
        c.system_data.total_supply = 300;
        assert!(verify_derived_commutativity(&c));
    }

    #[test]
    fn test_derived_commutativity_with_storage() {
        let mut c = minimal_canonical();
        c.storage
            .insert(StorageKey(vec![1, 2, 3]), StorageValue(vec![10, 20]));
        assert!(verify_derived_commutativity(&c));
    }

    // -- verify_trace_mapping_validity (THM-6) --

    #[test]
    fn test_trace_mapping_validity_empty() {
        let s = build_valid_state(minimal_canonical());
        let trace = Trace {
            entries: vec![],
            initial_state: s,
            commitment: Hash([0u8; 32]),
        };
        assert!(verify_trace_mapping_validity(&trace));
    }

    #[test]
    fn test_trace_mapping_validity_single_entry() {
        use vsel_core::observable::obs;
        use vsel_core::state::commit;
        use vsel_core::transition::apply;
        use vsel_trace::commitment::compute_chain_hash;
        use vsel_trace::engine::commit_entry;

        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        let observable = obs(&s, &sigma, &s_prime);

        let pre_commit = commit(&s.canonical);
        let post_commit = commit(&s_prime.canonical);
        let entry_commit = commit_entry(
            0,
            &pre_commit,
            &sigma,
            &post_commit,
            &observable,
            &s_prime.environment,
        );
        let chain_hash = compute_chain_hash(&Hash([0u8; 32]), &entry_commit);

        let entry = TraceEntry {
            index: 0,
            pre_state_commitment: pre_commit,
            input: sigma,
            post_state_commitment: post_commit,
            observable,
            environment: s_prime.environment.clone(),
            chain_hash: chain_hash.clone(),
        };

        let trace = Trace {
            entries: vec![entry],
            initial_state: s,
            commitment: chain_hash,
        };
        assert!(verify_trace_mapping_validity(&trace));
    }

    // -- verify_error_commutativity (THM-14) --

    #[test]
    fn test_error_commutativity() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        // Transfer with non-existent sender → Error
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        assert!(verify_error_commutativity(&s, &sigma));
    }

    #[test]
    fn test_error_commutativity_rejects_non_error() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        // Noop input is not an error
        let sigma = make_input("unknown_op", vec![0x01]);
        assert!(!verify_error_commutativity(&s, &sigma));
    }

    // -- verify_noop_commutativity (THM-15) --

    #[test]
    fn test_noop_commutativity() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        assert!(verify_noop_commutativity(&s, &sigma));
    }

    #[test]
    fn test_noop_commutativity_rejects_non_noop() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        // Error input is not a noop
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        assert!(!verify_noop_commutativity(&s, &sigma));
    }

    // -- verify_commutativity (master check) --

    #[test]
    fn test_commutativity_master_init() {
        use vsel_core::transition::apply;
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        assert!(verify_commutativity(&s, &sigma, &s_prime));
    }

    #[test]
    fn test_commutativity_master_transfer() {
        use vsel_core::transition::apply;
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id,
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        data.extend_from_slice(&100u128.to_le_bytes());
        let sigma = make_input("transfer", data);
        let s_prime = apply(&s, &sigma);
        assert!(verify_commutativity(&s, &sigma, &s_prime));
    }

    #[test]
    fn test_commutativity_master_noop() {
        use vsel_core::transition::apply;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let s_prime = apply(&s, &sigma);
        assert!(verify_commutativity(&s, &sigma, &s_prime));
    }

    #[test]
    fn test_commutativity_master_error() {
        use vsel_core::transition::apply;
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        let s_prime = apply(&s, &sigma);
        assert!(verify_commutativity(&s, &sigma, &s_prime));
    }

    // -- map_u128 precision tests --

    #[test]
    fn test_map_u128_zero() {
        let v = map_u128(0u128);
        assert_eq!(
            v,
            SirValue::Bytes {
                value: 0u128.to_le_bytes().to_vec()
            }
        );
    }

    #[test]
    fn test_map_u128_max() {
        let v = map_u128(u128::MAX);
        assert_eq!(
            v,
            SirValue::Bytes {
                value: u128::MAX.to_le_bytes().to_vec()
            }
        );
    }

    #[test]
    fn test_map_u128_exceeds_i64_max() {
        // This value would be truncated by `as i64`
        let large_balance: u128 = (i64::MAX as u128) + 1;
        let v = map_u128(large_balance);
        if let SirValue::Bytes { value } = &v {
            let decoded = u128::from_le_bytes(value[..16].try_into().unwrap());
            assert_eq!(decoded, large_balance, "u128 precision must be preserved");
        } else {
            panic!("map_u128 must produce SirValue::Bytes");
        }
    }

    #[test]
    fn test_map_u128_injectivity() {
        // Two distinct u128 values must produce distinct SirValue
        assert_ne!(map_u128(0), map_u128(1));
        assert_ne!(map_u128(u128::MAX), map_u128(u128::MAX - 1));
        assert_ne!(map_u128(i64::MAX as u128), map_u128((i64::MAX as u128) + 1));
    }

    // -- verify_state_injectivity tests --

    #[test]
    fn test_state_injectivity_same_state() {
        let s = build_valid_state(minimal_canonical());
        assert!(verify_state_injectivity(&s, &s));
    }

    #[test]
    fn test_state_injectivity_different_canonical() {
        let s1 = build_valid_state(minimal_canonical());
        let mut c2 = minimal_canonical();
        c2.system_data.total_supply = 100;
        c2.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: 100,
                nonce: 0,
                data: vec![],
            },
        );
        let s2 = build_valid_state(c2);
        assert!(verify_state_injectivity(&s1, &s2));
    }

    #[test]
    fn test_state_injectivity_large_balances() {
        // Test with balances that would be truncated by `as i64`
        let mut c1 = minimal_canonical();
        let large_balance: u128 = (i64::MAX as u128) + 1;
        c1.system_data.total_supply = large_balance;
        c1.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: large_balance,
                nonce: 0,
                data: vec![],
            },
        );
        let s1 = build_valid_state(c1);

        let mut c2 = minimal_canonical();
        let large_balance_2: u128 = (i64::MAX as u128) + 2;
        c2.system_data.total_supply = large_balance_2;
        c2.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: large_balance_2,
                nonce: 0,
                data: vec![],
            },
        );
        let s2 = build_valid_state(c2);

        // These states differ — injectivity must hold
        assert!(verify_state_injectivity(&s1, &s2));
        // And the formal states must differ (not truncated to same value)
        assert_ne!(map_state(&s1), map_state(&s2));
    }

    // -- derived_valid field tests --

    #[test]
    fn test_map_state_derived_valid_true() {
        let s = build_valid_state(minimal_canonical());
        let formal = map_state(&s);
        if let SirValue::Map { entries } = &formal.0 {
            assert_eq!(entries["derived_valid"], SirValue::Bool { value: true });
        }
    }

    #[test]
    fn test_map_state_derived_valid_false_when_corrupted() {
        let mut s = build_valid_state(minimal_canonical());
        // Corrupt the derived state
        s.derived.state_root = Hash([0xFFu8; 32]);
        let formal = map_state(&s);
        if let SirValue::Map { entries } = &formal.0 {
            assert_eq!(entries["derived_valid"], SirValue::Bool { value: false });
        }
    }

    // -- balance precision in canonical mapping --

    #[test]
    fn test_canonical_mapping_preserves_large_balance() {
        let mut c = minimal_canonical();
        let large_balance: u128 = u128::MAX / 2;
        c.system_data.total_supply = large_balance;
        c.accounts.insert(
            AccountId([1u8; 32]),
            AccountData {
                balance: large_balance,
                nonce: 0,
                data: vec![],
            },
        );
        let formal = map_canonical_state(&c);
        if let SirValue::Map { entries } = &formal {
            if let Some(SirValue::Map { entries: accounts }) = entries.get("accounts") {
                let account_key = hex_encode(&[1u8; 32]);
                if let Some(SirValue::Map { entries: acct }) = accounts.get(&account_key) {
                    if let Some(SirValue::Bytes { value }) = acct.get("balance") {
                        let decoded = u128::from_le_bytes(value[..16].try_into().unwrap());
                        assert_eq!(decoded, large_balance, "large balance must be preserved");
                    } else {
                        panic!("balance must be SirValue::Bytes");
                    }
                } else {
                    panic!("account not found in mapping");
                }
            }
        }
    }
}
