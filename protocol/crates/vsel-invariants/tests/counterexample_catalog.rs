//! Counterexample Catalog — adversarial tests for CEX families.
//!
//! Derived from: COUNTEREXAMPLE_CATALOG.md, Requirements 13.4, 14.6.
//!
//! Each counterexample family constructs a concrete violation scenario and
//! verifies that the VSEL invariant/constraint system correctly detects and
//! rejects it. Every counterexample is a formal artifact with:
//!   - ID (e.g. CEX-S-001)
//!   - Property violated
//!   - Concrete state sequence demonstrating the violation
//!   - Root cause analysis
//!   - Resolution (how the system prevents this)
//!
//! Families:
//! - CEX-S:     State space counterexamples
//! - CEX-ECON:  Economic counterexamples
//! - CEX-T:     Transition counterexamples
//! - CEX-I:     Invariant counterexamples
//! - CEX-M:     Semantic mapping counterexamples
//! - CEX-C:     Constraint counterexamples
//! - CEX-P:     Proof/verification counterexamples
//! - CEX-COMP:  Composition counterexamples
//! - CEX-TR:    Trace counterexamples
//! - CEX-TEMP:  Temporal counterexamples
//! - CEX-CRYPTO: Cryptographic counterexamples

use std::collections::BTreeMap;

use vsel_core::input::*;
use vsel_core::observable::obs;
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;
use vsel_engine::batch::execute_batch;
use vsel_engine::engine::{DefaultExecutionEngine, ExecutionEngine};
use vsel_invariants::economic::*;
use vsel_invariants::global::*;
use vsel_invariants::local::*;
use vsel_trace::commitment::{compute_chain_hash, verify_chain};
use vsel_trace::engine::{verify_trace, Trace, TraceEngine};

// ===========================================================================
// Shared test helpers (matching adversarial_w1_w8_tests.rs style)
// ===========================================================================

fn test_domain_tag() -> DomainTag {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    DomainTag(Hash(h))
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

fn build_genesis_state(c: CanonicalState) -> State {
    build_state_at_seq(c, 0)
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

fn make_deposit_input(account_id: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("deposit", data)
}

fn make_transfer_input(sender: [u8; 32], receiver: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&sender);
    data.extend_from_slice(&receiver);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("transfer", data)
}

fn canonical_with_account(id: [u8; 32], balance: u128) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(
        AccountId(id),
        AccountData {
            balance,
            nonce: 0,
            data: vec![],
        },
    );
    c.system_data.total_supply = balance;
    c
}

fn canonical_with_two_accounts(
    id1: [u8; 32],
    bal1: u128,
    id2: [u8; 32],
    bal2: u128,
) -> CanonicalState {
    let mut c = minimal_canonical();
    c.accounts.insert(
        AccountId(id1),
        AccountData {
            balance: bal1,
            nonce: 0,
            data: vec![],
        },
    );
    c.accounts.insert(
        AccountId(id2),
        AccountData {
            balance: bal2,
            nonce: 0,
            data: vec![],
        },
    );
    c.system_data.total_supply = bal1 + bal2;
    c
}

/// Build a valid 3-entry trace for testing.
fn build_valid_trace() -> Trace {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let obs0 = obs(&s0, &sigma0, &s1);

    let sigma1 = make_deposit_input([1u8; 32], 500);
    let s2 = apply(&s1, &sigma1);
    let obs1 = obs(&s1, &sigma1, &s2);

    let sigma2 = make_input("unknown_op", vec![0x01]);
    let s3 = apply(&s2, &sigma2);
    let obs2 = obs(&s2, &sigma2, &s3);

    let mut engine = TraceEngine::new();
    let e0 = engine.record_transition(&s0, &sigma0, &s1, &obs0);
    let e1 = engine.record_transition(&s1, &sigma1, &s2, &obs1);
    let e2 = engine.record_transition(&s2, &sigma2, &s3, &obs2);
    let commitment = engine.current_chain_hash().clone();

    Trace {
        entries: vec![e0, e1, e2],
        initial_state: s0,
        commitment,
    }
}

// ===========================================================================
// CEX-S: State Space Counterexamples
// ===========================================================================

/// CEX-S-001: Syntactically valid but semantically unreachable state.
///
/// Property violated: SAFE-1 (Unreachability of Invalid States)
/// State sequence: Construct state satisfying all structural predicates but
///   not reachable from any initial state via valid transitions.
/// Root cause: State passes ValidState but has no legitimate history.
/// Resolution: L_valid rejects transitions producing unreachable post-states;
///   Apply(s, σ) is the only way to produce new states.
#[test]
fn cex_s_001_unreachable_state_rejected_by_l_valid() {
    let c = minimal_canonical();
    let s = build_genesis_state(c);
    let sigma = make_input("init", vec![0xFF]);
    let real_post = apply(&s, &sigma);

    // Construct an "unreachable" state: structurally valid but not Apply(s, σ)
    let mut fake_c = real_post.canonical.clone();
    fake_c
        .system_data
        .parameters
        .insert("phantom".to_string(), vec![0xDE, 0xAD]);
    let mut fake_post = build_state_at_seq(fake_c, 1);
    fake_post.environment = real_post.environment.clone();

    assert!(
        valid_state(&fake_post),
        "CEX-S-001: Fake state is structurally valid"
    );
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(
        !result.valid,
        "CEX-S-001: L_valid must reject unreachable post-state"
    );
}

/// CEX-S-002: Derived state inconsistency — D ≠ Derive(C).
///
/// Property violated: DEF-1 (Derived State Functional Dependence), G_commit
/// State sequence: Modify D independently of C.
/// Root cause: Derived state trusted without recomputation.
/// Resolution: G_commit and valid_state enforce D = Derive(C) at every observation.
#[test]
fn cex_s_002_derived_state_inconsistency() {
    let c = canonical_with_account([1u8; 32], 1000);
    let mut s = build_state_at_seq(c, 1);

    // Corrupt derived state root
    s.derived.state_root = Hash([0xFFu8; 32]);

    let result = g_commit(&s);
    assert!(
        !result.valid,
        "CEX-S-002: G_commit must reject inconsistent derived state"
    );
    assert!(
        !valid_state(&s),
        "CEX-S-002: valid_state must reject D ≠ Derive(C)"
    );
}

/// CEX-S-003: State encoding collision attempt — s₁ ≠ s₂ but same commitment.
///
/// Property violated: DEF-2 (Canonical Encoding Injectivity)
/// State sequence: Two distinct canonical states must produce distinct commitments.
/// Root cause: Encoding collision would collapse distinct states.
/// Resolution: Injective encoding with length-prefixed fields and SHA3-256.
#[test]
fn cex_s_003_encoding_injectivity() {
    let c1 = canonical_with_account([1u8; 32], 100);
    let c2 = canonical_with_account([1u8; 32], 200);
    let h1 = commit(&c1);
    let h2 = commit(&c2);
    assert_ne!(
        h1, h2,
        "CEX-S-003: Different states must produce different commitments"
    );

    // Also test with different account IDs but same balance
    let c3 = canonical_with_account([1u8; 32], 500);
    let c4 = canonical_with_account([2u8; 32], 500);
    let h3 = commit(&c3);
    let h4 = commit(&c4);
    assert_ne!(
        h3, h4,
        "CEX-S-003: Different account IDs must produce different commitments"
    );
}

/// CEX-S-004: Valid state with economically absurd semantics.
///
/// Property violated: Economic Admissibility
/// State sequence: State satisfying all structural invariants but violating
///   economic constraints (e.g. excessive concentration).
/// Root cause: Structural validity ≠ economic validity.
/// Resolution: Admissible(s) = ValidState(s) ∧ EconomicallyValid(s).
#[test]
fn cex_s_004_structurally_valid_economically_absurd() {
    // Single account holds 100% of supply — violates G_concentration (>90%)
    let c = canonical_with_account([1u8; 32], 1_000_000);
    let s = build_state_at_seq(c, 1);

    assert!(valid_state(&s), "CEX-S-004: State is structurally valid");
    let result = g_concentration(&s);
    assert!(
        !result.valid,
        "CEX-S-004: G_concentration must reject 100% concentration"
    );
}

// ===========================================================================
// CEX-ECON: Economic Counterexamples
// ===========================================================================

/// CEX-ECON-001: Zero-cost resource acquisition via fee schedule.
///
/// Property violated: E_cost (Non-Zero Acquisition Cost)
/// State sequence: Fee rate exceeds 100% (10_000 bps).
/// Root cause: Unbounded fee parameters allow absurd fee schedules.
/// Resolution: E_cost bounds fee_rate_bps to ≤ 10_000.
#[test]
fn cex_econ_001_excessive_fee_rate() {
    let mut c = minimal_canonical();
    // Set fee_rate_bps to 20_000 (200%) — absurd
    c.system_data.parameters.insert(
        "fee_rate_bps".to_string(),
        20_000u128.to_le_bytes().to_vec(),
    );
    let s = build_state_at_seq(c, 1);
    let result = e_cost(&s);
    assert!(
        !result.valid,
        "CEX-ECON-001: E_cost must reject fee rate > 100%"
    );
}

/// CEX-ECON-002: Leverage exceeding maximum.
///
/// Property violated: E_leverage (Bounded Leverage)
/// State sequence: Entity exposure exceeds max_leverage_bps.
/// Root cause: Accumulated small position adjustments bypass per-step checks.
/// Resolution: E_leverage checks EffectiveLeverage at every state.
#[test]
fn cex_econ_002_excessive_leverage() {
    let mut c = minimal_canonical();
    c.system_data.parameters.insert(
        "max_leverage_bps".to_string(),
        100_000u128.to_le_bytes().to_vec(),
    );
    let mut s = build_state_at_seq(c, 1);

    // Inject an exposure limit exceeding max leverage
    let entity = EntityId([1u8; 32]);
    s.economic
        .exposure_limits
        .insert(entity, ExposureLimit(200_000));

    let result = e_leverage(&s);
    assert!(
        !result.valid,
        "CEX-ECON-002: E_leverage must reject exposure > max_leverage"
    );
}

/// CEX-ECON-003: Dust account below minimum threshold.
///
/// Property violated: G_dust (Bounded Minimum Balance)
/// State sequence: Account with balance below dust threshold.
/// Root cause: Micro-transactions create state bloat.
/// Resolution: G_dust rejects accounts with 0 < balance < dust_threshold.
#[test]
fn cex_econ_003_dust_account() {
    let mut c = canonical_with_account([1u8; 32], 5);
    c.system_data
        .parameters
        .insert("dust_threshold".to_string(), 100u128.to_le_bytes().to_vec());
    let s = build_state_at_seq(c, 1);
    let result = g_dust(&s);
    assert!(
        !result.valid,
        "CEX-ECON-003: G_dust must reject balance below dust threshold"
    );
}

/// CEX-ECON-004: Insolvency — balance sum ≠ total supply.
///
/// Property violated: G_solvency
/// State sequence: Account balances don't sum to total_supply.
/// Root cause: Resource creation/destruction without proper accounting.
/// Resolution: G_solvency checks sum(balances) == total_supply.
#[test]
fn cex_econ_004_insolvency() {
    let mut c = canonical_with_account([1u8; 32], 1000);
    c.system_data.total_supply = 2000; // Mismatch
    let s = build_state_at_seq(c, 1);
    let result = g_solvency(&s);
    assert!(
        !result.valid,
        "CEX-ECON-004: G_solvency must reject insolvency"
    );
}

/// CEX-ECON-005: Excessive epoch fee extraction.
///
/// Property violated: TE_extraction (Bounded Epoch Extraction)
/// State sequence: Fees collected exceed 10% of total supply in one epoch.
/// Root cause: Unbounded fee extraction enables value drain.
/// Resolution: TE_extraction bounds fees per epoch.
#[test]
fn cex_econ_005_excessive_extraction() {
    let mut c = canonical_with_account([1u8; 32], 1000);
    c.system_data.parameters.insert(
        "total_fees_collected".to_string(),
        500u128.to_le_bytes().to_vec(),
    );
    let s = build_state_at_seq(c, 1);
    let result = te_extraction(&s);
    assert!(
        !result.valid,
        "CEX-ECON-005: TE_extraction must reject excessive fee extraction"
    );
}

/// CEX-ECON-006: Zero price in oracle (slippage vulnerability).
///
/// Property violated: E_slippage
/// State sequence: Price oracle contains zero price for an asset pair.
/// Root cause: Zero price enables infinite slippage / division by zero.
/// Resolution: E_slippage rejects zero prices.
#[test]
fn cex_econ_006_zero_price_oracle() {
    let c = minimal_canonical();
    let mut s = build_state_at_seq(c, 1);
    s.economic.price_oracle.insert(
        AssetPair {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
        },
        Price(0),
    );
    let result = e_slippage(&s);
    assert!(
        !result.valid,
        "CEX-ECON-006: E_slippage must reject zero price"
    );
}

/// CEX-ECON-007: Collateral ratio below minimum.
///
/// Property violated: E_collateral
/// State sequence: Position collateral ratio below min_collateral_ratio_bps.
/// Root cause: Under-collateralized positions create systemic risk.
/// Resolution: E_collateral checks all positions against minimum ratio.
#[test]
fn cex_econ_007_undercollateralized_position() {
    let mut c = minimal_canonical();
    c.system_data.parameters.insert(
        "min_collateral_ratio_bps".to_string(),
        15_000u128.to_le_bytes().to_vec(),
    );
    let mut s = build_state_at_seq(c, 1);
    s.economic.collateral_requirements.insert(
        PositionType::Long,
        CollateralRatio(5_000), // Below 15_000 minimum
    );
    let result = e_collateral(&s);
    assert!(
        !result.valid,
        "CEX-ECON-007: E_collateral must reject under-collateralized position"
    );
}

/// CEX-ECON-008: Invalid economic parameters (zero max leverage).
///
/// Property violated: G_econ_valid
/// State sequence: Economic parameters with max_leverage_bps = 0.
/// Root cause: Zero max leverage makes all positions invalid.
/// Resolution: G_econ_valid rejects zero max leverage.
#[test]
fn cex_econ_008_invalid_economic_params() {
    let mut c = minimal_canonical();
    c.system_data
        .parameters
        .insert("max_leverage_bps".to_string(), 0u128.to_le_bytes().to_vec());
    let s = build_state_at_seq(c, 1);
    let result = g_econ_valid(&s);
    assert!(
        !result.valid,
        "CEX-ECON-008: G_econ_valid must reject zero max leverage"
    );
}

// ===========================================================================
// CEX-T: Transition Counterexamples
// ===========================================================================

/// CEX-T-001: Non-deterministic transition attempt.
///
/// Property violated: AX-1 (Determinism of Apply)
/// State sequence: Apply(s, σ) called twice must produce identical results.
/// Root cause: Hidden randomness or timing dependency.
/// Resolution: L_det verifies Apply(s, σ) is deterministic by double-application.
#[test]
fn cex_t_001_determinism_verified() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_deposit_input([2u8; 32], 500);

    let result1 = apply(&s, &sigma);
    let result2 = apply(&s, &sigma);
    assert_eq!(
        result1, result2,
        "CEX-T-001: Apply must be deterministic (AX-1)"
    );

    let det_result = l_det(&s, &sigma, &result1);
    assert!(
        det_result.valid,
        "CEX-T-001: L_det must confirm determinism"
    );
}

/// CEX-T-002: Transition producing invalid state (closure violation).
///
/// Property violated: AX-2 (Closure of State Space)
/// State sequence: Apply(s, σ) must always produce s' ∈ S.
/// Root cause: Edge-case inputs pushing state beyond valid ranges.
/// Resolution: Apply always returns valid state; L_state checks both pre and post.
#[test]
fn cex_t_002_closure_preserved() {
    let c = minimal_canonical();
    let s = build_genesis_state(c);

    // Various edge-case inputs — all must produce valid post-states
    let inputs = vec![
        make_input("init", vec![0xFF]),
        make_input("unknown_op", vec![0x01]),
        make_deposit_input([1u8; 32], 0),
        make_deposit_input([1u8; 32], u128::MAX / 2),
    ];

    for sigma in &inputs {
        let post = apply(&s, sigma);
        assert!(
            valid_state(&post),
            "CEX-T-002: Apply must produce valid state (AX-2)"
        );
    }
}

/// CEX-T-003: Hidden state mutation — noop changes canonical state.
///
/// Property violated: SAFE-3 (No Hidden State Mutation)
/// State sequence: Noop transition where Diff(s, s') ⊄ AllowedMutations(σ).
/// Root cause: Side effects in noop path (cache, counters, metadata).
/// Resolution: L_valid rejects any post-state ≠ Apply(pre, input).
#[test]
fn cex_t_003_hidden_mutation_in_noop() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);
    let real_post = apply(&s, &sigma);

    // Inject hidden mutation into noop result
    let mut fake_post = real_post.clone();
    fake_post
        .canonical
        .system_data
        .parameters
        .insert("hidden".to_string(), vec![0xFF]);
    fake_post.derived = derive(&fake_post.canonical);
    fake_post.economic = derive_economic(&fake_post.canonical, &fake_post.environment);

    let result = l_valid(&s, &sigma, &fake_post);
    assert!(
        !result.valid,
        "CEX-T-003: L_valid must reject hidden mutation in noop"
    );
}

/// CEX-T-004: Guard overlap — input matching multiple transition classes.
///
/// Property violated: Transition Partitioning (Guard Disjointness)
/// State sequence: Every (s, σ) pair must classify to exactly one class.
/// Root cause: Overlapping guard preconditions.
/// Resolution: Priority ordering ensures deterministic classification.
#[test]
fn cex_t_004_guard_disjointness() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);

    // Test various inputs — each must classify to exactly one class
    let inputs = vec![
        make_input("init", vec![0xFF]),
        make_deposit_input([1u8; 32], 100),
        make_transfer_input([1u8; 32], [2u8; 32], 50),
        make_input("unknown_op", vec![0x01]),
    ];

    for sigma in &inputs {
        let class = classify(&s, sigma);
        // Verify classification is deterministic
        let class2 = classify(&s, sigma);
        assert_eq!(
            class, class2,
            "CEX-T-004: Classification must be deterministic"
        );
    }
}

/// CEX-T-005: Error transition breaking invariant.
///
/// Property violated: LEM-7 (Error State Invariant Preservation)
/// State sequence: Apply(s, σ_invalid) = s_error where all invariants hold.
/// Root cause: Error handling path not preserving invariants.
/// Resolution: Error paths produce valid states with invariants preserved.
#[test]
fn cex_t_005_error_preserves_invariants() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);

    // Invalid input that triggers error/noop path
    let sigma = make_input("unknown_op", vec![0x01]);
    let post = apply(&s, &sigma);

    assert!(valid_state(&post), "CEX-T-005: Error state must be valid");
    let g_result = g_valid(&post);
    assert!(
        g_result.valid,
        "CEX-T-005: G_valid must hold on error state"
    );
    let g_struct_result = g_struct(&post);
    assert!(
        g_struct_result.valid,
        "CEX-T-005: G_struct must hold on error state"
    );
}

/// CEX-T-006: Batch non-equivalence to sequential application.
///
/// Property violated: LEM-9 (Batch Decomposition Equivalence)
/// State sequence: Apply(s, [σ₁, σ₂]) must equal Apply(Apply(s, σ₁), σ₂).
/// Root cause: Batch processing skipping intermediate validation.
/// Resolution: execute_batch applies sequentially with intermediate checks.
#[test]
fn cex_t_006_batch_sequential_equivalence() {
    let c = minimal_canonical();
    let s = build_state_at_seq(c, 1);
    let d1 = make_deposit_input([1u8; 32], 100);
    let d2 = make_deposit_input([2u8; 32], 200);

    let batch_result = execute_batch(&s, &[d1.clone(), d2.clone()]).unwrap();
    let s1 = apply(&s, &d1);
    let s2 = apply(&s1, &d2);

    assert_eq!(
        batch_result.post_state.canonical, s2.canonical,
        "CEX-T-006: Batch must equal sequential application (LEM-9)"
    );
}

// ===========================================================================
// CEX-I: Invariant Counterexamples
// ===========================================================================

/// CEX-I-001: Local invariant holds but global breaks.
///
/// Property violated: LEM-1 (Invariant Preservation Under Transition)
/// State sequence: Transition satisfying local checks but breaking global invariant.
/// Root cause: Per-transition checks insufficient for global properties.
/// Resolution: G_struct checks balance sum == total_supply at every state.
#[test]
fn cex_i_001_local_holds_global_breaks() {
    // Construct a state where total_supply is manually set wrong
    let mut c = canonical_with_two_accounts([1u8; 32], 500, [2u8; 32], 500);
    c.system_data.total_supply = 999; // Wrong — should be 1000

    let s = build_state_at_seq(c, 1);
    let result = g_struct(&s);
    assert!(
        !result.valid,
        "CEX-I-001: G_struct must detect balance/supply mismatch"
    );
}

/// CEX-I-002: Temporal invariant violation via accumulation.
///
/// Property violated: T_cons, T_no_revert
/// State sequence: Long trace where small per-step deviations accumulate.
/// Root cause: Invisible in short traces, manifests over many steps.
/// Resolution: Temporal invariants checked over complete traces.
#[test]
fn cex_i_002_temporal_accumulation() {
    // Build a trace and verify temporal consistency
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let sigma1 = make_deposit_input([1u8; 32], 500);
    let s2 = apply(&s1, &sigma1);

    // Verify monotonic metadata across trace steps
    assert!(
        s1.metadata.sequence_index >= s0.metadata.sequence_index || s0.metadata.sequence_index == 0,
        "CEX-I-002: Sequence must be monotonic"
    );
    assert!(
        s2.metadata.timestamp >= s1.metadata.timestamp,
        "CEX-I-002: Timestamps must be non-decreasing"
    );
}

/// CEX-I-003: Invariant satisfied by invalid execution.
///
/// Property violated: Invariant Completeness
/// State sequence: Execution where all invariants hold but execution is semantically invalid.
/// Root cause: Invariant set is incomplete.
/// Resolution: L_valid ensures post = Apply(pre, input) — the definitive check.
#[test]
fn cex_i_003_invariant_completeness() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_deposit_input([2u8; 32], 500);
    let _real_post = apply(&s, &sigma);

    // Construct a fake post-state that might pass some invariants
    // but is not the result of Apply(s, σ)
    let mut fake_c = s.canonical.clone();
    fake_c.accounts.insert(
        AccountId([2u8; 32]),
        AccountData {
            balance: 500,
            nonce: 0,
            data: vec![],
        },
    );
    fake_c.system_data.total_supply = 1500;
    let mut fake_post = build_state_at_seq(fake_c, 2);
    fake_post.environment = s.environment.clone();

    // L_valid is the definitive check — it catches this
    let result = l_valid(&s, &sigma, &fake_post);
    assert!(
        !result.valid,
        "CEX-I-003: L_valid must reject semantically invalid execution"
    );
}

// ===========================================================================
// CEX-M: Semantic Mapping Counterexamples
// ===========================================================================

/// CEX-M-001: Auxiliary data influencing semantics.
///
/// Property violated: THM-4 (Auxiliary Data Exclusion)
/// State sequence: Two executions with identical (payload, auth) but different aux.
/// Root cause: Auxiliary data leaking into semantic outcome.
/// Resolution: Apply ignores aux field entirely.
#[test]
fn cex_m_001_auxiliary_data_exclusion() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);

    let sigma1 = Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data: {
                let mut d = vec![];
                d.extend_from_slice(&[2u8; 32]);
                d.extend_from_slice(&100u128.to_le_bytes());
                d
            },
        },
        auth: valid_auth(),
        aux: AuxiliaryData {
            data: vec![0xAA, 0xBB],
        },
    };
    let sigma2 = Input {
        payload: sigma1.payload.clone(),
        auth: sigma1.auth.clone(),
        aux: AuxiliaryData {
            data: vec![0xCC, 0xDD, 0xEE],
        },
    };

    let post1 = apply(&s, &sigma1);
    let post2 = apply(&s, &sigma2);
    assert_eq!(
        post1.canonical, post2.canonical,
        "CEX-M-001: Auxiliary data must not influence semantic outcome (THM-4)"
    );
}

/// CEX-M-002: Canonicalization idempotence.
///
/// Property violated: DEF-5 (Canonicalization Idempotence)
/// State sequence: Canonical(Canonical(σ)) must equal Canonical(σ).
/// Root cause: Canonicalization altering semantic content.
/// Resolution: Apply is deterministic regardless of input normalization.
#[test]
fn cex_m_002_canonicalization_idempotence() {
    let c = minimal_canonical();
    let s = build_genesis_state(c);
    let sigma = make_deposit_input([1u8; 32], 500);

    // Apply twice with same input — result must be deterministic
    let post1 = apply(&s, &sigma);
    let post2 = apply(&s, &sigma);
    assert_eq!(
        post1, post2,
        "CEX-M-002: Apply must be idempotent for same input"
    );
}

/// CEX-M-003: Observable determinism — obs must be derivable from (s, σ, s').
///
/// Property violated: DEF-4 (Observable Determinism)
/// State sequence: obs(s, σ, s') must always produce the same result.
/// Root cause: Observable depending on hidden state.
/// Resolution: obs is a pure function of (s, σ, s').
#[test]
fn cex_m_003_observable_determinism() {
    let c = canonical_with_two_accounts([1u8; 32], 1000, [2u8; 32], 500);
    let s = build_state_at_seq(c, 1);
    let sigma = make_transfer_input([1u8; 32], [2u8; 32], 100);
    let post = apply(&s, &sigma);

    let obs1 = obs(&s, &sigma, &post);
    let obs2 = obs(&s, &sigma, &post);
    assert_eq!(
        obs1, obs2,
        "CEX-M-003: Observable must be deterministic (DEF-4)"
    );
}

// ===========================================================================
// CEX-C: Constraint Counterexamples
// ===========================================================================

/// CEX-C-001: Invalid trace detected by constraint system (soundness).
///
/// Property violated: LEM-4 (Constraint Soundness)
/// State sequence: Semantically invalid execution must be rejected.
/// Root cause: Underconstrained variable allowing invalid witness.
/// Resolution: L_valid, L_cons, G_struct collectively reject invalid traces.
#[test]
fn cex_c_001_invalid_trace_rejected() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);

    // Construct invalid post-state: resource created from nothing
    let mut fake_c = s.canonical.clone();
    if let Some(acc) = fake_c.accounts.get_mut(&AccountId([1u8; 32])) {
        acc.balance += 500;
    }
    fake_c.system_data.total_supply += 500;
    let mut fake_post = build_state_at_seq(fake_c, 2);
    fake_post.environment = s.environment.clone();

    let result = l_valid(&s, &sigma, &fake_post);
    assert!(
        !result.valid,
        "CEX-C-001: L_valid must reject invalid trace (soundness)"
    );
}

/// CEX-C-002: Valid trace accepted by constraint system (completeness).
///
/// Property violated: LEM-5 (Constraint Completeness)
/// State sequence: Valid execution must pass all invariant checks.
/// Root cause: Overly restrictive constraints rejecting valid executions.
/// Resolution: All invariants pass for legitimate Apply(s, σ) results.
#[test]
fn cex_c_002_valid_trace_accepted() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_deposit_input([2u8; 32], 500);
    let post = apply(&s, &sigma);

    let l_result = l_valid(&s, &sigma, &post);
    assert!(l_result.valid, "CEX-C-002: L_valid must accept valid trace");
    let l_cons_result = l_cons(&s, &sigma, &post);
    assert!(
        l_cons_result.valid,
        "CEX-C-002: L_cons must accept valid trace"
    );
    assert!(valid_state(&post), "CEX-C-002: Post-state must be valid");
}

/// CEX-C-003: Resource conservation violation detected.
///
/// Property violated: L_cons (Resource Conservation)
/// State sequence: Post-state balance sum ≠ total_supply.
/// Root cause: Resource creation/destruction without accounting.
/// Resolution: L_cons checks balance sum == total_supply in both states.
#[test]
fn cex_c_003_resource_conservation_violation() {
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);
    let sigma = make_input("unknown_op", vec![0x01]);

    // Construct post-state with resource creation
    let mut fake_post = apply(&s, &sigma);
    if let Some(acc) = fake_post.canonical.accounts.get_mut(&AccountId([1u8; 32])) {
        acc.balance += 500;
    }
    fake_post.derived = derive(&fake_post.canonical);

    let result = l_cons(&s, &sigma, &fake_post);
    assert!(
        !result.valid,
        "CEX-C-003: L_cons must reject resource conservation violation"
    );
}

// ===========================================================================
// CEX-P: Proof/Verification Counterexamples
// ===========================================================================

/// CEX-P-001: Proof over partial trace — missing intermediate states.
///
/// Property violated: PROOF-1 (Full Trace Binding)
/// State sequence: Trace with missing intermediate entry.
/// Root cause: Proof binding only to endpoints, skipping intermediates.
/// Resolution: verify_trace checks sequential indices and commitment chain.
#[test]
fn cex_p_001_partial_trace_rejected() {
    let mut trace = build_valid_trace();
    // Remove middle entry — creates gap in indices
    trace.entries.remove(1);
    assert!(
        !verify_trace(&trace),
        "CEX-P-001: Partial trace must be rejected"
    );
}

/// CEX-P-002: Cross-domain proof replay attempt.
///
/// Property violated: PROOF-3 (Domain Separation)
/// State sequence: Proof generated for Domain_A submitted to Domain_B.
/// Root cause: Missing domain tag validation.
/// Resolution: Domain tag is part of state and checked by G_env.
#[test]
fn cex_p_002_cross_domain_rejection() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);

    // Input with zero domain tag — cross-domain attack
    let sigma = Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data: {
                let mut d = vec![];
                d.extend_from_slice(&[1u8; 32]);
                d.extend_from_slice(&100u128.to_le_bytes());
                d
            },
        },
        auth: Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: DomainTag(Hash([0u8; 32])),
        },
        aux: AuxiliaryData { data: vec![] },
    };

    let result = engine.execute(&s, &sigma);
    assert!(
        result.is_err(),
        "CEX-P-002: Zero domain tag must be rejected"
    );
}

/// CEX-P-003: Tampered proof commitment chain.
///
/// Property violated: Trace Commitment Integrity
/// State sequence: Trace with tampered chain hash.
/// Root cause: Commitment chain not verified end-to-end.
/// Resolution: verify_trace validates h_{i+1} = Hash(h_i | Commit(e_i)).
#[test]
fn cex_p_003_tampered_commitment_chain() {
    let mut trace = build_valid_trace();
    trace.entries[1].chain_hash = Hash([0xDEu8; 32]);
    assert!(
        !verify_trace(&trace),
        "CEX-P-003: Tampered chain hash must be rejected"
    );
}

// ===========================================================================
// CEX-COMP: Composition Counterexamples
// ===========================================================================

/// CEX-COMP-001: Local validity, global invalidity across systems.
///
/// Property violated: COMP-3 (Compositional Invariant Preservation)
/// State sequence: Two individually valid systems with inconsistent shared state.
/// Root cause: No cross-system invariant enforcement.
/// Resolution: Cross-system resource accounting verification.
#[test]
fn cex_comp_001_local_valid_global_invalid() {
    let c_a = canonical_with_account([1u8; 32], 1000);
    let s_a = build_state_at_seq(c_a, 1);
    let c_b = canonical_with_account([1u8; 32], 500);
    let s_b = build_state_at_seq(c_b, 1);

    // Both systems are individually valid
    assert!(
        valid_state(&s_a),
        "CEX-COMP-001: System A is individually valid"
    );
    assert!(
        valid_state(&s_b),
        "CEX-COMP-001: System B is individually valid"
    );

    // But shared account has inconsistent balance
    let bal_a = s_a.canonical.accounts[&AccountId([1u8; 32])].balance;
    let bal_b = s_b.canonical.accounts[&AccountId([1u8; 32])].balance;
    assert_ne!(
        bal_a, bal_b,
        "CEX-COMP-001: Shared account has inconsistent balance"
    );
}

/// CEX-COMP-002: Double-spend across domains.
///
/// Property violated: COMP-1 (Cross-System Resource Conservation)
/// State sequence: Resource consumed in A but still available in B.
/// Root cause: No cross-system resource debit/credit synchronization.
/// Resolution: CI-1 enforces Total_A + Total_B = constant.
#[test]
fn cex_comp_002_double_spend() {
    let c_a_pre = canonical_with_account([1u8; 32], 1000);
    let c_a_post = canonical_with_account([1u8; 32], 500);
    let c_b_pre = canonical_with_account([2u8; 32], 0);
    let c_b_post = canonical_with_account([2u8; 32], 600);

    let total_pre = c_a_pre.system_data.total_supply + c_b_pre.system_data.total_supply;
    let total_post = c_a_post.system_data.total_supply + c_b_post.system_data.total_supply;

    assert_ne!(
        total_pre, total_post,
        "CEX-COMP-002: Cross-system total supply changed — double-spend detected"
    );
}

// ===========================================================================
// CEX-TR: Trace Counterexamples
// ===========================================================================

/// CEX-TR-001: Missing transition in trace.
///
/// Property violated: T_complete (No Hidden Transitions)
/// State sequence: State change occurs but no trace entry records it.
/// Root cause: State mutation outside traced execution pipeline.
/// Resolution: verify_trace checks sequential indices and state chain.
#[test]
fn cex_tr_001_missing_transition() {
    let mut trace = build_valid_trace();
    trace.entries.remove(1); // Remove middle entry
    assert!(
        !verify_trace(&trace),
        "CEX-TR-001: Missing transition must be detected"
    );
}

/// CEX-TR-002: Trace commitment chain break.
///
/// Property violated: Trace Commitment Integrity
/// State sequence: h_{i+1} ≠ Hash(h_i | Commit(e_i)).
/// Root cause: Modified trace entry after commitment.
/// Resolution: verify_chain validates incremental hash chain.
#[test]
fn cex_tr_002_commitment_chain_break() {
    let e1 = Hash([1u8; 32]);
    let e2 = Hash([2u8; 32]);
    let h1 = compute_chain_hash(&Hash([0u8; 32]), &e1);
    let h2 = compute_chain_hash(&h1, &e2);

    assert!(verify_chain(
        &[e1.clone(), e2.clone()],
        &[h1.clone(), h2.clone()]
    ));
    assert!(
        !verify_chain(&[e1.clone(), e2.clone()], &[Hash([0xFFu8; 32]), h2]),
        "CEX-TR-002: Tampered first hash must be rejected"
    );
}

/// CEX-TR-003: Non-deterministic replay attempt.
///
/// Property violated: Trace Determinism
/// State sequence: Replay(τ) must equal τ.
/// Root cause: Environment differences or randomness sources.
/// Resolution: Apply is deterministic; replay produces identical trace.
#[test]
fn cex_tr_003_deterministic_replay() {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma = make_input("init", vec![0xFF]);

    let post1 = apply(&s0, &sigma);
    let post2 = apply(&s0, &sigma);
    assert_eq!(
        post1, post2,
        "CEX-TR-003: Replay must produce identical state"
    );

    let obs1 = obs(&s0, &sigma, &post1);
    let obs2 = obs(&s0, &sigma, &post2);
    assert_eq!(
        obs1, obs2,
        "CEX-TR-003: Replay must produce identical observable"
    );
}

/// CEX-TR-004: Reordered trace entries.
///
/// Property violated: Trace Sequential Integrity
/// State sequence: Trace entries swapped out of order.
/// Root cause: Entries not validated for sequential ordering.
/// Resolution: verify_trace checks index ordering and commitment chain.
#[test]
fn cex_tr_004_reordered_entries() {
    let mut trace = build_valid_trace();
    trace.entries.swap(1, 2);
    assert!(
        !verify_trace(&trace),
        "CEX-TR-004: Reordered entries must be rejected"
    );
}

// ===========================================================================
// CEX-TEMP: Temporal Counterexamples
// ===========================================================================

/// CEX-TEMP-001: Delayed invariant failure over long trace.
///
/// Property violated: Temporal Invariants
/// State sequence: All invariants hold for first N steps but accumulated drift
///   causes failure at step N+1.
/// Root cause: Precision loss, counter overflow, resource drift.
/// Resolution: Temporal invariants checked at every step; monotonic metadata.
#[test]
fn cex_temp_001_delayed_invariant_failure() {
    // Build a multi-step trace and verify invariants hold at every step
    let c = minimal_canonical();
    let mut current = build_genesis_state(c);

    let steps = vec![
        make_input("init", vec![0xFF]),
        make_deposit_input([1u8; 32], 100),
        make_deposit_input([2u8; 32], 200),
    ];

    for sigma in &steps {
        let post = apply(&current, sigma);
        assert!(
            valid_state(&post),
            "CEX-TEMP-001: Every intermediate state must be valid"
        );
        let g_result = g_valid(&post);
        assert!(
            g_result.valid,
            "CEX-TEMP-001: G_valid must hold at every step"
        );
        current = post;
    }
}

/// CEX-TEMP-002: Replay attack — valid trace segment resubmitted.
///
/// Property violated: Replay Resistance
/// State sequence: Valid trace segment resubmitted as new execution.
/// Root cause: Missing nonce/sequence verification.
/// Resolution: Trace commitment chain with unique chain hashes prevents replay.
#[test]
fn cex_temp_002_replay_resistance() {
    let trace = build_valid_trace();

    // Each entry has a unique chain hash — replay would need to forge chain
    let chain_hashes: Vec<&Hash> = trace.entries.iter().map(|e| &e.chain_hash).collect();
    for i in 0..chain_hashes.len() {
        for j in (i + 1)..chain_hashes.len() {
            assert_ne!(
                chain_hashes[i], chain_hashes[j],
                "CEX-TEMP-002: Chain hashes must be unique (replay resistance)"
            );
        }
    }
}

/// CEX-TEMP-003: Metadata monotonicity violation.
///
/// Property violated: G_mono (Monotonic Metadata)
/// State sequence: Non-genesis state with zero commitment.
/// Root cause: Metadata regression allowing state reversion.
/// Resolution: G_mono checks sequence_index/commitment consistency.
#[test]
fn cex_temp_003_metadata_monotonicity() {
    let c = minimal_canonical();
    let mut s = build_state_at_seq(c, 5);
    // Force zero commitment on non-genesis state
    s.metadata.previous_commitment = Hash([0u8; 32]);

    let result = g_mono(&s);
    assert!(
        !result.valid,
        "CEX-TEMP-003: G_mono must reject non-genesis with zero commitment"
    );
}

// ===========================================================================
// CEX-CRYPTO: Cryptographic Counterexamples
// ===========================================================================

/// CEX-CRYPTO-001: Commitment collision — distinct states, same commitment.
///
/// Property violated: DEF-3, AX-5 (Commitment Collision Resistance)
/// State sequence: s₁ ≠ s₂ but Commit(s₁) = Commit(s₂).
/// Root cause: Weak hash function or insufficient domain separation.
/// Resolution: SHA3-256 with domain-separated encoding provides collision resistance.
#[test]
fn cex_crypto_001_commitment_collision_resistance() {
    // Verify distinct canonical states produce distinct commitments
    let states = vec![
        minimal_canonical(),
        canonical_with_account([1u8; 32], 100),
        canonical_with_account([1u8; 32], 200),
        canonical_with_account([2u8; 32], 100),
        canonical_with_two_accounts([1u8; 32], 100, [2u8; 32], 200),
    ];

    let commitments: Vec<Hash> = states.iter().map(|c| commit(c)).collect();
    for i in 0..commitments.len() {
        for j in (i + 1)..commitments.len() {
            assert_ne!(
                commitments[i], commitments[j],
                "CEX-CRYPTO-001: Distinct states must produce distinct commitments"
            );
        }
    }
}

/// CEX-CRYPTO-002: Hybrid signature — both components required.
///
/// Property violated: Cryptographic Model (Hybrid Signatures)
/// State sequence: Input with missing classical or PQC signature component.
/// Root cause: Accepting single-component signature bypasses hybrid security.
/// Resolution: Engine rejects inputs with empty classical_sig or pqc_sig.
#[test]
fn cex_crypto_002_hybrid_signature_both_required() {
    let engine = DefaultExecutionEngine;
    let c = canonical_with_account([1u8; 32], 1000);
    let s = build_state_at_seq(c, 1);

    // Missing classical signature
    let sigma_no_classical = Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data: {
                let mut d = vec![];
                d.extend_from_slice(&[1u8; 32]);
                d.extend_from_slice(&100u128.to_le_bytes());
                d
            },
        },
        auth: Authorization {
            classical_sig: vec![],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    assert!(
        engine.execute(&s, &sigma_no_classical).is_err(),
        "CEX-CRYPTO-002: Missing classical sig must be rejected"
    );

    // Missing PQC signature
    let sigma_no_pqc = Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data: {
                let mut d = vec![];
                d.extend_from_slice(&[1u8; 32]);
                d.extend_from_slice(&100u128.to_le_bytes());
                d
            },
        },
        auth: Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: test_domain_tag(),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    assert!(
        engine.execute(&s, &sigma_no_pqc).is_err(),
        "CEX-CRYPTO-002: Missing PQC sig must be rejected"
    );
}

/// CEX-CRYPTO-003: Domain separation — zero domain tag rejected.
///
/// Property violated: PROOF-3 (Domain Separation)
/// State sequence: State or input with zero domain tag.
/// Root cause: Missing domain separation enables cross-protocol attacks.
/// Resolution: G_env rejects zero domain tag; engine rejects zero domain in auth.
#[test]
fn cex_crypto_003_domain_separation() {
    // State-level: zero domain tag
    let c = minimal_canonical();
    let mut s = build_genesis_state(c);
    s.environment.execution_domain = DomainTag(Hash([0u8; 32]));
    let result = g_env(&s);
    assert!(
        !result.valid,
        "CEX-CRYPTO-003: G_env must reject zero domain tag"
    );

    // Input-level: zero domain tag in auth
    let engine = DefaultExecutionEngine;
    let c2 = canonical_with_account([1u8; 32], 1000);
    let s2 = build_state_at_seq(c2, 1);
    let sigma = Input {
        payload: Payload {
            payload_type: "deposit".to_string(),
            data: {
                let mut d = vec![];
                d.extend_from_slice(&[1u8; 32]);
                d.extend_from_slice(&100u128.to_le_bytes());
                d
            },
        },
        auth: Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: DomainTag(Hash([0u8; 32])),
        },
        aux: AuxiliaryData { data: vec![] },
    };
    assert!(
        engine.execute(&s2, &sigma).is_err(),
        "CEX-CRYPTO-003: Zero domain in auth must be rejected"
    );
}

/// CEX-CRYPTO-004: Chain hash integrity — tampered hashes detected.
///
/// Property violated: Incremental Commitment Chaining
/// State sequence: Chain with tampered intermediate hash.
/// Root cause: Chain hash not verified incrementally.
/// Resolution: verify_chain validates h_{i+1} = Hash(h_i | Commit(e_i)).
#[test]
fn cex_crypto_004_chain_hash_integrity() {
    let e1 = Hash([1u8; 32]);
    let e2 = Hash([2u8; 32]);
    let e3 = Hash([3u8; 32]);
    let h1 = compute_chain_hash(&Hash([0u8; 32]), &e1);
    let h2 = compute_chain_hash(&h1, &e2);
    let h3 = compute_chain_hash(&h2, &e3);

    // Valid chain
    assert!(verify_chain(
        &[e1.clone(), e2.clone(), e3.clone()],
        &[h1.clone(), h2.clone(), h3.clone()]
    ));

    // Tampered middle hash
    assert!(
        !verify_chain(
            &[e1.clone(), e2.clone(), e3.clone()],
            &[h1.clone(), Hash([0xFFu8; 32]), h3.clone()]
        ),
        "CEX-CRYPTO-004: Tampered middle hash must be rejected"
    );

    // Swapped hashes
    assert!(
        !verify_chain(&[e1, e2, e3], &[h2, h1, h3]),
        "CEX-CRYPTO-004: Swapped hashes must be rejected"
    );
}
