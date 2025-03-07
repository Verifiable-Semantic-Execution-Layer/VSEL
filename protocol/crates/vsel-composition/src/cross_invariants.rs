//! Cross-system invariants for compositional verification.
//!
//! Derived from: COMPOSITION_MODEL.md, ECONOMIC_INVARIANTS.md,
//! Requirements 11.3, 11.9.
//!
//! Cross-system invariants (CI-1 through CI-5) ensure correctness
//! survives interaction between independently correct systems:
//!
//!   CI-1: Resource conservation — Total_A + Total_B = constant
//!   CI-2: Shared state consistency — shared keys have identical values
//!   CI-3: Authorization transitivity — both systems independently verify
//!   CI-4: Causal consistency — timestamps are consistent across systems
//!   CI-5: Version compatibility — major protocol versions match
//!
//! Economic composition invariants:
//!   CE_arbitrage: No cross-system arbitrage (price oracle consistency)
//!   CE_contagion: Economic failure contagion is bounded

use vsel_core::state::State;
use vsel_core::types::StorageKey;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of cross-invariant checks.
#[derive(Clone, Debug)]
pub struct CrossInvariantResult {
    /// Whether all checked invariants hold.
    pub valid: bool,
    /// List of violations found (empty if valid).
    pub violations: Vec<CrossInvariantViolation>,
}

impl CrossInvariantResult {
    /// Create a passing result with no violations.
    pub fn ok() -> Self {
        Self {
            valid: true,
            violations: Vec::new(),
        }
    }

    /// Create a failing result with a single violation.
    pub fn violation(invariant_id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            valid: false,
            violations: vec![CrossInvariantViolation {
                invariant_id: invariant_id.into(),
                description: description.into(),
            }],
        }
    }

    /// Merge another result into this one, accumulating violations.
    fn merge(&mut self, other: CrossInvariantResult) {
        if !other.valid {
            self.valid = false;
        }
        self.violations.extend(other.violations);
    }
}

/// A specific cross-invariant violation.
#[derive(Clone, Debug)]
pub struct CrossInvariantViolation {
    /// Identifier of the violated invariant (e.g. "CI-1", "CE_arbitrage").
    pub invariant_id: String,
    /// Human-readable description of the violation.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for cross-invariant checks.
#[derive(Clone, Debug)]
pub struct CrossInvariantConfig {
    /// Expected total supply across both systems (CI-1).
    pub expected_total: u128,
    /// Storage keys that must be consistent across systems (CI-2).
    pub shared_keys: Vec<StorageKey>,
    /// Maximum allowed timestamp drift between systems in time units (CI-4).
    pub max_timestamp_drift: u64,
    /// Maximum exposure ratio for contagion check (CE_contagion).
    /// Expressed as a fraction of total supply (e.g. 5000 = 50% in basis points).
    pub max_exposure_ratio: u128,
}

// ---------------------------------------------------------------------------
// CI-1: Resource conservation — Total_A + Total_B = constant
// ---------------------------------------------------------------------------

/// Check CI-1: resource conservation across two systems.
///
/// Verifies that `total_supply_a + total_supply_b == expected_total`.
/// This ensures no resources are created or destroyed during cross-system
/// interaction.
pub fn check_ci1_resource_conservation(
    state_a: &State,
    state_b: &State,
    expected_total: u128,
) -> CrossInvariantResult {
    let total_a = state_a.canonical.system_data.total_supply;
    let total_b = state_b.canonical.system_data.total_supply;

    match total_a.checked_add(total_b) {
        Some(actual_total) if actual_total == expected_total => CrossInvariantResult::ok(),
        Some(actual_total) => CrossInvariantResult::violation(
            "CI-1",
            format!(
                "Resource conservation violated: Total_A ({}) + Total_B ({}) = {} != expected {}",
                total_a, total_b, actual_total, expected_total
            ),
        ),
        None => CrossInvariantResult::violation(
            "CI-1",
            format!(
                "Resource conservation violated: Total_A ({}) + Total_B ({}) overflows u128",
                total_a, total_b
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// CI-2: Shared state consistency
// ---------------------------------------------------------------------------

/// Check CI-2: shared state consistency across two systems.
///
/// Verifies that all shared storage keys have identical values in both states.
pub fn check_ci2_shared_state_consistency(
    state_a: &State,
    state_b: &State,
    shared_keys: &[StorageKey],
) -> CrossInvariantResult {
    let mut result = CrossInvariantResult::ok();

    for key in shared_keys {
        let val_a = state_a.canonical.storage.get(key);
        let val_b = state_b.canonical.storage.get(key);

        if val_a != val_b {
            result.valid = false;
            result.violations.push(CrossInvariantViolation {
                invariant_id: "CI-2".to_string(),
                description: format!(
                    "Shared state inconsistency for key {:?}: system A has {:?}, system B has {:?}",
                    key, val_a, val_b
                ),
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// CI-3: Authorization transitivity
// ---------------------------------------------------------------------------

/// Check CI-3: authorization transitivity across two systems.
///
/// Both systems must independently verify authorization. If either system
/// rejects authorization, the cross-system operation is invalid.
pub fn check_ci3_authorization_transitivity(
    auth_a_valid: bool,
    auth_b_valid: bool,
) -> CrossInvariantResult {
    if auth_a_valid && auth_b_valid {
        CrossInvariantResult::ok()
    } else {
        let mut violations = Vec::new();
        if !auth_a_valid {
            violations.push(CrossInvariantViolation {
                invariant_id: "CI-3".to_string(),
                description: "Authorization not verified by system A".to_string(),
            });
        }
        if !auth_b_valid {
            violations.push(CrossInvariantViolation {
                invariant_id: "CI-3".to_string(),
                description: "Authorization not verified by system B".to_string(),
            });
        }
        CrossInvariantResult {
            valid: false,
            violations,
        }
    }
}

// ---------------------------------------------------------------------------
// CI-4: Causal consistency
// ---------------------------------------------------------------------------

/// Check CI-4: causal consistency across two systems.
///
/// Verifies that timestamps are consistent — neither system is ahead of the
/// other by more than `max_timestamp_drift`. This prevents temporal
/// inconsistencies in cross-system interactions.
///
/// Uses a default threshold of 300 time units if not specified via config.
pub fn check_ci4_causal_consistency(
    state_a: &State,
    state_b: &State,
) -> CrossInvariantResult {
    check_ci4_causal_consistency_with_threshold(state_a, state_b, 300)
}

/// Check CI-4 with a custom timestamp drift threshold.
pub fn check_ci4_causal_consistency_with_threshold(
    state_a: &State,
    state_b: &State,
    max_timestamp_drift: u64,
) -> CrossInvariantResult {
    let ts_a = state_a.environment.timestamp;
    let ts_b = state_b.environment.timestamp;

    let drift = if ts_a >= ts_b {
        ts_a - ts_b
    } else {
        ts_b - ts_a
    };

    if drift <= max_timestamp_drift {
        CrossInvariantResult::ok()
    } else {
        CrossInvariantResult::violation(
            "CI-4",
            format!(
                "Causal consistency violated: timestamp drift {} exceeds max {} \
                 (system A: {}, system B: {})",
                drift, max_timestamp_drift, ts_a, ts_b
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// CI-5: Version compatibility
// ---------------------------------------------------------------------------

/// Check CI-5: version compatibility across two systems.
///
/// Verifies that the major protocol versions match. Systems with different
/// major versions are incompatible and must not compose.
pub fn check_ci5_version_compatibility(
    state_a: &State,
    state_b: &State,
) -> CrossInvariantResult {
    let ver_a = &state_a.canonical.system_data.protocol_version;
    let ver_b = &state_b.canonical.system_data.protocol_version;

    if ver_a.major == ver_b.major {
        CrossInvariantResult::ok()
    } else {
        CrossInvariantResult::violation(
            "CI-5",
            format!(
                "Version incompatibility: system A major version {} != system B major version {}",
                ver_a.major, ver_b.major
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// CE_arbitrage: No cross-system arbitrage
// ---------------------------------------------------------------------------

/// Check CE_arbitrage: no cross-system arbitrage opportunity.
///
/// Verifies price oracle consistency between two systems. If both systems
/// have price data for the same asset pair, the prices must not diverge
/// beyond a reasonable threshold (10% = 1000 basis points).
pub fn check_ce_arbitrage(
    state_a: &State,
    state_b: &State,
) -> CrossInvariantResult {
    let oracle_a = &state_a.economic.price_oracle;
    let oracle_b = &state_b.economic.price_oracle;

    let mut result = CrossInvariantResult::ok();

    // Maximum allowed price divergence: 10% (1000 basis points out of 10000)
    const MAX_DIVERGENCE_BPS: u128 = 1000;

    for (pair, price_a) in oracle_a {
        if let Some(price_b) = oracle_b.get(pair) {
            let pa = price_a.0;
            let pb = price_b.0;

            if pa == 0 && pb == 0 {
                continue;
            }

            let max_price = pa.max(pb);
            let min_price = pa.min(pb);
            let diff = max_price - min_price;

            // Check if divergence exceeds threshold: diff / max_price > MAX_DIVERGENCE_BPS / 10000
            // Rearranged to avoid floating point: diff * 10000 > max_price * MAX_DIVERGENCE_BPS
            if diff.checked_mul(10_000).map_or(true, |scaled_diff| {
                max_price
                    .checked_mul(MAX_DIVERGENCE_BPS)
                    .map_or(true, |threshold| scaled_diff > threshold)
            }) {
                result.valid = false;
                result.violations.push(CrossInvariantViolation {
                    invariant_id: "CE_arbitrage".to_string(),
                    description: format!(
                        "Cross-system arbitrage opportunity for {:?}/{:?}: \
                         system A price {}, system B price {}",
                        pair.base, pair.quote, pa, pb
                    ),
                });
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// CE_contagion: Economic failure contagion is bounded
// ---------------------------------------------------------------------------

/// Check CE_contagion: economic failure contagion is bounded.
///
/// Verifies that neither system's total supply exceeds `max_exposure_ratio`
/// (in basis points, where 10000 = 100%) of the combined total supply.
/// This bounds the impact of economic failure in one system on the other.
pub fn check_ce_contagion(
    state_a: &State,
    state_b: &State,
    max_exposure_ratio: u128,
) -> CrossInvariantResult {
    let total_a = state_a.canonical.system_data.total_supply;
    let total_b = state_b.canonical.system_data.total_supply;

    let combined = match total_a.checked_add(total_b) {
        Some(c) => c,
        None => {
            return CrossInvariantResult::violation(
                "CE_contagion",
                "Combined total supply overflows u128".to_string(),
            );
        }
    };

    if combined == 0 {
        return CrossInvariantResult::ok();
    }

    let mut result = CrossInvariantResult::ok();

    // Check system A exposure: total_a / combined <= max_exposure_ratio / 10000
    // Rearranged: total_a * 10000 <= combined * max_exposure_ratio
    let check_exposure = |total: u128, label: &str| -> Option<CrossInvariantViolation> {
        let scaled_total = total.checked_mul(10_000)?;
        let threshold = combined.checked_mul(max_exposure_ratio)?;
        if scaled_total > threshold {
            Some(CrossInvariantViolation {
                invariant_id: "CE_contagion".to_string(),
                description: format!(
                    "Economic contagion risk: {} total supply {} exceeds {}bps of combined {}",
                    label, total, max_exposure_ratio, combined
                ),
            })
        } else {
            None
        }
    };

    if let Some(v) = check_exposure(total_a, "system A") {
        result.valid = false;
        result.violations.push(v);
    }
    if let Some(v) = check_exposure(total_b, "system B") {
        result.valid = false;
        result.violations.push(v);
    }

    result
}

// ---------------------------------------------------------------------------
// check_all_cross_invariants — runs all checks
// ---------------------------------------------------------------------------

/// Run all cross-system invariant checks.
///
/// Combines CI-1 through CI-5 and CE_arbitrage, CE_contagion using the
/// provided configuration.
pub fn check_all_cross_invariants(
    state_a: &State,
    state_b: &State,
    config: &CrossInvariantConfig,
) -> CrossInvariantResult {
    let mut result = CrossInvariantResult::ok();

    result.merge(check_ci1_resource_conservation(
        state_a,
        state_b,
        config.expected_total,
    ));
    result.merge(check_ci2_shared_state_consistency(
        state_a,
        state_b,
        &config.shared_keys,
    ));
    // CI-3 requires external authorization results; skip in aggregate check
    // since the caller must provide auth_a_valid / auth_b_valid separately.
    result.merge(check_ci4_causal_consistency_with_threshold(
        state_a,
        state_b,
        config.max_timestamp_drift,
    ));
    result.merge(check_ci5_version_compatibility(state_a, state_b));
    result.merge(check_ce_arbitrage(state_a, state_b));
    result.merge(check_ce_contagion(
        state_a,
        state_b,
        config.max_exposure_ratio,
    ));

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::state::*;
    use vsel_core::types::*;

    // -- Helpers --

    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 1;
        DomainTag(Hash(h))
    }

    fn minimal_canonical(total_supply: u128) -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                total_supply,
                parameters: BTreeMap::new(),
            },
        }
    }

    fn build_state(total_supply: u128, timestamp: u64) -> State {
        let c = minimal_canonical(total_supply);
        let d = derive(&c);
        let env = Environment {
            timestamp,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let meta = TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp,
        };
        State {
            canonical: c,
            derived: d,
            environment: env,
            economic: econ,
            metadata: meta,
        }
    }

    fn build_state_with_version(total_supply: u128, timestamp: u64, major: u32) -> State {
        let mut s = build_state(total_supply, timestamp);
        s.canonical.system_data.protocol_version.major = major;
        s.derived = derive(&s.canonical);
        s
    }

    // -- CI-1: Resource conservation --

    #[test]
    fn test_ci1_conservation_holds() {
        let a = build_state(600, 1000);
        let b = build_state(400, 1000);
        let result = check_ci1_resource_conservation(&a, &b, 1000);
        assert!(result.valid);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_ci1_conservation_violated() {
        let a = build_state(600, 1000);
        let b = build_state(500, 1000);
        let result = check_ci1_resource_conservation(&a, &b, 1000);
        assert!(!result.valid);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].invariant_id, "CI-1");
    }

    #[test]
    fn test_ci1_conservation_zero() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1000);
        let result = check_ci1_resource_conservation(&a, &b, 0);
        assert!(result.valid);
    }

    // -- CI-2: Shared state consistency --

    #[test]
    fn test_ci2_consistency_holds() {
        let key = StorageKey(vec![1, 2, 3]);
        let val = StorageValue(vec![10, 20]);

        let mut a = build_state(0, 1000);
        a.canonical.storage.insert(key.clone(), val.clone());

        let mut b = build_state(0, 1000);
        b.canonical.storage.insert(key.clone(), val);

        let result = check_ci2_shared_state_consistency(&a, &b, &[key]);
        assert!(result.valid);
    }

    #[test]
    fn test_ci2_consistency_violated() {
        let key = StorageKey(vec![1, 2, 3]);

        let mut a = build_state(0, 1000);
        a.canonical.storage.insert(key.clone(), StorageValue(vec![10]));

        let mut b = build_state(0, 1000);
        b.canonical.storage.insert(key.clone(), StorageValue(vec![20]));

        let result = check_ci2_shared_state_consistency(&a, &b, &[key]);
        assert!(!result.valid);
        assert_eq!(result.violations[0].invariant_id, "CI-2");
    }

    #[test]
    fn test_ci2_missing_key_in_one_system() {
        let key = StorageKey(vec![1, 2, 3]);

        let mut a = build_state(0, 1000);
        a.canonical.storage.insert(key.clone(), StorageValue(vec![10]));

        let b = build_state(0, 1000);
        // b does not have the key

        let result = check_ci2_shared_state_consistency(&a, &b, &[key]);
        assert!(!result.valid);
        assert_eq!(result.violations[0].invariant_id, "CI-2");
    }

    #[test]
    fn test_ci2_empty_shared_keys() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1000);
        let result = check_ci2_shared_state_consistency(&a, &b, &[]);
        assert!(result.valid);
    }

    // -- CI-3: Authorization transitivity --

    #[test]
    fn test_ci3_both_valid() {
        let result = check_ci3_authorization_transitivity(true, true);
        assert!(result.valid);
    }

    #[test]
    fn test_ci3_a_invalid() {
        let result = check_ci3_authorization_transitivity(false, true);
        assert!(!result.valid);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].invariant_id, "CI-3");
        assert!(result.violations[0].description.contains("system A"));
    }

    #[test]
    fn test_ci3_b_invalid() {
        let result = check_ci3_authorization_transitivity(true, false);
        assert!(!result.valid);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].description.contains("system B"));
    }

    #[test]
    fn test_ci3_both_invalid() {
        let result = check_ci3_authorization_transitivity(false, false);
        assert!(!result.valid);
        assert_eq!(result.violations.len(), 2);
    }

    // -- CI-4: Causal consistency --

    #[test]
    fn test_ci4_timestamps_consistent() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1100);
        let result = check_ci4_causal_consistency_with_threshold(&a, &b, 300);
        assert!(result.valid);
    }

    #[test]
    fn test_ci4_timestamps_at_threshold() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1300);
        let result = check_ci4_causal_consistency_with_threshold(&a, &b, 300);
        assert!(result.valid);
    }

    #[test]
    fn test_ci4_timestamps_exceed_threshold() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1500);
        let result = check_ci4_causal_consistency_with_threshold(&a, &b, 300);
        assert!(!result.valid);
        assert_eq!(result.violations[0].invariant_id, "CI-4");
    }

    #[test]
    fn test_ci4_reverse_direction() {
        let a = build_state(0, 2000);
        let b = build_state(0, 1000);
        let result = check_ci4_causal_consistency_with_threshold(&a, &b, 300);
        assert!(!result.valid);
    }

    #[test]
    fn test_ci4_default_threshold() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1200);
        let result = check_ci4_causal_consistency(&a, &b);
        assert!(result.valid);
    }

    // -- CI-5: Version compatibility --

    #[test]
    fn test_ci5_same_major_version() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1000);
        let result = check_ci5_version_compatibility(&a, &b);
        assert!(result.valid);
    }

    #[test]
    fn test_ci5_different_major_version() {
        let a = build_state_with_version(0, 1000, 1);
        let b = build_state_with_version(0, 1000, 2);
        let result = check_ci5_version_compatibility(&a, &b);
        assert!(!result.valid);
        assert_eq!(result.violations[0].invariant_id, "CI-5");
    }

    #[test]
    fn test_ci5_different_minor_ok() {
        let mut a = build_state(0, 1000);
        a.canonical.system_data.protocol_version.minor = 1;
        let mut b = build_state(0, 1000);
        b.canonical.system_data.protocol_version.minor = 5;
        let result = check_ci5_version_compatibility(&a, &b);
        assert!(result.valid);
    }

    // -- CE_arbitrage --

    #[test]
    fn test_ce_arbitrage_no_oracles() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1000);
        let result = check_ce_arbitrage(&a, &b);
        assert!(result.valid);
    }

    #[test]
    fn test_ce_arbitrage_consistent_prices() {
        let pair = AssetPair {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
        };

        let mut a = build_state(0, 1000);
        a.economic.price_oracle.insert(pair.clone(), Price(2000));

        let mut b = build_state(0, 1000);
        b.economic.price_oracle.insert(pair, Price(2050));

        let result = check_ce_arbitrage(&a, &b);
        assert!(result.valid);
    }

    #[test]
    fn test_ce_arbitrage_divergent_prices() {
        let pair = AssetPair {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
        };

        let mut a = build_state(0, 1000);
        a.economic.price_oracle.insert(pair.clone(), Price(1000));

        let mut b = build_state(0, 1000);
        b.economic.price_oracle.insert(pair, Price(2000));

        let result = check_ce_arbitrage(&a, &b);
        assert!(!result.valid);
        assert_eq!(result.violations[0].invariant_id, "CE_arbitrage");
    }

    #[test]
    fn test_ce_arbitrage_both_zero_prices() {
        let pair = AssetPair {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
        };

        let mut a = build_state(0, 1000);
        a.economic.price_oracle.insert(pair.clone(), Price(0));

        let mut b = build_state(0, 1000);
        b.economic.price_oracle.insert(pair, Price(0));

        let result = check_ce_arbitrage(&a, &b);
        assert!(result.valid);
    }

    // -- CE_contagion --

    #[test]
    fn test_ce_contagion_balanced() {
        let a = build_state(500, 1000);
        let b = build_state(500, 1000);
        // 50% each, max 6000 bps (60%) — should pass
        let result = check_ce_contagion(&a, &b, 6000);
        assert!(result.valid);
    }

    #[test]
    fn test_ce_contagion_exceeded() {
        let a = build_state(900, 1000);
        let b = build_state(100, 1000);
        // A is 90% of combined, max 5000 bps (50%) — should fail for A
        let result = check_ce_contagion(&a, &b, 5000);
        assert!(!result.valid);
        assert!(result.violations.iter().any(|v| v.invariant_id == "CE_contagion"));
    }

    #[test]
    fn test_ce_contagion_zero_combined() {
        let a = build_state(0, 1000);
        let b = build_state(0, 1000);
        let result = check_ce_contagion(&a, &b, 5000);
        assert!(result.valid);
    }

    // -- check_all_cross_invariants --

    #[test]
    fn test_all_invariants_pass() {
        let a = build_state(500, 1000);
        let b = build_state(500, 1000);
        let config = CrossInvariantConfig {
            expected_total: 1000,
            shared_keys: vec![],
            max_timestamp_drift: 300,
            max_exposure_ratio: 6000,
        };
        let result = check_all_cross_invariants(&a, &b, &config);
        assert!(result.valid);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_all_invariants_multiple_failures() {
        let a = build_state_with_version(900, 1000, 1);
        let b = build_state_with_version(200, 2000, 2);
        let config = CrossInvariantConfig {
            expected_total: 1000,
            shared_keys: vec![],
            max_timestamp_drift: 300,
            max_exposure_ratio: 5000,
        };
        let result = check_all_cross_invariants(&a, &b, &config);
        assert!(!result.valid);
        // Should have violations for CI-1 (900+200=1100 != 1000),
        // CI-4 (drift 1000 > 300), CI-5 (major 1 != 2),
        // and CE_contagion (900/1100 > 50%)
        assert!(result.violations.len() >= 3);

        let ids: Vec<&str> = result.violations.iter().map(|v| v.invariant_id.as_str()).collect();
        assert!(ids.contains(&"CI-1"));
        assert!(ids.contains(&"CI-4"));
        assert!(ids.contains(&"CI-5"));
    }
}
