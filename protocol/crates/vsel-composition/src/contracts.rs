//! Assume-guarantee contracts for compositional verification.
//!
//! Derived from: ASSUME_GUARANTEE_MODEL.md, COMPOSITION_MODEL.md,
//! Requirements 11.1, 11.2, 11.7.
//!
//! Each subsystem defines a contract:
//!   Contract(M) = {Assumes, Guarantees, Exports, Effects, Forbids, Temporal}
//!
//! Composition rule (Requirement 11.2):
//!   COMPOSE(M_A, M_B) is valid ⟺
//!     G(M_A) ⊇ A(M_B) ∧ G(M_B) ⊇ A(M_A)
//!     ∧ Eff(M_A) ∩ F(M_B) = ∅ ∧ Eff(M_B) ∩ F(M_A) = ∅
//!     ∧ temporal obligations jointly satisfiable
//!
//! Backward-compatible upgrades (Requirement 11.7):
//!   A(M^v2) ⊆ A(M^v1)  — new version assumes less
//!   G(M^v2) ⊇ G(M^v1)  — new version guarantees more

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Contract property — a named property with ID and description
// ---------------------------------------------------------------------------

/// A named property used in contract specifications.
///
/// Properties are identified by a unique string ID and carry a human-readable
/// description. The `id` field is used for set operations (subset, intersection,
/// disjointness) when verifying composition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContractProperty {
    /// Unique identifier for this property (e.g. "valid_state", "resource_conservation").
    pub id: String,
    /// Human-readable description of what this property means.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Temporal obligation — temporal constraints on subsystem behavior
// ---------------------------------------------------------------------------

/// A temporal obligation constraining subsystem behavior over time.
///
/// Temporal obligations express liveness and safety properties that must
/// hold across sequences of transitions, not just individual states.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TemporalObligation {
    /// Unique identifier for this obligation.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// IDs of properties this obligation depends on.
    pub depends_on: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// SubsystemContract — the full assume-guarantee contract
// ---------------------------------------------------------------------------

/// Assume-guarantee contract for a subsystem.
///
/// Contract(M) = {Assumes, Guarantees, Exports, Effects, Forbids, Temporal}
///
/// - `assumes`: properties this subsystem requires from its environment
/// - `guarantees`: properties this subsystem provides to its environment
/// - `exports`: observable interfaces exposed by this subsystem
/// - `effects`: state mutations this subsystem may perform
/// - `forbids`: interactions this subsystem prohibits
/// - `temporal`: temporal obligations on subsystem behavior
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemContract {
    /// Properties this subsystem assumes about its environment.
    pub assumes: BTreeSet<String>,
    /// Properties this subsystem guarantees to its environment.
    pub guarantees: BTreeSet<String>,
    /// Observable interfaces exported by this subsystem.
    pub exports: BTreeSet<String>,
    /// State effects (mutations) this subsystem may perform.
    pub effects: BTreeSet<String>,
    /// Interactions this subsystem forbids.
    pub forbids: BTreeSet<String>,
    /// Temporal obligations on this subsystem's behavior.
    pub temporal: Vec<TemporalObligation>,
}

// ---------------------------------------------------------------------------
// SystemDefinition — defines a subsystem for contract generation
// ---------------------------------------------------------------------------

/// Definition of a subsystem used to generate its contract.
///
/// A `SystemDefinition` captures the declared properties, effects, and
/// constraints of a subsystem so that `define_contract` can produce
/// the corresponding `SubsystemContract`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemDefinition {
    /// Human-readable name of the subsystem.
    pub name: String,
    /// Properties this subsystem assumes from its environment.
    pub assumed_properties: Vec<ContractProperty>,
    /// Properties this subsystem guarantees.
    pub guaranteed_properties: Vec<ContractProperty>,
    /// Observable interfaces this subsystem exports.
    pub exported_interfaces: Vec<String>,
    /// State effects this subsystem may perform.
    pub state_effects: Vec<String>,
    /// Interactions this subsystem forbids.
    pub forbidden_interactions: Vec<String>,
    /// Temporal obligations.
    pub temporal_obligations: Vec<TemporalObligation>,
}

// ---------------------------------------------------------------------------
// CompositionResult — result of composition verification
// ---------------------------------------------------------------------------

/// Result of verifying composition of two subsystem contracts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompositionResult {
    /// Composition is valid — all conditions satisfied.
    Valid,
    /// Composition is invalid — one or more violations found.
    Invalid {
        violations: Vec<CompositionViolation>,
    },
}

/// A specific violation found during composition verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionViolation {
    /// Category of the violation.
    pub kind: ViolationKind,
    /// Human-readable description of the violation.
    pub description: String,
    /// The specific property IDs involved in the violation.
    pub properties: Vec<String>,
}

/// Categories of composition violations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// G(M_A) does not cover A(M_B) — guarantees of A don't satisfy assumptions of B.
    GuaranteesDoNotCoverAssumptions,
    /// Eff(M_A) ∩ F(M_B) ≠ ∅ — effects of A conflict with forbids of B.
    EffectsConflictWithForbids,
    /// Temporal obligations are not jointly satisfiable.
    TemporalConflict,
}

// ---------------------------------------------------------------------------
// CompatibilityResult — result of backward compatibility check
// ---------------------------------------------------------------------------

/// Result of checking backward compatibility between contract versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityResult {
    /// The upgrade is backward-compatible.
    Compatible,
    /// The upgrade is not backward-compatible.
    Incompatible {
        violations: Vec<CompatibilityViolation>,
    },
}

/// A specific backward-compatibility violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibilityViolation {
    /// Category of the violation.
    pub kind: CompatibilityViolationKind,
    /// Human-readable description.
    pub description: String,
    /// The specific property IDs involved.
    pub properties: Vec<String>,
}

/// Categories of backward-compatibility violations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibilityViolationKind {
    /// A(M^v2) ⊄ A(M^v1) — new version assumes more than old version.
    AssumptionsExpanded,
    /// G(M^v2) ⊅ G(M^v1) — new version guarantees less than old version.
    GuaranteesReduced,
    /// F(M^v2) ⊄ F(M^v1) — new version forbids more than old version.
    ForbidsExpanded,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during contract operations.
#[derive(Debug, Error)]
pub enum ContractError {
    /// The system definition is invalid (e.g. empty name).
    #[error("invalid system definition: {0}")]
    InvalidDefinition(String),
}

// ---------------------------------------------------------------------------
// define_contract — generate a SubsystemContract from a SystemDefinition
// ---------------------------------------------------------------------------

/// Generate a `SubsystemContract` from a `SystemDefinition`.
///
/// Extracts the property IDs from the definition's assumed and guaranteed
/// properties and assembles the full contract structure.
pub fn define_contract(system: &SystemDefinition) -> SubsystemContract {
    let assumes: BTreeSet<String> = system
        .assumed_properties
        .iter()
        .map(|p| p.id.clone())
        .collect();

    let guarantees: BTreeSet<String> = system
        .guaranteed_properties
        .iter()
        .map(|p| p.id.clone())
        .collect();

    let exports: BTreeSet<String> = system.exported_interfaces.iter().cloned().collect();
    let effects: BTreeSet<String> = system.state_effects.iter().cloned().collect();
    let forbids: BTreeSet<String> = system.forbidden_interactions.iter().cloned().collect();

    SubsystemContract {
        assumes,
        guarantees,
        exports,
        effects,
        forbids,
        temporal: system.temporal_obligations.clone(),
    }
}

// ---------------------------------------------------------------------------
// verify_composition — check composition validity of two contracts
// ---------------------------------------------------------------------------

/// Verify that two subsystem contracts can be composed.
///
/// Enforces the composition rule (Requirement 11.2):
///   G(M_A) ⊇ A(M_B) ∧ G(M_B) ⊇ A(M_A)
///   ∧ Eff(M_A) ∩ F(M_B) = ∅ ∧ Eff(M_B) ∩ F(M_A) = ∅
///   ∧ temporal obligations jointly satisfiable
///
/// Returns `CompositionResult::Valid` if all conditions hold, or
/// `CompositionResult::Invalid` with a list of violations otherwise.
pub fn verify_composition(a: &SubsystemContract, b: &SubsystemContract) -> CompositionResult {
    let mut violations = Vec::new();

    // Check 1: G(M_A) ⊇ A(M_B) — guarantees of A must cover assumptions of B
    let uncovered_b_assumptions: BTreeSet<_> =
        b.assumes.difference(&a.guarantees).cloned().collect();
    if !uncovered_b_assumptions.is_empty() {
        violations.push(CompositionViolation {
            kind: ViolationKind::GuaranteesDoNotCoverAssumptions,
            description: format!(
                "G(M_A) does not cover A(M_B): assumptions of B not guaranteed by A: {:?}",
                uncovered_b_assumptions
            ),
            properties: uncovered_b_assumptions.into_iter().collect(),
        });
    }

    // Check 2: G(M_B) ⊇ A(M_A) — guarantees of B must cover assumptions of A
    let uncovered_a_assumptions: BTreeSet<_> =
        a.assumes.difference(&b.guarantees).cloned().collect();
    if !uncovered_a_assumptions.is_empty() {
        violations.push(CompositionViolation {
            kind: ViolationKind::GuaranteesDoNotCoverAssumptions,
            description: format!(
                "G(M_B) does not cover A(M_A): assumptions of A not guaranteed by B: {:?}",
                uncovered_a_assumptions
            ),
            properties: uncovered_a_assumptions.into_iter().collect(),
        });
    }

    // Check 3: Eff(M_A) ∩ F(M_B) = ∅ — effects of A must not conflict with forbids of B
    let a_effects_conflict: BTreeSet<_> = a.effects.intersection(&b.forbids).cloned().collect();
    if !a_effects_conflict.is_empty() {
        violations.push(CompositionViolation {
            kind: ViolationKind::EffectsConflictWithForbids,
            description: format!(
                "Eff(M_A) ∩ F(M_B) ≠ ∅: effects of A conflict with forbids of B: {:?}",
                a_effects_conflict
            ),
            properties: a_effects_conflict.into_iter().collect(),
        });
    }

    // Check 4: Eff(M_B) ∩ F(M_A) = ∅ — effects of B must not conflict with forbids of A
    let b_effects_conflict: BTreeSet<_> = b.effects.intersection(&a.forbids).cloned().collect();
    if !b_effects_conflict.is_empty() {
        violations.push(CompositionViolation {
            kind: ViolationKind::EffectsConflictWithForbids,
            description: format!(
                "Eff(M_B) ∩ F(M_A) ≠ ∅: effects of B conflict with forbids of A: {:?}",
                b_effects_conflict
            ),
            properties: b_effects_conflict.into_iter().collect(),
        });
    }

    // Check 5: Temporal obligations jointly satisfiable
    // Two temporal obligations conflict if they depend on the same property
    // but one subsystem forbids what the other's temporal obligation requires.
    check_temporal_compatibility(a, b, &mut violations);

    if violations.is_empty() {
        CompositionResult::Valid
    } else {
        CompositionResult::Invalid { violations }
    }
}

/// Check temporal compatibility between two contracts.
///
/// Temporal obligations conflict when an obligation in one contract depends
/// on a property that the other contract forbids.
fn check_temporal_compatibility(
    a: &SubsystemContract,
    b: &SubsystemContract,
    violations: &mut Vec<CompositionViolation>,
) {
    // Check A's temporal obligations against B's forbids
    for obligation in &a.temporal {
        let conflicting: BTreeSet<_> = obligation
            .depends_on
            .intersection(&b.forbids)
            .cloned()
            .collect();
        if !conflicting.is_empty() {
            violations.push(CompositionViolation {
                kind: ViolationKind::TemporalConflict,
                description: format!(
                    "Temporal obligation '{}' of A depends on properties forbidden by B: {:?}",
                    obligation.id, conflicting
                ),
                properties: conflicting.into_iter().collect(),
            });
        }
    }

    // Check B's temporal obligations against A's forbids
    for obligation in &b.temporal {
        let conflicting: BTreeSet<_> = obligation
            .depends_on
            .intersection(&a.forbids)
            .cloned()
            .collect();
        if !conflicting.is_empty() {
            violations.push(CompositionViolation {
                kind: ViolationKind::TemporalConflict,
                description: format!(
                    "Temporal obligation '{}' of B depends on properties forbidden by A: {:?}",
                    obligation.id, conflicting
                ),
                properties: conflicting.into_iter().collect(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// check_backward_compatibility — verify upgrade compatibility
// ---------------------------------------------------------------------------

/// Check backward compatibility between an old and new version of a contract.
///
/// Enforces (Requirement 11.7):
///   A(M^v2) ⊆ A(M^v1)  — new version must not assume more
///   G(M^v2) ⊇ G(M^v1)  — new version must not guarantee less
///   F(M^v2) ⊆ F(M^v1)  — new version must not forbid more
///
/// Returns `CompatibilityResult::Compatible` if all conditions hold, or
/// `CompatibilityResult::Incompatible` with violations otherwise.
pub fn check_backward_compatibility(
    old: &SubsystemContract,
    new: &SubsystemContract,
) -> CompatibilityResult {
    let mut violations = Vec::new();

    // Check 1: A(M^v2) ⊆ A(M^v1) — new version must not assume more
    let new_extra_assumptions: BTreeSet<_> =
        new.assumes.difference(&old.assumes).cloned().collect();
    if !new_extra_assumptions.is_empty() {
        violations.push(CompatibilityViolation {
            kind: CompatibilityViolationKind::AssumptionsExpanded,
            description: format!(
                "A(M^v2) ⊄ A(M^v1): new version introduces additional assumptions: {:?}",
                new_extra_assumptions
            ),
            properties: new_extra_assumptions.into_iter().collect(),
        });
    }

    // Check 2: G(M^v2) ⊇ G(M^v1) — new version must not guarantee less
    let lost_guarantees: BTreeSet<_> = old
        .guarantees
        .difference(&new.guarantees)
        .cloned()
        .collect();
    if !lost_guarantees.is_empty() {
        violations.push(CompatibilityViolation {
            kind: CompatibilityViolationKind::GuaranteesReduced,
            description: format!(
                "G(M^v2) ⊅ G(M^v1): new version drops guarantees: {:?}",
                lost_guarantees
            ),
            properties: lost_guarantees.into_iter().collect(),
        });
    }

    // Check 3: F(M^v2) ⊆ F(M^v1) — new version must not forbid more
    let new_extra_forbids: BTreeSet<_> = new.forbids.difference(&old.forbids).cloned().collect();
    if !new_extra_forbids.is_empty() {
        violations.push(CompatibilityViolation {
            kind: CompatibilityViolationKind::ForbidsExpanded,
            description: format!(
                "F(M^v2) ⊄ F(M^v1): new version introduces additional forbids: {:?}",
                new_extra_forbids
            ),
            properties: new_extra_forbids.into_iter().collect(),
        });
    }

    if violations.is_empty() {
        CompatibilityResult::Compatible
    } else {
        CompatibilityResult::Incompatible { violations }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn prop(id: &str, desc: &str) -> ContractProperty {
        ContractProperty {
            id: id.to_string(),
            description: desc.to_string(),
        }
    }

    fn temporal(id: &str, desc: &str, deps: &[&str]) -> TemporalObligation {
        TemporalObligation {
            id: id.to_string(),
            description: desc.to_string(),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_system(
        name: &str,
        assumes: &[(&str, &str)],
        guarantees: &[(&str, &str)],
        exports: &[&str],
        effects: &[&str],
        forbids: &[&str],
        temporal_obs: Vec<TemporalObligation>,
    ) -> SystemDefinition {
        SystemDefinition {
            name: name.to_string(),
            assumed_properties: assumes.iter().map(|(id, desc)| prop(id, desc)).collect(),
            guaranteed_properties: guarantees.iter().map(|(id, desc)| prop(id, desc)).collect(),
            exported_interfaces: exports.iter().map(|s| s.to_string()).collect(),
            state_effects: effects.iter().map(|s| s.to_string()).collect(),
            forbidden_interactions: forbids.iter().map(|s| s.to_string()).collect(),
            temporal_obligations: temporal_obs,
        }
    }

    // -- define_contract tests --

    #[test]
    fn test_define_contract_from_system_definition() {
        let system = make_system(
            "subsystem_a",
            &[
                ("valid_state", "State is valid"),
                ("resource_conservation", "Resources conserved"),
            ],
            &[
                ("determinism", "Execution is deterministic"),
                ("closure", "State closure"),
            ],
            &["api_v1"],
            &["write_accounts", "write_storage"],
            &["direct_storage_access"],
            vec![temporal(
                "liveness",
                "Eventually progresses",
                &["valid_state"],
            )],
        );

        let contract = define_contract(&system);

        assert_eq!(contract.assumes.len(), 2);
        assert!(contract.assumes.contains("valid_state"));
        assert!(contract.assumes.contains("resource_conservation"));

        assert_eq!(contract.guarantees.len(), 2);
        assert!(contract.guarantees.contains("determinism"));
        assert!(contract.guarantees.contains("closure"));

        assert_eq!(contract.exports.len(), 1);
        assert!(contract.exports.contains("api_v1"));

        assert_eq!(contract.effects.len(), 2);
        assert!(contract.effects.contains("write_accounts"));
        assert!(contract.effects.contains("write_storage"));

        assert_eq!(contract.forbids.len(), 1);
        assert!(contract.forbids.contains("direct_storage_access"));

        assert_eq!(contract.temporal.len(), 1);
        assert_eq!(contract.temporal[0].id, "liveness");
    }

    #[test]
    fn test_define_contract_deduplicates_properties() {
        let system = SystemDefinition {
            name: "dedup_test".to_string(),
            assumed_properties: vec![prop("p1", "first"), prop("p1", "duplicate")],
            guaranteed_properties: vec![],
            exported_interfaces: vec!["api".to_string(), "api".to_string()],
            state_effects: vec![],
            forbidden_interactions: vec![],
            temporal_obligations: vec![],
        };

        let contract = define_contract(&system);
        // BTreeSet deduplicates
        assert_eq!(contract.assumes.len(), 1);
        assert_eq!(contract.exports.len(), 1);
    }

    // -- verify_composition: compatible contracts --

    #[test]
    fn test_composition_valid_compatible_contracts() {
        // A assumes what B guarantees and vice versa; no effect/forbid conflicts
        let a = SubsystemContract {
            assumes: ["valid_input"].iter().map(|s| s.to_string()).collect(),
            guarantees: ["determinism", "closure"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            exports: ["api_a"].iter().map(|s| s.to_string()).collect(),
            effects: ["write_accounts"].iter().map(|s| s.to_string()).collect(),
            forbids: ["write_proofs"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let b = SubsystemContract {
            assumes: ["determinism"].iter().map(|s| s.to_string()).collect(),
            guarantees: ["valid_input", "resource_conservation"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            exports: ["api_b"].iter().map(|s| s.to_string()).collect(),
            effects: ["write_proofs_internal"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            forbids: ["write_storage"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        assert_eq!(result, CompositionResult::Valid);
    }

    // -- verify_composition: guarantees don't cover assumptions --

    #[test]
    fn test_composition_invalid_guarantees_dont_cover_assumptions() {
        // B assumes "resource_conservation" but A doesn't guarantee it
        let a = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: ["determinism"].iter().map(|s| s.to_string()).collect(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let b = SubsystemContract {
            assumes: ["determinism", "resource_conservation"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        match result {
            CompositionResult::Invalid { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == ViolationKind::GuaranteesDoNotCoverAssumptions
                        && v.properties.contains(&"resource_conservation".to_string())
                }));
            }
            CompositionResult::Valid => panic!("Expected invalid composition"),
        }
    }

    // -- verify_composition: effects conflict with forbids --

    #[test]
    fn test_composition_invalid_effects_conflict_with_forbids() {
        // A's effects include "write_storage" which B forbids
        let a = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: ["write_storage", "write_accounts"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let b = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["write_storage"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        match result {
            CompositionResult::Invalid { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == ViolationKind::EffectsConflictWithForbids
                        && v.properties.contains(&"write_storage".to_string())
                }));
            }
            CompositionResult::Valid => panic!("Expected invalid composition"),
        }
    }

    #[test]
    fn test_composition_invalid_bidirectional_effects_forbids() {
        // Both directions have conflicts
        let a = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: ["modify_proofs"].iter().map(|s| s.to_string()).collect(),
            forbids: ["modify_traces"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let b = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: ["modify_traces"].iter().map(|s| s.to_string()).collect(),
            forbids: ["modify_proofs"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        match result {
            CompositionResult::Invalid { violations } => {
                // Should have two violations: one for each direction
                let effect_violations: Vec<_> = violations
                    .iter()
                    .filter(|v| v.kind == ViolationKind::EffectsConflictWithForbids)
                    .collect();
                assert_eq!(effect_violations.len(), 2);
            }
            CompositionResult::Valid => panic!("Expected invalid composition"),
        }
    }

    // -- verify_composition: temporal conflicts --

    #[test]
    fn test_composition_invalid_temporal_conflict() {
        let a = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![temporal(
                "liveness_a",
                "A must progress",
                &["shared_resource"],
            )],
        };

        let b = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["shared_resource"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        match result {
            CompositionResult::Invalid { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == ViolationKind::TemporalConflict
                        && v.properties.contains(&"shared_resource".to_string())
                }));
            }
            CompositionResult::Valid => {
                panic!("Expected invalid composition due to temporal conflict")
            }
        }
    }

    // -- verify_composition: multiple violations --

    #[test]
    fn test_composition_reports_all_violations() {
        // Contract with multiple issues
        let a = SubsystemContract {
            assumes: ["prop_x"].iter().map(|s| s.to_string()).collect(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: ["forbidden_effect"].iter().map(|s| s.to_string()).collect(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let b = SubsystemContract {
            assumes: ["prop_y"].iter().map(|s| s.to_string()).collect(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["forbidden_effect"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let result = verify_composition(&a, &b);
        match result {
            CompositionResult::Invalid { violations } => {
                // Should have at least 3 violations:
                // 1. G(A) doesn't cover A(B) (prop_y)
                // 2. G(B) doesn't cover A(A) (prop_x)
                // 3. Eff(A) ∩ F(B) ≠ ∅ (forbidden_effect)
                assert!(violations.len() >= 3);
            }
            CompositionResult::Valid => panic!("Expected invalid composition"),
        }
    }

    // -- backward compatibility: compatible upgrade --

    #[test]
    fn test_backward_compatible_upgrade() {
        // v2 assumes less, guarantees more — compatible
        let v1 = SubsystemContract {
            assumes: ["prop_a", "prop_b"].iter().map(|s| s.to_string()).collect(),
            guarantees: ["g1"].iter().map(|s| s.to_string()).collect(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["f1"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let v2 = SubsystemContract {
            assumes: ["prop_a"].iter().map(|s| s.to_string()).collect(), // assumes less
            guarantees: ["g1", "g2"].iter().map(|s| s.to_string()).collect(), // guarantees more
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["f1"].iter().map(|s| s.to_string()).collect(), // same forbids
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        assert_eq!(result, CompatibilityResult::Compatible);
    }

    // -- backward compatibility: incompatible — assumptions expanded --

    #[test]
    fn test_backward_incompatible_assumptions_expanded() {
        let v1 = SubsystemContract {
            assumes: ["prop_a"].iter().map(|s| s.to_string()).collect(),
            guarantees: ["g1"].iter().map(|s| s.to_string()).collect(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let v2 = SubsystemContract {
            assumes: ["prop_a", "prop_new"]
                .iter()
                .map(|s| s.to_string())
                .collect(), // assumes more
            guarantees: ["g1"].iter().map(|s| s.to_string()).collect(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        match result {
            CompatibilityResult::Incompatible { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == CompatibilityViolationKind::AssumptionsExpanded
                        && v.properties.contains(&"prop_new".to_string())
                }));
            }
            CompatibilityResult::Compatible => panic!("Expected incompatible"),
        }
    }

    // -- backward compatibility: incompatible — guarantees reduced --

    #[test]
    fn test_backward_incompatible_guarantees_reduced() {
        let v1 = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: ["g1", "g2"].iter().map(|s| s.to_string()).collect(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let v2 = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: ["g1"].iter().map(|s| s.to_string()).collect(), // dropped g2
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        match result {
            CompatibilityResult::Incompatible { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == CompatibilityViolationKind::GuaranteesReduced
                        && v.properties.contains(&"g2".to_string())
                }));
            }
            CompatibilityResult::Compatible => panic!("Expected incompatible"),
        }
    }

    // -- backward compatibility: incompatible — forbids expanded --

    #[test]
    fn test_backward_incompatible_forbids_expanded() {
        let v1 = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["f1"].iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        };

        let v2 = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: ["f1", "f_new"].iter().map(|s| s.to_string()).collect(), // forbids more
            temporal: vec![],
        };

        let result = check_backward_compatibility(&v1, &v2);
        match result {
            CompatibilityResult::Incompatible { violations } => {
                assert!(violations.iter().any(|v| {
                    v.kind == CompatibilityViolationKind::ForbidsExpanded
                        && v.properties.contains(&"f_new".to_string())
                }));
            }
            CompatibilityResult::Compatible => panic!("Expected incompatible"),
        }
    }

    // -- empty contracts compose trivially --

    #[test]
    fn test_empty_contracts_compose() {
        let empty = SubsystemContract {
            assumes: BTreeSet::new(),
            guarantees: BTreeSet::new(),
            exports: BTreeSet::new(),
            effects: BTreeSet::new(),
            forbids: BTreeSet::new(),
            temporal: vec![],
        };

        assert_eq!(verify_composition(&empty, &empty), CompositionResult::Valid);
        assert_eq!(
            check_backward_compatibility(&empty, &empty),
            CompatibilityResult::Compatible
        );
    }
}
