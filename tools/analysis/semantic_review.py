"""
Phase 4: Semantic review — per-constraint semantic verification, per-property
coverage verification.

Derived from: CONSTRAINT_COVERAGE_MATRIX.md, INVARIANTS.md, PROOF_OBLIGATIONS.md.
Requirements: 13.6 (adversarial constraint testing), 5.9 (constraint coverage),
12.9 (coverage matrix completeness), 12.10 (coverage gap detection).

Verifies that:
- Every constraint has a clear semantic purpose (not just structural).
- Every property/invariant is covered by at least one constraint.
- The constraint system covers all proof obligations (CONST-1 through CONST-4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from tools.invalid_witness.constraint_mapping import (
    ALL_CONSTRAINTS,
    WITNESS_CONSTRAINT_MAP,
    ConstraintMapping,
)
from .static_analysis import ConstraintInfo, ConstraintSystemModel


# ---------------------------------------------------------------------------
# Constraint semantic verification
# ---------------------------------------------------------------------------


class SemanticPurpose(Enum):
    """Semantic purpose of a constraint."""
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    CARRY_OVER = "carry_over"
    BRANCH_COMPLETENESS = "branch_completeness"
    BODY_COMPUTATION = "body_computation"
    STRUCTURAL_BINDING = "structural_binding"
    UNKNOWN = "unknown"


@dataclass
class ConstraintSemanticResult:
    """Result of per-constraint semantic verification."""
    total_constraints: int = 0
    verified_constraints: int = 0
    unknown_purpose: List[str] = field(default_factory=list)
    per_constraint: Dict[str, SemanticPurpose] = field(default_factory=dict)

    @property
    def all_verified(self) -> bool:
        return len(self.unknown_purpose) == 0


# ---------------------------------------------------------------------------
# Property coverage verification
# ---------------------------------------------------------------------------


@dataclass
class PropertyCoverageResult:
    """Result of per-property coverage verification."""
    total_properties: int = 0
    covered_properties: int = 0
    uncovered_properties: List[str] = field(default_factory=list)
    per_property: Dict[str, List[str]] = field(default_factory=dict)
    proof_obligations: Dict[str, bool] = field(default_factory=dict)

    @property
    def coverage_pct(self) -> float:
        if self.total_properties == 0:
            return 100.0
        return (self.covered_properties / self.total_properties) * 100.0

    @property
    def all_covered(self) -> bool:
        return len(self.uncovered_properties) == 0


# ---------------------------------------------------------------------------
# Semantic reviewer
# ---------------------------------------------------------------------------


# Known semantic patterns in constraint descriptions.
_SEMANTIC_PATTERNS: Dict[str, SemanticPurpose] = {
    "precondition": SemanticPurpose.PRECONDITION,
    "postcondition": SemanticPurpose.POSTCONDITION,
    "invariant": SemanticPurpose.INVARIANT,
    "carry-over": SemanticPurpose.CARRY_OVER,
    "CONST-3": SemanticPurpose.BRANCH_COMPLETENESS,
    "conditional constraint": SemanticPurpose.BRANCH_COMPLETENESS,
    "match constraint": SemanticPurpose.BRANCH_COMPLETENESS,
    "body constraint": SemanticPurpose.BODY_COMPUTATION,
    "variable reference": SemanticPurpose.STRUCTURAL_BINDING,
    "literal constraint": SemanticPurpose.STRUCTURAL_BINDING,
    "let binding": SemanticPurpose.STRUCTURAL_BINDING,
    "field access": SemanticPurpose.STRUCTURAL_BINDING,
    "binop constraint": SemanticPurpose.STRUCTURAL_BINDING,
}

# Proof obligations from CONSTRAINT_COVERAGE_MATRIX.md.
PROOF_OBLIGATIONS = ["CONST-1", "CONST-2", "CONST-3", "CONST-4"]

# All properties that must be covered by the constraint system.
ALL_PROPERTIES: List[str] = [
    # Global invariants
    "G_valid", "G_struct", "G_commit", "G_mono", "G_env",
    # Local invariants
    "L_valid", "L_cons", "L_bounded", "L_det",
    # Temporal invariants
    "T_complete", "T_no_revert", "T_causal",
    # Economic invariants
    "E_cost", "E_leverage",
    # Cross-layer
    "X_exec", "X_constraint", "X_proof",
    # Proof obligations
    "CONST-1", "CONST-2", "CONST-3", "CONST-4",
]


class SemanticReviewer:
    """Phase 4: Semantic review of the VSEL constraint system.

    Verifies per-constraint semantic purpose and per-property coverage.
    """

    def __init__(self, model: ConstraintSystemModel) -> None:
        self._model = model
        self._constraint_mapping = ConstraintMapping(WITNESS_CONSTRAINT_MAP)

    # -------------------------------------------------------------------
    # Per-constraint semantic verification
    # -------------------------------------------------------------------

    def constraint_semantic_verification(self) -> ConstraintSemanticResult:
        """Verify that every constraint has a clear semantic purpose.

        Classifies each constraint by matching its description against
        known semantic patterns. Constraints with unknown purpose are
        flagged for manual review.
        """
        result = ConstraintSemanticResult()
        result.total_constraints = len(self._model.constraints)

        for constraint in self._model.constraints:
            purpose = self._classify_constraint(constraint)
            result.per_constraint[constraint.id] = purpose

            if purpose == SemanticPurpose.UNKNOWN:
                result.unknown_purpose.append(
                    f"constraint {constraint.id} ({constraint.category}): "
                    f"{constraint.description}"
                )
            else:
                result.verified_constraints += 1

        return result

    def _classify_constraint(self, constraint: ConstraintInfo) -> SemanticPurpose:
        """Classify a constraint's semantic purpose from its description."""
        desc_lower = constraint.description.lower()

        for pattern, purpose in _SEMANTIC_PATTERNS.items():
            if pattern.lower() in desc_lower:
                return purpose

        # Fall back to category-based classification.
        category_map = {
            "Semantic": SemanticPurpose.PRECONDITION,
            "Invariant": SemanticPurpose.INVARIANT,
            "CarryOver": SemanticPurpose.CARRY_OVER,
            "Branch": SemanticPurpose.BRANCH_COMPLETENESS,
            "Structural": SemanticPurpose.STRUCTURAL_BINDING,
        }
        return category_map.get(constraint.category, SemanticPurpose.UNKNOWN)

    # -------------------------------------------------------------------
    # Per-property coverage verification
    # -------------------------------------------------------------------

    def property_coverage_verification(self) -> PropertyCoverageResult:
        """Verify that every property/invariant is covered by constraints.

        Checks:
        1. Every invariant has at least one Invariant-category constraint.
        2. Every proof obligation (CONST-1 through CONST-4) is covered.
        3. Cross-layer invariants are represented.
        """
        result = PropertyCoverageResult()
        result.total_properties = len(ALL_PROPERTIES)

        # Check invariant coverage.
        invariant_constraints = [
            c for c in self._model.constraints if c.category == "Invariant"
        ]

        for prop_name in ALL_PROPERTIES:
            covering_constraints: List[str] = []

            # Check if any invariant constraint mentions this property.
            for c in invariant_constraints:
                if prop_name in c.description:
                    covering_constraints.append(f"constraint {c.id}: {c.description}")

            # Check constraint mapping coverage.
            families = self._constraint_mapping.get_families_for_constraint(prop_name)
            if families:
                covering_constraints.append(
                    f"witness families: {', '.join(families)}"
                )

            # Check proof obligations via category analysis.
            if prop_name == "CONST-1":
                structural = [
                    c for c in self._model.constraints
                    if c.category in ("Structural", "Semantic")
                ]
                if structural:
                    covering_constraints.append(
                        f"{len(structural)} structural/semantic constraints"
                    )
            elif prop_name == "CONST-2":
                semantic = [
                    c for c in self._model.constraints
                    if c.category in ("Semantic", "CarryOver")
                ]
                if semantic:
                    covering_constraints.append(
                        f"{len(semantic)} semantic/carry-over constraints"
                    )
            elif prop_name == "CONST-3":
                branch = [
                    c for c in self._model.constraints if c.category == "Branch"
                ]
                if branch:
                    covering_constraints.append(
                        f"{len(branch)} branch constraints"
                    )
            elif prop_name == "CONST-4":
                # All constraints contribute to CONST-4 (deterministic generation).
                if self._model.constraints:
                    covering_constraints.append(
                        f"{len(self._model.constraints)} total constraints"
                    )

            result.per_property[prop_name] = covering_constraints

            if covering_constraints:
                result.covered_properties += 1
            else:
                result.uncovered_properties.append(prop_name)

        # Proof obligation status.
        for po in PROOF_OBLIGATIONS:
            result.proof_obligations[po] = po not in result.uncovered_properties

        return result

    # -------------------------------------------------------------------
    # Full semantic review
    # -------------------------------------------------------------------

    def run_all(self) -> Dict[str, object]:
        """Run all Phase 4 semantic analyses and return a combined report."""
        semantics = self.constraint_semantic_verification()
        coverage = self.property_coverage_verification()

        # Also check constraint mapping coverage.
        mapping_report = self._constraint_mapping.coverage_report()

        findings: List[str] = []

        if not semantics.all_verified:
            findings.append(
                f"SEMANTIC WARNING: {len(semantics.unknown_purpose)} constraint(s) "
                f"with unknown semantic purpose"
            )
        if not coverage.all_covered:
            findings.append(
                f"COVERAGE WARNING: {len(coverage.uncovered_properties)} uncovered "
                f"property/properties: {', '.join(coverage.uncovered_properties)}"
            )
        for po, covered in coverage.proof_obligations.items():
            if not covered:
                findings.append(f"PROOF OBLIGATION GAP: {po} not covered")

        uncovered_constraints = mapping_report["uncovered_constraints"]
        if uncovered_constraints:
            findings.append(
                f"CONSTRAINT MAPPING WARNING: {len(uncovered_constraints)} "
                f"constraint(s) not covered by any witness family: "
                f"{', '.join(uncovered_constraints)}"
            )

        is_sound = (
            semantics.all_verified
            and coverage.all_covered
            and not uncovered_constraints
        )

        return {
            "phase": "Phase 4: Semantic Review",
            "is_sound": is_sound,
            "findings": findings,
            "constraint_semantics": semantics,
            "property_coverage": coverage,
            "constraint_mapping_coverage": mapping_report,
        }
