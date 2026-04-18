"""
Constraint mapping — maps each invalid witness family to its rejecting constraint(s).

Implements Requirement 13.8: every constraint is the rejecting constraint for
at least one invalid witness family. Constraints that reject no invalid witness
are investigated as redundant or incorrectly analyzed.

The mapping is bidirectional:
  - witness family → rejecting constraint(s)
  - constraint → witness families it rejects

Derived from: INVALID_EXECUTION_WITNESS_SUITE.md, CONSTRAINT_COVERAGE_MATRIX.md,
Requirements 13.3, 13.8.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set


# ---------------------------------------------------------------------------
# Witness → Constraint mapping
# ---------------------------------------------------------------------------
# Each entry maps a witness family ID (e.g. "W1.1") to the constraint(s)
# that reject it. Constraint IDs use the invariant/check names from the
# Rust invariant system (vsel-invariants) and execution engine (vsel-engine).
#
# Global invariants: G_valid, G_struct, G_commit, G_mono, G_env
# Local invariants:  L_valid, L_state, L_cons, L_bounded, L_det
# Temporal invariants: T_valid, T_no_revert, T_cons, T_causal, T_complete
# Economic invariants: E_cost, E_leverage, G_solvency, etc.
# Cross-layer: X_exec, X_constraint, X_proof
# Engine checks: MalformedInput, PreconditionViolation
# Trace checks: verify_trace, verify_chain
# Observable: obs_determinism
# Batch: batch_sequential_equivalence, batch_halt_on_invalid
# Cross-system: CI-1, CI-2

WITNESS_CONSTRAINT_MAP: Dict[str, List[str]] = {
    # W1: State Violation
    "W1.1": ["G_valid", "G_struct"],
    "W1.2": ["G_commit", "L_bounded"],
    "W1.3": ["G_env"],
    "W1.4": ["G_mono"],
    "W1.5": ["L_valid"],

    # W2: Transition Violation
    "W2.1": ["L_valid"],
    "W2.2": ["L_valid"],
    "W2.3": ["L_cons"],
    "W2.4": ["MalformedInput"],
    "W2.5": ["PreconditionViolation"],

    # W3: Trace Structure
    "W3.1": ["verify_trace", "verify_chain"],
    "W3.2": ["verify_trace", "T_complete"],
    "W3.3": ["verify_trace", "T_causal"],
    "W3.4": ["verify_trace"],

    # W4: Observable Manipulation
    "W4.1": ["obs_determinism", "L_det"],
    "W4.2": ["obs_determinism"],
    "W4.3": ["obs_determinism"],

    # W5: Authorization Manipulation
    "W5.1": ["MalformedInput"],
    "W5.2": ["T_no_revert"],
    "W5.3": ["MalformedInput", "G_env"],

    # W6: Batch Manipulation
    "W6.1": ["batch_sequential_equivalence", "L_valid"],
    "W6.2": ["batch_halt_on_invalid", "MalformedInput"],
    "W6.3": ["batch_sequential_equivalence", "T_complete"],

    # W7: Commitment Manipulation
    "W7.1": ["verify_trace", "G_commit"],
    "W7.2": ["verify_trace", "verify_chain"],

    # W8: Cross-System
    "W8.1": ["CI-2"],
    "W8.2": ["CI-1"],
}

# ---------------------------------------------------------------------------
# All known constraints in the system
# ---------------------------------------------------------------------------
# This is the complete set of constraints that must each be the rejecting
# constraint for at least one invalid witness family (Req 13.8).

ALL_CONSTRAINTS: List[str] = [
    # Global invariants
    "G_valid",
    "G_struct",
    "G_commit",
    "G_mono",
    "G_env",
    # Local invariants
    "L_valid",
    "L_cons",
    "L_bounded",
    "L_det",
    # Temporal invariants
    "T_complete",
    "T_no_revert",
    "T_causal",
    # Engine checks
    "MalformedInput",
    "PreconditionViolation",
    # Trace checks
    "verify_trace",
    "verify_chain",
    # Observable
    "obs_determinism",
    # Batch
    "batch_sequential_equivalence",
    "batch_halt_on_invalid",
    # Cross-system
    "CI-1",
    "CI-2",
]


class ConstraintMapping:
    """Bidirectional mapping between witness families and constraints.

    Provides lookup in both directions and coverage analysis.
    """

    def __init__(self, witness_map: Dict[str, List[str]]) -> None:
        self._witness_to_constraints = witness_map
        self._constraint_to_families: Dict[str, List[str]] = {}
        self._build_reverse_map()

    def _build_reverse_map(self) -> None:
        """Build the constraint → families reverse mapping."""
        for family, constraints in self._witness_to_constraints.items():
            for constraint in constraints:
                self._constraint_to_families.setdefault(constraint, []).append(family)

    def get_rejecting_constraints(self, family: str) -> List[str]:
        """Get the constraint(s) that reject a given witness family."""
        return self._witness_to_constraints.get(family, [])

    def get_families_for_constraint(self, constraint_id: str) -> List[str]:
        """Get the witness families rejected by a given constraint."""
        return self._constraint_to_families.get(constraint_id, [])

    def constraint_to_families(self) -> Dict[str, List[str]]:
        """Return the full constraint → families mapping."""
        return dict(self._constraint_to_families)

    def all_constraints(self) -> List[str]:
        """Return all known constraints in the system."""
        return list(ALL_CONSTRAINTS)

    def uncovered_constraints(self) -> List[str]:
        """Return constraints that are not the rejecting constraint for any family.

        Requirement 13.8: these must be investigated as redundant or
        incorrectly analyzed.
        """
        return [
            c for c in ALL_CONSTRAINTS
            if c not in self._constraint_to_families
            or not self._constraint_to_families[c]
        ]

    def coverage_report(self) -> Dict[str, object]:
        """Generate a coverage report.

        Returns a dict with:
          - total_constraints: number of known constraints
          - covered_constraints: number covered by at least one family
          - uncovered_constraints: list of uncovered constraint IDs
          - coverage_percentage: float 0-100
          - per_constraint: dict mapping each constraint to its families
        """
        uncovered = self.uncovered_constraints()
        covered = len(ALL_CONSTRAINTS) - len(uncovered)
        pct = (covered / len(ALL_CONSTRAINTS) * 100) if ALL_CONSTRAINTS else 0.0

        return {
            "total_constraints": len(ALL_CONSTRAINTS),
            "covered_constraints": covered,
            "uncovered_constraints": uncovered,
            "coverage_percentage": round(pct, 1),
            "per_constraint": {
                c: self._constraint_to_families.get(c, [])
                for c in ALL_CONSTRAINTS
            },
        }

    def verify_full_coverage(self) -> bool:
        """Verify every constraint is the rejecting constraint for at least one family.

        Returns True if coverage is 100%, False otherwise.
        """
        return len(self.uncovered_constraints()) == 0
