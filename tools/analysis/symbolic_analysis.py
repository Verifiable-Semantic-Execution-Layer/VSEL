"""
Phase 2: Symbolic analysis — SAT/SMT-style alternate witness search, degree of
freedom analysis, range analysis.

Derived from: UNDERCONSTRAINT_ANALYSIS.md, WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md.
Requirements: 13.6 (adversarial constraint testing), 5.4 (CONST-1).

Performs symbolic reasoning over the constraint system to detect:
- Alternate witnesses: can two different witness assignments satisfy the same
  constraints with the same public inputs? (LEM-6 violation)
- Degree of freedom: how many independent values can the prover choose?
- Range analysis: what value ranges are permitted for each variable?

Note: This is a lightweight Python-based symbolic analysis. For full SAT/SMT
solving, integrate with Z3 or similar. This module provides the structural
analysis and heuristic detection that feeds into such solvers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .static_analysis import ConstraintInfo, ConstraintSystemModel


# ---------------------------------------------------------------------------
# Alternate witness analysis
# ---------------------------------------------------------------------------


class WitnessUniquenessStatus(Enum):
    """Status of witness uniqueness for a variable."""
    UNIQUE = "unique"
    POTENTIALLY_NON_UNIQUE = "potentially_non_unique"
    UNKNOWN = "unknown"


@dataclass
class AlternateWitnessResult:
    """Result of alternate witness search.

    Identifies variables where the prover may be able to choose between
    multiple valid witness values for the same public inputs.
    """
    total_variables: int = 0
    unique_variables: int = 0
    potentially_non_unique: List[str] = field(default_factory=list)
    analysis: Dict[str, WitnessUniquenessStatus] = field(default_factory=dict)

    @property
    def is_unique(self) -> bool:
        """LEM-6: all witness variables are semantically unique."""
        return len(self.potentially_non_unique) == 0


# ---------------------------------------------------------------------------
# Degree of freedom analysis
# ---------------------------------------------------------------------------


@dataclass
class DegreeOfFreedomResult:
    """Degree of freedom analysis for the constraint system.

    Computes the number of independent values the prover can choose.
    In a sound system, the degree of freedom should be zero for semantic
    variables (all values are determined by public inputs and constraints).
    """
    total_variables: int = 0
    total_constraints: int = 0
    estimated_dof: int = 0
    per_variable_dof: Dict[str, int] = field(default_factory=dict)
    underdetermined_variables: List[str] = field(default_factory=list)

    @property
    def is_fully_determined(self) -> bool:
        """True if the system has zero degrees of freedom."""
        return self.estimated_dof == 0


# ---------------------------------------------------------------------------
# Range analysis
# ---------------------------------------------------------------------------


@dataclass
class VariableRange:
    """Inferred range for a variable."""
    variable: str
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    is_bounded: bool = False
    bound_constraints: List[str] = field(default_factory=list)

    @property
    def range_width(self) -> Optional[int]:
        if self.lower_bound is not None and self.upper_bound is not None:
            return self.upper_bound - self.lower_bound
        return None


@dataclass
class RangeAnalysisResult:
    """Range analysis for all variables in the constraint system."""
    variable_ranges: Dict[str, VariableRange] = field(default_factory=dict)
    unbounded_variables: List[str] = field(default_factory=list)
    cosmetic_range_only: List[str] = field(default_factory=list)

    @property
    def all_bounded(self) -> bool:
        return len(self.unbounded_variables) == 0


# ---------------------------------------------------------------------------
# Symbolic analyzer
# ---------------------------------------------------------------------------


class SymbolicAnalyzer:
    """Phase 2: Symbolic analysis of the VSEL constraint system.

    Performs alternate witness search, degree of freedom analysis, and
    range analysis using structural heuristics over the constraint graph.
    """

    def __init__(self, model: ConstraintSystemModel) -> None:
        self._model = model
        self._var_to_constraints: Dict[str, List[int]] = {}
        self._constraint_to_vars: Dict[int, Set[str]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build variable ↔ constraint index."""
        for idx, constraint in enumerate(self._model.constraints):
            var_set = set(constraint.variable_refs)
            self._constraint_to_vars[idx] = var_set
            for var_name in var_set:
                self._var_to_constraints.setdefault(var_name, []).append(idx)

    # -------------------------------------------------------------------
    # Alternate witness search
    # -------------------------------------------------------------------

    def alternate_witness_search(self) -> AlternateWitnessResult:
        """Search for variables that may admit alternate witness values.

        A variable is potentially non-unique if:
        1. It is constrained only by range constraints (U6).
        2. It appears in fewer equality constraints than its degree of freedom.
        3. It is not transitively determined by public inputs.

        This is a heuristic analysis — full uniqueness requires SAT/SMT solving.
        """
        result = AlternateWitnessResult()
        result.total_variables = len(self._model.witness_variables)

        # Determine which variables are transitively determined by public inputs.
        determined = self._compute_determined_variables()

        for var_name in self._model.witness_variables:
            constraint_indices = self._var_to_constraints.get(var_name, [])

            # Also check parent references.
            if "." in var_name:
                parent = var_name.split(".")[0]
                parent_indices = self._var_to_constraints.get(parent, [])
                constraint_indices = list(set(constraint_indices + parent_indices))

            if not constraint_indices:
                # Free variable — definitely non-unique.
                result.analysis[var_name] = WitnessUniquenessStatus.POTENTIALLY_NON_UNIQUE
                result.potentially_non_unique.append(var_name)
                continue

            # Check if all constraints are range-only.
            all_range = all(
                self._model.constraints[idx].is_range_only
                for idx in constraint_indices
            )
            if all_range:
                result.analysis[var_name] = WitnessUniquenessStatus.POTENTIALLY_NON_UNIQUE
                result.potentially_non_unique.append(var_name)
                continue

            # Check if variable is determined.
            if var_name in determined:
                result.analysis[var_name] = WitnessUniquenessStatus.UNIQUE
            else:
                # Count equality constraints.
                eq_count = sum(
                    1 for idx in constraint_indices
                    if not self._model.constraints[idx].is_range_only
                    and self._model.constraints[idx].category in (
                        "Structural", "Semantic", "CarryOver", "Invariant"
                    )
                )
                if eq_count >= 1:
                    result.analysis[var_name] = WitnessUniquenessStatus.UNIQUE
                else:
                    result.analysis[var_name] = WitnessUniquenessStatus.POTENTIALLY_NON_UNIQUE
                    result.potentially_non_unique.append(var_name)

        result.unique_variables = sum(
            1 for s in result.analysis.values()
            if s == WitnessUniquenessStatus.UNIQUE
        )
        result.potentially_non_unique.sort()

        return result

    def _compute_determined_variables(self) -> Set[str]:
        """Compute the set of variables transitively determined by public inputs.

        A variable is determined if it appears in an equality constraint with
        a constant, public input, or another determined variable.
        """
        determined: Set[str] = set()

        # Public inputs are determined by definition.
        for pi in self._model.public_inputs:
            determined.add(pi)

        # Fixed-point iteration: propagate determinism through equality constraints.
        changed = True
        while changed:
            changed = False
            for idx, constraint in enumerate(self._model.constraints):
                if constraint.is_range_only:
                    continue
                vars_in_constraint = set(constraint.variable_refs)
                undetermined = vars_in_constraint - determined
                if len(undetermined) == 1:
                    # Single undetermined variable — it's now determined.
                    var = undetermined.pop()
                    if var not in determined:
                        determined.add(var)
                        changed = True
                elif len(undetermined) == 0:
                    # All variables determined — constraint is satisfied.
                    pass

        return determined

    # -------------------------------------------------------------------
    # Degree of freedom analysis
    # -------------------------------------------------------------------

    def degree_of_freedom(self) -> DegreeOfFreedomResult:
        """Analyze degrees of freedom in the constraint system.

        Estimates the number of independent values the prover can choose.
        Uses the formula: DoF ≈ max(0, #variables - #independent_constraints).

        For a sound system, DoF should be 0 for all semantic variables.
        """
        result = DegreeOfFreedomResult()
        result.total_variables = len(self._model.witness_variables)
        result.total_constraints = len(self._model.constraints)

        # Count independent (non-range) constraints per variable.
        for var_name in self._model.witness_variables:
            constraint_indices = self._var_to_constraints.get(var_name, [])

            # Also check parent references.
            if "." in var_name:
                parent = var_name.split(".")[0]
                parent_indices = self._var_to_constraints.get(parent, [])
                constraint_indices = list(set(constraint_indices + parent_indices))

            non_range = [
                idx for idx in constraint_indices
                if not self._model.constraints[idx].is_range_only
            ]
            dof = max(0, 1 - len(non_range))
            result.per_variable_dof[var_name] = dof
            if dof > 0:
                result.underdetermined_variables.append(var_name)

        result.estimated_dof = sum(result.per_variable_dof.values())
        result.underdetermined_variables.sort()

        return result

    # -------------------------------------------------------------------
    # Range analysis
    # -------------------------------------------------------------------

    def range_analysis(self) -> RangeAnalysisResult:
        """Analyze value ranges for all variables.

        Extracts range bounds from range constraints (Lt, Le, Gt, Ge)
        and identifies variables with only cosmetic range constraints.
        """
        result = RangeAnalysisResult()

        for var_name in self._model.witness_variables:
            constraint_indices = self._var_to_constraints.get(var_name, [])

            # Also check parent references.
            if "." in var_name:
                parent = var_name.split(".")[0]
                parent_indices = self._var_to_constraints.get(parent, [])
                constraint_indices = list(set(constraint_indices + parent_indices))

            var_range = VariableRange(variable=var_name)

            has_range = False
            has_non_range = False

            for idx in constraint_indices:
                c = self._model.constraints[idx]
                if c.is_range_only:
                    has_range = True
                    var_range.bound_constraints.append(c.description)
                    # Heuristic: extract bounds from description.
                    if ">=" in c.description or "ge" in c.description.lower():
                        var_range.lower_bound = 0  # Common: non-negative
                    if "<" in c.description or "lt" in c.description.lower():
                        var_range.upper_bound = 2**63 - 1  # Field element bound
                else:
                    has_non_range = True

            var_range.is_bounded = has_range
            result.variable_ranges[var_name] = var_range

            if not has_range and not has_non_range:
                result.unbounded_variables.append(var_name)
            elif has_range and not has_non_range:
                result.cosmetic_range_only.append(var_name)

        result.unbounded_variables.sort()
        result.cosmetic_range_only.sort()

        return result

    # -------------------------------------------------------------------
    # Full symbolic analysis
    # -------------------------------------------------------------------

    def run_all(self) -> Dict[str, object]:
        """Run all Phase 2 symbolic analyses and return a combined report."""
        witnesses = self.alternate_witness_search()
        dof = self.degree_of_freedom()
        ranges = self.range_analysis()

        findings: List[str] = []

        if not witnesses.is_unique:
            findings.append(
                f"LEM-6 WARNING: {len(witnesses.potentially_non_unique)} variable(s) "
                f"may admit alternate witnesses: "
                f"{', '.join(witnesses.potentially_non_unique)}"
            )
        if not dof.is_fully_determined:
            findings.append(
                f"DoF WARNING: estimated {dof.estimated_dof} degree(s) of freedom. "
                f"Underdetermined: {', '.join(dof.underdetermined_variables)}"
            )
        if ranges.cosmetic_range_only:
            findings.append(
                f"U6 WARNING: {len(ranges.cosmetic_range_only)} variable(s) with "
                f"only cosmetic range constraints: "
                f"{', '.join(ranges.cosmetic_range_only)}"
            )
        if ranges.unbounded_variables:
            findings.append(
                f"RANGE WARNING: {len(ranges.unbounded_variables)} unbounded "
                f"variable(s): {', '.join(ranges.unbounded_variables)}"
            )

        is_sound = witnesses.is_unique and dof.is_fully_determined

        return {
            "phase": "Phase 2: Symbolic Analysis",
            "is_sound": is_sound,
            "findings": findings,
            "alternate_witnesses": witnesses,
            "degree_of_freedom": dof,
            "range_analysis": ranges,
        }
