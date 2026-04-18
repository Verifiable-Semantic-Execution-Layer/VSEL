"""
Phase 1: Static analysis — variable census, graph connectivity, branch coverage,
carry-over verification.

Derived from: UNDERCONSTRAINT_ANALYSIS.md, CONSTRAINT_DERIVATION.md.
Requirements: 13.6 (adversarial constraint testing), 5.4 (CONST-1), 5.6 (CONST-3),
5.8 (carry-over equality).

Analyzes the constraint system structure without executing it. Detects potential
underconstraint vulnerabilities by examining the constraint graph topology.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from tools.invalid_witness.constraint_mapping import ALL_CONSTRAINTS, ConstraintMapping


# ---------------------------------------------------------------------------
# Variable census
# ---------------------------------------------------------------------------


class VariableRole(Enum):
    """Role of a variable in the constraint system."""
    SEMANTIC = "semantic"
    AUXILIARY = "auxiliary"
    DERIVED = "derived"
    PUBLIC_INPUT = "public_input"


@dataclass
class VariableInfo:
    """Information about a single variable in the constraint system."""
    name: str
    role: VariableRole
    constraint_count: int = 0
    categories: Set[str] = field(default_factory=set)
    is_free: bool = False
    is_weakly_constrained: bool = False
    is_structural_only: bool = False
    is_range_cosmetic: bool = False


@dataclass
class VariableCensus:
    """Complete census of all variables in the constraint system."""
    variables: Dict[str, VariableInfo] = field(default_factory=dict)
    total_variables: int = 0
    free_variables: List[str] = field(default_factory=list)
    weakly_constrained: List[str] = field(default_factory=list)
    structural_only: List[str] = field(default_factory=list)
    range_cosmetic: List[str] = field(default_factory=list)
    public_inputs: List[str] = field(default_factory=list)

    @property
    def is_sound(self) -> bool:
        """CONST-1: zero free variables."""
        return len(self.free_variables) == 0


# ---------------------------------------------------------------------------
# Graph connectivity
# ---------------------------------------------------------------------------


@dataclass
class GraphConnectivity:
    """Constraint graph connectivity analysis."""
    total_nodes: int = 0
    total_edges: int = 0
    connected_components: int = 0
    orphan_constraints: List[str] = field(default_factory=list)
    isolated_variables: List[str] = field(default_factory=list)
    max_degree: int = 0
    avg_degree: float = 0.0

    @property
    def is_connected(self) -> bool:
        """True if the constraint graph is fully connected (single component)."""
        return self.connected_components <= 1

    @property
    def has_orphans(self) -> bool:
        """CONST-2: no orphan constraints."""
        return len(self.orphan_constraints) > 0


# ---------------------------------------------------------------------------
# Branch coverage
# ---------------------------------------------------------------------------


@dataclass
class BranchCoverageResult:
    """Branch coverage analysis result (CONST-3)."""
    total_conditionals: int = 0
    covered_conditionals: int = 0
    missing_branches: List[str] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        if self.total_conditionals == 0:
            return 100.0
        return (self.covered_conditionals / self.total_conditionals) * 100.0

    @property
    def is_complete(self) -> bool:
        """CONST-3: all branches covered."""
        return len(self.missing_branches) == 0


# ---------------------------------------------------------------------------
# Carry-over verification
# ---------------------------------------------------------------------------


@dataclass
class CarryOverResult:
    """Carry-over equality constraint verification (Requirement 5.8)."""
    total_fields: int = 0
    total_transitions: int = 0
    expected_carry_overs: int = 0
    actual_carry_overs: int = 0
    missing_carry_overs: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """All non-mutated fields have carry-over constraints."""
        return len(self.missing_carry_overs) == 0


# ---------------------------------------------------------------------------
# Static analyzer
# ---------------------------------------------------------------------------


# Constraint system model — mirrors the Rust ConstraintSystem structure.
# We parse the Rust source to extract the constraint system topology.

@dataclass
class ConstraintInfo:
    """Parsed constraint information."""
    id: str
    category: str
    description: str
    variable_refs: List[str] = field(default_factory=list)
    is_range_only: bool = False


@dataclass
class ConstraintSystemModel:
    """Model of the constraint system extracted from Rust source analysis."""
    constraints: List[ConstraintInfo] = field(default_factory=list)
    witness_variables: List[str] = field(default_factory=list)
    public_inputs: List[str] = field(default_factory=list)
    transitions: List[str] = field(default_factory=list)
    state_fields: List[str] = field(default_factory=list)
    invariants: List[str] = field(default_factory=list)
    allowed_mutations: Dict[str, List[str]] = field(default_factory=dict)


class StaticAnalyzer:
    """Phase 1: Static analysis of the VSEL constraint system.

    Performs variable census, graph connectivity analysis, branch coverage
    verification, and carry-over constraint verification.

    The analyzer works on a ConstraintSystemModel which can be built from
    the Rust source or from a serialized constraint system.
    """

    def __init__(self, model: ConstraintSystemModel) -> None:
        self._model = model
        self._var_to_constraints: Dict[str, Set[int]] = {}
        self._constraint_to_vars: Dict[int, Set[str]] = {}
        self._build_graph()

    def _build_graph(self) -> None:
        """Build the variable ↔ constraint bipartite graph."""
        for idx, constraint in enumerate(self._model.constraints):
            var_set: Set[str] = set(constraint.variable_refs)
            self._constraint_to_vars[idx] = var_set
            for var_name in var_set:
                self._var_to_constraints.setdefault(var_name, set()).add(idx)

    # -------------------------------------------------------------------
    # Variable census
    # -------------------------------------------------------------------

    def variable_census(self) -> VariableCensus:
        """Perform a complete variable census.

        Identifies free variables (U1), weakly constrained (U2),
        structural-only (U4), and range-cosmetic (U6) variables.
        """
        census = VariableCensus()

        # Build variable info for each witness variable.
        for var_name in self._model.witness_variables:
            constraint_indices = self._var_to_constraints.get(var_name, set())

            # Also check parent references for dotted names.
            if "." in var_name:
                parent = var_name.split(".")[0]
                parent_indices = self._var_to_constraints.get(parent, set())
                constraint_indices = constraint_indices | parent_indices

            categories: Set[str] = set()
            has_range_only = True
            has_equality = False

            for idx in constraint_indices:
                c = self._model.constraints[idx]
                categories.add(c.category)
                if not c.is_range_only:
                    has_range_only = False
                    has_equality = True

            info = VariableInfo(
                name=var_name,
                role=VariableRole.SEMANTIC,
                constraint_count=len(constraint_indices),
                categories=categories,
                is_free=len(constraint_indices) == 0,
                is_weakly_constrained=len(constraint_indices) == 1,
                is_structural_only=(
                    len(categories) == 1 and "Structural" in categories
                ),
                is_range_cosmetic=(
                    has_range_only and not has_equality and len(constraint_indices) > 0
                ),
            )
            census.variables[var_name] = info

            if info.is_free:
                census.free_variables.append(var_name)
            if info.is_weakly_constrained:
                census.weakly_constrained.append(var_name)
            if info.is_structural_only:
                census.structural_only.append(var_name)
            if info.is_range_cosmetic:
                census.range_cosmetic.append(var_name)

        # Add public inputs.
        for pi in self._model.public_inputs:
            census.public_inputs.append(pi)

        census.total_variables = len(self._model.witness_variables)
        census.free_variables.sort()
        census.weakly_constrained.sort()
        census.structural_only.sort()
        census.range_cosmetic.sort()

        return census

    # -------------------------------------------------------------------
    # Graph connectivity
    # -------------------------------------------------------------------

    def graph_connectivity(self) -> GraphConnectivity:
        """Analyze constraint graph connectivity.

        Detects orphan constraints (U5), isolated variables, and
        computes connected components via union-find.
        """
        result = GraphConnectivity()

        all_nodes: Set[str] = set()
        for var_name in self._model.witness_variables:
            all_nodes.add(f"var:{var_name}")
        for idx in range(len(self._model.constraints)):
            all_nodes.add(f"con:{idx}")

        result.total_nodes = len(all_nodes)

        # Count edges and detect orphans.
        edge_count = 0
        witness_names = set(self._model.witness_variables)

        for idx, var_set in self._constraint_to_vars.items():
            connected_witnesses = var_set & witness_names
            # Also check parent references.
            for v in list(var_set):
                if "." not in v and v in witness_names:
                    connected_witnesses.add(v)
                elif "." in v:
                    parent = v.split(".")[0]
                    # Check if any witness starts with this parent
                    for wv in witness_names:
                        if wv.startswith(parent + ".") or wv == parent:
                            connected_witnesses.add(wv)

            edge_count += len(connected_witnesses)
            if not connected_witnesses:
                c = self._model.constraints[idx]
                result.orphan_constraints.append(
                    f"constraint {c.id} ({c.category}): {c.description}"
                )

        result.total_edges = edge_count

        # Isolated variables (not referenced by any constraint).
        for var_name in self._model.witness_variables:
            if var_name not in self._var_to_constraints:
                # Check parent reference.
                if "." in var_name:
                    parent = var_name.split(".")[0]
                    if parent not in self._var_to_constraints:
                        result.isolated_variables.append(var_name)
                else:
                    result.isolated_variables.append(var_name)

        # Connected components via union-find.
        parent_map: Dict[str, str] = {n: n for n in all_nodes}

        def find(x: str) -> str:
            while parent_map[x] != x:
                parent_map[x] = parent_map[parent_map[x]]
                x = parent_map[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent_map[ra] = rb

        for idx, var_set in self._constraint_to_vars.items():
            con_node = f"con:{idx}"
            for v in var_set:
                var_node = f"var:{v}"
                if var_node in all_nodes:
                    union(con_node, var_node)

        roots = {find(n) for n in all_nodes}
        result.connected_components = len(roots)

        # Degree statistics.
        degrees = [len(refs) for refs in self._var_to_constraints.values()]
        if degrees:
            result.max_degree = max(degrees)
            result.avg_degree = sum(degrees) / len(degrees)

        return result

    # -------------------------------------------------------------------
    # Branch coverage (CONST-3)
    # -------------------------------------------------------------------

    def branch_coverage(self) -> BranchCoverageResult:
        """Verify branch coverage (CONST-3).

        Checks that every conditional in the SIR program has corresponding
        Branch-category constraints in the constraint system.
        """
        result = BranchCoverageResult()

        # Count branch constraints.
        branch_constraints = [
            c for c in self._model.constraints if c.category == "Branch"
        ]
        result.covered_conditionals = len(branch_constraints)

        # Estimate total conditionals from constraint descriptions.
        # Branch constraints have descriptions like "conditional constraint (CONST-3)"
        # or "match constraint (CONST-3)".
        conditional_transitions: Set[str] = set()
        for c in self._model.constraints:
            if "CONST-3" in c.description:
                conditional_transitions.add(c.description)

        result.total_conditionals = max(
            len(conditional_transitions), result.covered_conditionals
        )

        # Check for transitions that have conditionals but no branch constraints.
        for transition_name in self._model.transitions:
            has_conditional = any(
                transition_name in c.description
                for c in self._model.constraints
                if c.category == "Branch"
            )
            # If the transition has structural constraints with If/Match patterns
            # but no branch constraints, flag it.
            has_if_pattern = any(
                "conditional" in c.description.lower()
                or "match" in c.description.lower()
                for c in self._model.constraints
                if transition_name in c.description and c.category != "Branch"
            )
            if has_if_pattern and not has_conditional:
                result.missing_branches.append(
                    f"transition '{transition_name}': conditionals found but no "
                    f"Branch constraints"
                )

        return result

    # -------------------------------------------------------------------
    # Carry-over verification (Requirement 5.8)
    # -------------------------------------------------------------------

    def carry_over_verification(self) -> CarryOverResult:
        """Verify carry-over equality constraints.

        For every transition, every field NOT in AllowedMutations must have
        a carry-over constraint: s'.field = s.field.
        """
        result = CarryOverResult()
        result.total_fields = len(self._model.state_fields)
        result.total_transitions = len(self._model.transitions)

        # Collect carry-over constraints.
        carry_over_constraints = [
            c for c in self._model.constraints if c.category == "CarryOver"
        ]

        # For each transition, check non-mutated fields.
        expected = 0
        for transition_name in self._model.transitions:
            allowed = set(self._model.allowed_mutations.get(transition_name, []))
            for field_name in self._model.state_fields:
                if field_name not in allowed:
                    expected += 1
                    # Check if a carry-over constraint exists for this field.
                    has_carry_over = any(
                        field_name in c.description
                        for c in carry_over_constraints
                    )
                    if not has_carry_over:
                        result.missing_carry_overs.append(
                            f"transition '{transition_name}', field '{field_name}': "
                            f"missing carry-over constraint"
                        )

        result.expected_carry_overs = expected
        result.actual_carry_overs = len(carry_over_constraints)

        return result

    # -------------------------------------------------------------------
    # Full static analysis
    # -------------------------------------------------------------------

    def run_all(self) -> Dict[str, object]:
        """Run all Phase 1 static analyses and return a combined report."""
        census = self.variable_census()
        connectivity = self.graph_connectivity()
        branches = self.branch_coverage()
        carry_over = self.carry_over_verification()

        findings: List[str] = []

        if not census.is_sound:
            findings.append(
                f"CONST-1 VIOLATION: {len(census.free_variables)} free variable(s): "
                f"{', '.join(census.free_variables)}"
            )
        if census.weakly_constrained:
            findings.append(
                f"U2 WARNING: {len(census.weakly_constrained)} weakly constrained "
                f"variable(s): {', '.join(census.weakly_constrained)}"
            )
        if census.structural_only:
            findings.append(
                f"U4 WARNING: {len(census.structural_only)} structural-only "
                f"variable(s): {', '.join(census.structural_only)}"
            )
        if census.range_cosmetic:
            findings.append(
                f"U6 WARNING: {len(census.range_cosmetic)} range-cosmetic "
                f"variable(s): {', '.join(census.range_cosmetic)}"
            )
        if connectivity.has_orphans:
            findings.append(
                f"U5 WARNING: {len(connectivity.orphan_constraints)} orphan "
                f"constraint(s)"
            )
        if not connectivity.is_connected:
            findings.append(
                f"GRAPH WARNING: {connectivity.connected_components} connected "
                f"components (expected 1)"
            )
        if not branches.is_complete:
            findings.append(
                f"CONST-3 WARNING: {len(branches.missing_branches)} missing "
                f"branch constraint(s)"
            )
        if not carry_over.is_complete:
            findings.append(
                f"CARRY-OVER WARNING: {len(carry_over.missing_carry_overs)} missing "
                f"carry-over constraint(s)"
            )

        is_sound = (
            census.is_sound
            and not connectivity.has_orphans
            and branches.is_complete
            and carry_over.is_complete
        )

        return {
            "phase": "Phase 1: Static Analysis",
            "is_sound": is_sound,
            "findings": findings,
            "variable_census": census,
            "graph_connectivity": connectivity,
            "branch_coverage": branches,
            "carry_over": carry_over,
        }


# ---------------------------------------------------------------------------
# Model builder — constructs ConstraintSystemModel from known VSEL structure
# ---------------------------------------------------------------------------


def build_vsel_model() -> ConstraintSystemModel:
    """Build a ConstraintSystemModel from the known VSEL constraint structure.

    Uses the constraint mapping and known invariant/field structure to
    construct a model for static analysis. This mirrors what the Rust
    compiler produces for the standard VSEL program.
    """
    model = ConstraintSystemModel()

    # State fields from the VSEL state schema.
    model.state_fields = ["balance", "nonce", "data"]

    # Transitions from the VSEL transition system.
    model.transitions = ["deposit", "withdraw", "transfer", "init", "noop"]
    model.allowed_mutations = {
        "deposit": ["balance"],
        "withdraw": ["balance", "nonce"],
        "transfer": ["balance", "nonce"],
        "init": ["balance", "nonce", "data"],
        "noop": [],
    }

    # Invariants from the VSEL invariant system.
    model.invariants = [
        "G_valid", "G_struct", "G_commit", "G_mono", "G_env",
        "L_valid", "L_cons", "L_bounded", "L_det",
        "T_complete", "T_no_revert", "T_causal",
    ]

    # Witness variables — state_pre.*, state_post.*, input.*.
    for prefix in ["state_pre", "state_post"]:
        for field_name in model.state_fields:
            model.witness_variables.append(f"{prefix}.{field_name}")
    model.witness_variables.extend(["input.amount", "input.payload_type"])

    # Public inputs.
    model.public_inputs = [
        "state_pre_commitment", "state_post_commitment", "domain", "version",
    ]

    # Build constraints from the known structure.
    cid = 0

    # Structural constraints for each transition.
    for transition_name in model.transitions:
        # Body constraint.
        model.constraints.append(ConstraintInfo(
            id=str(cid),
            category="Structural",
            description=f"body constraint for transition '{transition_name}'",
            variable_refs=["state_post", "state_pre", "input"],
        ))
        cid += 1

        # Precondition constraints.
        model.constraints.append(ConstraintInfo(
            id=str(cid),
            category="Semantic",
            description=f"precondition 0 for transition '{transition_name}'",
            variable_refs=["input"],
        ))
        cid += 1

        # Carry-over constraints.
        allowed = set(model.allowed_mutations.get(transition_name, []))
        for field_name in model.state_fields:
            if field_name not in allowed:
                model.constraints.append(ConstraintInfo(
                    id=str(cid),
                    category="CarryOver",
                    description=(
                        f"carry-over: s'.{field_name} = s.{field_name} "
                        f"(field not in AllowedMutations)"
                    ),
                    variable_refs=[
                        f"state_post.{field_name}",
                        f"state_pre.{field_name}",
                    ],
                ))
                cid += 1

    # Invariant constraints.
    for inv_name in model.invariants:
        model.constraints.append(ConstraintInfo(
            id=str(cid),
            category="Invariant",
            description=f"invariant '{inv_name}' must hold",
            variable_refs=["state_pre", "state_post"],
        ))
        cid += 1

    # Branch constraints (for transitions with conditionals).
    model.constraints.append(ConstraintInfo(
        id=str(cid),
        category="Branch",
        description="conditional constraint (CONST-3): both branches constrained",
        variable_refs=["state_pre", "input"],
    ))
    cid += 1

    return model
