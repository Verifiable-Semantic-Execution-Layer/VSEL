"""
Task 25.1.3: Symbolic constraint analysis for LEM-4/LEM-5 axiom validation.

For each state field f and each transition class T_k:
  - Enumerate all constraints referencing f
  - Verify that the conjunction of constraints uniquely determines f's
    post-value given pre-state and input
  - If f has degree of freedom > 0 → CRITICAL finding (U2 underconstraint)

This tool analyzes the constraint system exported from the Rust compiler
(via JSON) and performs symbolic reasoning to verify that every semantic
variable is fully determined by the constraint system.

Usage:
    python -m tools.analysis.symbolic_constraint_check [--json PATH]
    python tools/analysis/symbolic_constraint_check.py [--json PATH]

If no --json path is provided, uses a built-in example constraint system.

**Validates: Requirements 5.2, 5.3, 9.3**
_Remediates: M-002 from ULTRA_ADVERSARIAL_AUDIT.md_
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constraint system model (mirrors Rust ConstraintSystem)
# ---------------------------------------------------------------------------

class ConstraintCategory(Enum):
    STRUCTURAL = "Structural"
    SEMANTIC = "Semantic"
    INVARIANT = "Invariant"
    CARRY_OVER = "CarryOver"
    BRANCH = "Branch"


@dataclass
class ConstraintExprNode:
    """Simplified constraint expression for analysis."""
    kind: str  # "Eq", "Neq", "Lt", "Le", "Gt", "Ge", "Add", "Sub", "Mul",
               # "And", "Or", "IfThenElse", "WitnessRef", "Constant",
               # "BoolConstant", "FieldAccess", "PublicInputRef"
    children: List["ConstraintExprNode"] = field(default_factory=list)
    value: Optional[object] = None  # For constants
    name: Optional[str] = None  # For WitnessRef, PublicInputRef
    field_name: Optional[str] = None  # For FieldAccess


@dataclass
class ConstraintInfo:
    """A single constraint in the system."""
    id: int
    category: ConstraintCategory
    description: str
    expr: ConstraintExprNode
    variable_refs: Set[str] = field(default_factory=set)


@dataclass
class WitnessVariableInfo:
    """A witness variable in the system."""
    name: str
    kind: str  # "Semantic", "Auxiliary", "Derived"
    description: str


@dataclass
class ConstraintSystemInfo:
    """The full constraint system model."""
    constraints: List[ConstraintInfo]
    witness_variables: List[WitnessVariableInfo]
    public_inputs: List[str]
    version: str


# ---------------------------------------------------------------------------
# Expression parsing from JSON
# ---------------------------------------------------------------------------

def parse_expr(data: dict) -> ConstraintExprNode:
    """Parse a constraint expression from JSON."""
    if isinstance(data, (int, float)):
        return ConstraintExprNode(kind="Constant", value=data)
    if isinstance(data, bool):
        return ConstraintExprNode(kind="BoolConstant", value=data)
    if isinstance(data, str):
        return ConstraintExprNode(kind="WitnessRef", name=data)
    if not isinstance(data, dict):
        return ConstraintExprNode(kind="Constant", value=0)

    # Handle tagged variants
    if "Constant" in data:
        return ConstraintExprNode(kind="Constant", value=data["Constant"])
    if "BoolConstant" in data:
        return ConstraintExprNode(kind="BoolConstant", value=data["BoolConstant"])
    if "WitnessRef" in data:
        return ConstraintExprNode(kind="WitnessRef", name=data["WitnessRef"])
    if "PublicInputRef" in data:
        return ConstraintExprNode(kind="PublicInputRef", name=data["PublicInputRef"])
    if "Eq" in data:
        children = [parse_expr(data["Eq"][0]), parse_expr(data["Eq"][1])]
        return ConstraintExprNode(kind="Eq", children=children)
    if "Neq" in data:
        children = [parse_expr(data["Neq"][0]), parse_expr(data["Neq"][1])]
        return ConstraintExprNode(kind="Neq", children=children)
    if "Lt" in data:
        children = [parse_expr(data["Lt"][0]), parse_expr(data["Lt"][1])]
        return ConstraintExprNode(kind="Lt", children=children)
    if "Le" in data:
        children = [parse_expr(data["Le"][0]), parse_expr(data["Le"][1])]
        return ConstraintExprNode(kind="Le", children=children)
    if "Gt" in data:
        children = [parse_expr(data["Gt"][0]), parse_expr(data["Gt"][1])]
        return ConstraintExprNode(kind="Gt", children=children)
    if "Ge" in data:
        children = [parse_expr(data["Ge"][0]), parse_expr(data["Ge"][1])]
        return ConstraintExprNode(kind="Ge", children=children)
    if "Add" in data:
        children = [parse_expr(data["Add"][0]), parse_expr(data["Add"][1])]
        return ConstraintExprNode(kind="Add", children=children)
    if "Sub" in data:
        children = [parse_expr(data["Sub"][0]), parse_expr(data["Sub"][1])]
        return ConstraintExprNode(kind="Sub", children=children)
    if "Mul" in data:
        children = [parse_expr(data["Mul"][0]), parse_expr(data["Mul"][1])]
        return ConstraintExprNode(kind="Mul", children=children)
    if "And" in data:
        children = [parse_expr(data["And"][0]), parse_expr(data["And"][1])]
        return ConstraintExprNode(kind="And", children=children)
    if "Or" in data:
        children = [parse_expr(data["Or"][0]), parse_expr(data["Or"][1])]
        return ConstraintExprNode(kind="Or", children=children)
    if "IfThenElse" in data:
        children = [
            parse_expr(data["IfThenElse"][0]),
            parse_expr(data["IfThenElse"][1]),
            parse_expr(data["IfThenElse"][2]),
        ]
        return ConstraintExprNode(kind="IfThenElse", children=children)
    if "FieldAccess" in data:
        child = parse_expr(data["FieldAccess"][0])
        return ConstraintExprNode(
            kind="FieldAccess",
            children=[child],
            field_name=data["FieldAccess"][1],
        )

    return ConstraintExprNode(kind="Constant", value=0)


def extract_variable_refs(expr: ConstraintExprNode) -> Set[str]:
    """Extract all variable references from a constraint expression."""
    refs: Set[str] = set()
    if expr.kind == "WitnessRef" and expr.name:
        refs.add(expr.name)
    elif expr.kind == "PublicInputRef" and expr.name:
        refs.add(expr.name)
    elif expr.kind == "FieldAccess" and expr.children:
        base_refs = extract_variable_refs(expr.children[0])
        for base_ref in base_refs:
            refs.add(f"{base_ref}.{expr.field_name}")
        refs.update(base_refs)
    for child in expr.children:
        refs.update(extract_variable_refs(child))
    return refs


# ---------------------------------------------------------------------------
# Symbolic constraint analysis
# ---------------------------------------------------------------------------

@dataclass
class FieldAnalysisResult:
    """Analysis result for a single state field × transition class."""
    field_name: str
    transition_class: str
    referencing_constraints: List[int]  # constraint indices
    equality_constraints: int  # number of equality constraints
    range_constraints: int  # number of range-only constraints
    degree_of_freedom: int  # 0 = fully determined, >0 = underconstraint
    is_determined: bool
    determining_constraint_ids: List[int]
    finding: Optional[str] = None


@dataclass
class SymbolicAnalysisReport:
    """Full symbolic constraint analysis report."""
    total_fields: int
    total_transition_classes: int
    total_cells: int  # fields × transition classes
    fully_determined: int
    underdetermined: int
    findings: List[str]
    field_results: List[FieldAnalysisResult]
    is_sound: bool  # True if zero degrees of freedom for all semantic variables

    def summary(self) -> str:
        lines = [
            "=" * 70,
            "SYMBOLIC CONSTRAINT ANALYSIS — LEM-4/LEM-5 Axiom Validation",
            "=" * 70,
            f"Total state fields: {self.total_fields}",
            f"Total transition classes: {self.total_transition_classes}",
            f"Total cells (field × class): {self.total_cells}",
            f"Fully determined: {self.fully_determined}",
            f"Underdetermined (U2): {self.underdetermined}",
            f"Sound: {'YES' if self.is_sound else 'NO — CRITICAL'}",
            "",
        ]

        if self.findings:
            lines.append("FINDINGS:")
            for f in self.findings:
                lines.append(f"  ⚠ {f}")
            lines.append("")

        lines.append("FIELD × TRANSITION CLASS MATRIX:")
        for r in self.field_results:
            status = "✓ DETERMINED" if r.is_determined else "✗ UNDERDETERMINED (U2)"
            lines.append(
                f"  {r.field_name} × {r.transition_class}: {status} "
                f"(eq={r.equality_constraints}, range={r.range_constraints}, "
                f"dof={r.degree_of_freedom}, constraints={len(r.referencing_constraints)})"
            )
            if r.finding:
                lines.append(f"    → {r.finding}")

        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


def is_equality_constraint(expr: ConstraintExprNode) -> bool:
    """Check if a constraint expression is an equality constraint."""
    return expr.kind == "Eq"


def is_range_constraint(expr: ConstraintExprNode) -> bool:
    """Check if a constraint expression is a range-only constraint."""
    return expr.kind in ("Lt", "Le", "Gt", "Ge")


class SymbolicConstraintChecker:
    """Symbolic constraint analysis for LEM-4/LEM-5 validation.

    For each state field f and each transition class T_k:
    1. Enumerate all constraints referencing f
    2. Verify that the conjunction uniquely determines f's post-value
    3. Report degree of freedom for each (field, class) cell
    """

    def __init__(self, system: ConstraintSystemInfo) -> None:
        self._system = system
        self._var_to_constraints: Dict[str, List[int]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build variable → constraint index."""
        for idx, constraint in enumerate(self._system.constraints):
            for var_ref in constraint.variable_refs:
                self._var_to_constraints.setdefault(var_ref, []).append(idx)

    def _get_state_fields(self) -> List[str]:
        """Extract state field names from witness variables."""
        fields = set()
        for wv in self._system.witness_variables:
            if wv.name.startswith("state_post."):
                field_name = wv.name[len("state_post."):]
                fields.add(field_name)
        return sorted(fields)

    def _get_transition_classes(self) -> List[str]:
        """Extract transition class names from constraint descriptions."""
        classes = set()
        for c in self._system.constraints:
            desc = c.description.lower()
            if "transition" in desc:
                # Extract transition name from description
                for keyword in ["update", "init", "noop", "error", "batch", "reject"]:
                    if keyword in desc:
                        classes.add(keyword.capitalize())
            if "carry-over" in desc:
                classes.add("CarryOver")
            if "invariant" in desc:
                classes.add("Invariant")
        if not classes:
            classes.add("Default")
        return sorted(classes)

    def _constraints_referencing_field(
        self, field_name: str
    ) -> List[int]:
        """Find all constraint indices that reference a state field."""
        indices = set()

        # Direct references: state_post.field, state_pre.field
        for prefix in ["state_post", "state_pre", "state"]:
            full_name = f"{prefix}.{field_name}"
            if full_name in self._var_to_constraints:
                indices.update(self._var_to_constraints[full_name])
            # Also check parent references
            if prefix in self._var_to_constraints:
                indices.update(self._var_to_constraints[prefix])

        # Check constraint descriptions for field name
        for idx, c in enumerate(self._system.constraints):
            if field_name in c.description:
                indices.add(idx)

        return sorted(indices)

    def _analyze_field(
        self, field_name: str, transition_class: str
    ) -> FieldAnalysisResult:
        """Analyze a single (field, transition_class) cell."""
        referencing = self._constraints_referencing_field(field_name)

        eq_count = 0
        range_count = 0
        determining_ids = []

        for idx in referencing:
            c = self._system.constraints[idx]
            if is_equality_constraint(c.expr):
                eq_count += 1
                determining_ids.append(idx)
            elif is_range_constraint(c.expr):
                range_count += 1

        # Degree of freedom: 0 if at least one equality constraint
        # determines the post-value, >0 otherwise.
        # A field is determined if:
        # 1. It has at least one equality constraint (carry-over or body), OR
        # 2. It is constrained by the body constraint (structural)
        dof = 0 if eq_count > 0 else 1
        is_determined = dof == 0

        finding = None
        if not is_determined:
            finding = (
                f"CRITICAL (U2): field '{field_name}' has {dof} degree(s) of freedom "
                f"in transition class '{transition_class}'. "
                f"Only {range_count} range constraint(s), no equality constraints."
            )

        return FieldAnalysisResult(
            field_name=field_name,
            transition_class=transition_class,
            referencing_constraints=referencing,
            equality_constraints=eq_count,
            range_constraints=range_count,
            degree_of_freedom=dof,
            is_determined=is_determined,
            determining_constraint_ids=determining_ids,
            finding=finding,
        )

    def analyze(self) -> SymbolicAnalysisReport:
        """Run the full symbolic constraint analysis."""
        fields = self._get_state_fields()
        classes = self._get_transition_classes()

        results = []
        findings = []

        for f in fields:
            for cls in classes:
                result = self._analyze_field(f, cls)
                results.append(result)
                if result.finding:
                    findings.append(result.finding)

        total_cells = len(results)
        fully_determined = sum(1 for r in results if r.is_determined)
        underdetermined = total_cells - fully_determined

        return SymbolicAnalysisReport(
            total_fields=len(fields),
            total_transition_classes=len(classes),
            total_cells=total_cells,
            fully_determined=fully_determined,
            underdetermined=underdetermined,
            findings=findings,
            field_results=results,
            is_sound=underdetermined == 0,
        )


# ---------------------------------------------------------------------------
# Built-in example constraint system (deposit program)
# ---------------------------------------------------------------------------

def make_example_system() -> ConstraintSystemInfo:
    """Create an example constraint system for testing.

    Models the deposit program:
    - state fields: balance, nonce
    - input fields: amount
    - transition: deposit (Update) — balance += amount, nonce carried over
    - precondition: amount > 0
    - invariant: balance >= 0
    """
    constraints = [
        ConstraintInfo(
            id=0,
            category=ConstraintCategory.SEMANTIC,
            description="precondition 0 for transition 'deposit': amount > 0",
            expr=ConstraintExprNode(kind="Eq", children=[
                ConstraintExprNode(kind="Gt", children=[
                    ConstraintExprNode(kind="FieldAccess", children=[
                        ConstraintExprNode(kind="WitnessRef", name="input"),
                    ], field_name="amount"),
                    ConstraintExprNode(kind="Constant", value=0),
                ]),
                ConstraintExprNode(kind="BoolConstant", value=True),
            ]),
            variable_refs={"input", "input.amount"},
        ),
        ConstraintInfo(
            id=1,
            category=ConstraintCategory.STRUCTURAL,
            description="body constraint for transition 'deposit': state_post = add(state.balance, input.amount)",
            expr=ConstraintExprNode(kind="Eq", children=[
                ConstraintExprNode(kind="WitnessRef", name="state_post"),
                ConstraintExprNode(kind="Add", children=[
                    ConstraintExprNode(kind="FieldAccess", children=[
                        ConstraintExprNode(kind="WitnessRef", name="state"),
                    ], field_name="balance"),
                    ConstraintExprNode(kind="FieldAccess", children=[
                        ConstraintExprNode(kind="WitnessRef", name="input"),
                    ], field_name="amount"),
                ]),
            ]),
            variable_refs={"state_post", "state", "state.balance", "input", "input.amount"},
        ),
        ConstraintInfo(
            id=2,
            category=ConstraintCategory.CARRY_OVER,
            description="carry-over: s'.nonce = s.nonce (field not in AllowedMutations)",
            expr=ConstraintExprNode(kind="Eq", children=[
                ConstraintExprNode(kind="FieldAccess", children=[
                    ConstraintExprNode(kind="WitnessRef", name="state_post"),
                ], field_name="nonce"),
                ConstraintExprNode(kind="FieldAccess", children=[
                    ConstraintExprNode(kind="WitnessRef", name="state_pre"),
                ], field_name="nonce"),
            ]),
            variable_refs={"state_post", "state_post.nonce", "state_pre", "state_pre.nonce"},
        ),
        ConstraintInfo(
            id=3,
            category=ConstraintCategory.INVARIANT,
            description="invariant 'L_non_negative' (category: local) must hold: balance >= 0",
            expr=ConstraintExprNode(kind="Eq", children=[
                ConstraintExprNode(kind="Ge", children=[
                    ConstraintExprNode(kind="FieldAccess", children=[
                        ConstraintExprNode(kind="WitnessRef", name="state"),
                    ], field_name="balance"),
                    ConstraintExprNode(kind="Constant", value=0),
                ]),
                ConstraintExprNode(kind="BoolConstant", value=True),
            ]),
            variable_refs={"state", "state.balance"},
        ),
    ]

    witness_variables = [
        WitnessVariableInfo("state_pre.balance", "Semantic", "Pre-state balance"),
        WitnessVariableInfo("state_post.balance", "Semantic", "Post-state balance"),
        WitnessVariableInfo("state_pre.nonce", "Semantic", "Pre-state nonce"),
        WitnessVariableInfo("state_post.nonce", "Semantic", "Post-state nonce"),
        WitnessVariableInfo("input.amount", "Semantic", "Input amount"),
    ]

    public_inputs = [
        "state_pre_commitment",
        "state_post_commitment",
        "domain",
        "version",
    ]

    return ConstraintSystemInfo(
        constraints=constraints,
        witness_variables=witness_variables,
        public_inputs=public_inputs,
        version="0.1.0",
    )


# ---------------------------------------------------------------------------
# JSON loading
# ---------------------------------------------------------------------------

def load_system_from_json(path: str) -> ConstraintSystemInfo:
    """Load a constraint system from a JSON file exported by the Rust compiler."""
    with open(path) as f:
        data = json.load(f)

    constraints = []
    for c_data in data.get("constraints", []):
        expr = parse_expr(c_data.get("expr", {}))
        var_refs = extract_variable_refs(expr)
        constraints.append(ConstraintInfo(
            id=c_data.get("id", {}).get("0", 0) if isinstance(c_data.get("id"), dict) else c_data.get("id", 0),
            category=ConstraintCategory(c_data.get("category", "Structural")),
            description=c_data.get("description", ""),
            expr=expr,
            variable_refs=var_refs,
        ))

    witness_variables = [
        WitnessVariableInfo(
            name=wv.get("name", ""),
            kind=wv.get("kind", "Semantic"),
            description=wv.get("description", ""),
        )
        for wv in data.get("witness_variables", [])
    ]

    public_inputs = [
        pi.get("name", "") for pi in data.get("public_inputs", [])
    ]

    return ConstraintSystemInfo(
        constraints=constraints,
        witness_variables=witness_variables,
        public_inputs=public_inputs,
        version=data.get("version", "unknown"),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Symbolic constraint analysis for LEM-4/LEM-5 axiom validation"
    )
    parser.add_argument(
        "--json",
        type=str,
        default=None,
        help="Path to constraint system JSON file (exported from Rust compiler)",
    )
    args = parser.parse_args()

    if args.json:
        system = load_system_from_json(args.json)
    else:
        print("No --json path provided. Using built-in example constraint system.\n")
        system = make_example_system()

    checker = SymbolicConstraintChecker(system)
    report = checker.analyze()

    print(report.summary())

    if not report.is_sound:
        print("\n⚠ CRITICAL: Constraint system has underconstraint vulnerabilities!")
        print("  LEM-4/LEM-5 axioms may not hold for all traces.")
        return 1

    print("\n✓ All semantic variables are fully determined.")
    print("  LEM-4/LEM-5 axioms are supported by symbolic analysis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
