"""
Adversarial Constraint Analysis Suite — Python tooling for VSEL constraint testing.

Derived from: UNDERCONSTRAINT_ANALYSIS.md, CONSTRAINT_COVERAGE_MATRIX.md,
CONSTRAINT_DERIVATION.md, design.md Component 6.

Requirements: 13.6 (adversarial constraint testing).

Provides four analysis phases:
  Phase 1: Static analysis — variable census, graph connectivity, branch coverage,
           carry-over verification.
  Phase 2: Symbolic analysis — SAT/SMT-style alternate witness search, degree of
           freedom analysis, range analysis.
  Phase 3: Adversarial fuzzing — random invalid traces, witness mutation, targeted
           U-type inputs (see tools/fuzz/).
  Phase 4: Semantic review — per-constraint semantic verification, per-property
           coverage verification.
"""

from .static_analysis import (
    BranchCoverageResult,
    CarryOverResult,
    GraphConnectivity,
    StaticAnalyzer,
    VariableCensus,
    VariableInfo,
)
from .symbolic_analysis import (
    AlternateWitnessResult,
    DegreeOfFreedomResult,
    RangeAnalysisResult,
    SymbolicAnalyzer,
)
from .semantic_review import (
    ConstraintSemanticResult,
    PropertyCoverageResult,
    SemanticReviewer,
)
