"""
Counterexample Catalog — Python tooling for VSEL adversarial testing.

Derived from: COUNTEREXAMPLE_CATALOG.md, Requirements 13.4, 14.6.

Manages the counterexample catalog as formal artifacts. Each counterexample
has a unique ID, property violated, concrete state sequence, root cause
analysis, and resolution documenting how the system prevents the violation.

Families:
  CEX-S:     State space counterexamples
  CEX-ECON:  Economic counterexamples
  CEX-T:     Transition counterexamples
  CEX-I:     Invariant counterexamples
  CEX-M:     Semantic mapping counterexamples
  CEX-C:     Constraint counterexamples
  CEX-P:     Proof/verification counterexamples
  CEX-COMP:  Composition counterexamples
  CEX-TR:    Trace counterexamples
  CEX-TEMP:  Temporal counterexamples
  CEX-CRYPTO: Cryptographic counterexamples
"""

from .catalog import (
    Counterexample,
    CounterexampleCatalog,
    CounterexampleFamily,
    Severity,
    build_full_catalog,
)
