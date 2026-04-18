"""
Invalid Witness Generator Suite — Python tooling for VSEL adversarial testing.

Derived from: INVALID_EXECUTION_WITNESS_SUITE.md, Requirements 13.1, 13.2, 13.3, 13.8.

Generates invalid witness instances programmatically for each family (W1-W8).
Each generator produces minimal invalid witnesses that should be rejected
by the Rust constraint system and invariant checks.

The construction protocol (Req 13.3) implements the formal 5-step procedure:
  (1) Construct minimal invalid witness
  (2) Verify constraint rejection
  (3) Identify rejecting constraint
  (4) Remove rejecting constraint to confirm necessity
  (5) Document

The constraint mapping (Req 13.8) ensures every constraint is the rejecting
constraint for at least one invalid witness family.
"""

from .generators import (
    W1StateViolation,
    W2TransitionViolation,
    W3TraceStructure,
    W4ObservableManipulation,
    W5AuthorizationManipulation,
    W6BatchManipulation,
    W7CommitmentManipulation,
    W8CrossSystem,
    generate_all_invalid_witnesses,
)
from .constraint_mapping import (
    ALL_CONSTRAINTS,
    WITNESS_CONSTRAINT_MAP,
    ConstraintMapping,
)
from .protocol import (
    ProtocolResult,
    StepResult,
    StepStatus,
    run_protocol,
    run_protocol_all,
    verify_constraint_coverage,
)
