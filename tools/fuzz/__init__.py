"""
Adversarial Fuzzing Suite — Python tooling for VSEL constraint fuzzing.

Derived from: UNDERCONSTRAINT_ANALYSIS.md, INVALID_EXECUTION_WITNESS_SUITE.md,
THREAT_MODEL.md.
Requirements: 13.6 (adversarial constraint testing), 18.6 (adversarial testing).

Phase 3: Adversarial fuzzing — random invalid trace generation, witness mutation,
targeted U-type inputs.

Full-system fuzzing: orchestrates the Rust proptest-based full-system fuzzer
that exercises all transition classes, invariants, error recovery, and
cascading error resilience.

Generates adversarial inputs designed to exploit potential underconstraint
vulnerabilities in the VSEL constraint system. Works alongside the Rust
proptest-based fuzzer in protocol/crates/vsel-constraints/tests/ and
protocol/crates/vsel-invariants/tests/.
"""

from .adversarial_fuzzer import (
    AdversarialFuzzer,
    FuzzResult,
    FuzzStrategy,
    MutatedWitness,
    MutationKind,
)
from .full_system_fuzzer import (
    FullSystemFuzzer,
    FuzzProperty,
    FuzzReport,
    PropertyResult,
)
