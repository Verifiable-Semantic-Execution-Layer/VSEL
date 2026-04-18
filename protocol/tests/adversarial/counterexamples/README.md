# Counterexample Catalog — Adversarial Tests

Derived from: COUNTEREXAMPLE_CATALOG.md, Requirements 13.4, 14.6.

## Overview

This directory is the designated location for counterexample adversarial tests.
The primary test file is located at:

```
protocol/crates/vsel-invariants/tests/counterexample_catalog.rs
```

This placement allows the tests to directly access the `vsel-invariants` crate's
internal modules (local, global, economic invariants) as dev-dependencies.

## Families

| Family     | Description              | Count |
|------------|--------------------------|-------|
| CEX-S      | State Space              | 4     |
| CEX-ECON   | Economic                 | 8     |
| CEX-T      | Transition               | 6     |
| CEX-I      | Invariant                | 3     |
| CEX-M      | Semantic Mapping         | 3     |
| CEX-C      | Constraint               | 3     |
| CEX-P      | Proof/Verification       | 3     |
| CEX-COMP   | Composition              | 2     |
| CEX-TR     | Trace                    | 4     |
| CEX-TEMP   | Temporal                 | 3     |
| CEX-CRYPTO | Cryptographic            | 4     |
| **Total**  |                          | **43**|

## Running Tests

```bash
cd protocol
cargo test --test counterexample_catalog
```

## Python Tooling

The Python counterexample catalog management tool is at `tools/counterexample/`:

```bash
python -m tools.counterexample.cli summary    # Summary report
python -m tools.counterexample.cli coverage   # Coverage check
python -m tools.counterexample.cli show CEX-S-001  # Show one entry
python -m tools.counterexample.cli report     # Markdown report
python -m tools.counterexample.cli json       # JSON export
```
