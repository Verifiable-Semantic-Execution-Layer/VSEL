# Invalid Execution Witness Suite (W1-W8)

Adversarial tests for the VSEL protocol covering all eight invalid witness families.

## Test Location

The Rust test harnesses are in:
- `protocol/crates/vsel-invariants/tests/adversarial_w1_w8_tests.rs` — W1-W8 rejection tests
- `protocol/crates/vsel-invariants/tests/witness_protocol.rs` — 5-step construction protocol

Run with:
```bash
cargo test --test adversarial_w1_w8_tests
cargo test --test witness_protocol
```

## Python Generators and Protocol

Invalid witness generators and construction protocol are in:
- `tools/invalid_witness/`

Run with:
```bash
python3 -m tools.invalid_witness.cli summary
python3 -m tools.invalid_witness.cli generate
python3 -m tools.invalid_witness.cli generate W1
python3 -m tools.invalid_witness.cli protocol          # Run 5-step protocol
python3 -m tools.invalid_witness.cli protocol W1.1     # Run protocol on one family
python3 -m tools.invalid_witness.cli coverage           # Check constraint coverage
python3 -m tools.invalid_witness.cli mapping            # Show witness→constraint map
```

## Construction Protocol (Requirement 13.3)

Each invalid witness goes through the formal 5-step construction protocol:
1. **Construct** — Build minimal invalid witness (single point of invalidity)
2. **Verify rejection** — Confirm the constraint system rejects it
3. **Identify constraint** — Determine which constraint(s) reject it
4. **Confirm necessity** — Remove rejecting constraint, verify witness would pass
5. **Document** — Record the protocol result

## Constraint Coverage (Requirement 13.8)

Every constraint must be the rejecting constraint for at least one invalid witness
family. The `coverage` command verifies this property.

## Families

| Family | Name | Sub-tests |
|--------|------|-----------|
| W1 | State Violation | negative balance, inconsistent derived, invalid environment, metadata regression, unreachable state |
| W2 | Transition Violation | arbitrary jump, hidden mutation, resource creation/destruction, unauthorized, precondition-violating |
| W3 | Trace Structure | broken chain, missing transition, reordered/duplicate entries, invalid initial state |
| W4 | Observable Manipulation | fabricated, missing, no-op with non-null |
| W5 | Authorization Manipulation | wrong payload, replayed, cross-domain |
| W6 | Batch Manipulation | reordered, skipping validation, phantom operations |
| W7 | Commitment Manipulation | wrong state, chain hash |
| W8 | Cross-System | inconsistent shared state, resource creation |

Requirements: 13.1, 13.2, 13.3, 13.8
