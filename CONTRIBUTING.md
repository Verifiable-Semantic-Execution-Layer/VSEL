# Contributing to VSEL

Thank you for your interest in contributing to the Verifiable Semantic Execution Layer (VSEL) protocol.

## Development Process

1. All changes must maintain the derivation chain: Lean 4 → SIR/IR → Rust → Constraints → Proof
2. Lean 4 is the absolute source of truth. Rust does NOT invent semantics.
3. All property-based tests must pass before merging.
4. Each phase requires an audit gate with 100% invariant compliance.

## Getting Started

- Rust workspace: `cd protocol && cargo check`
- Lean 4 project: `cd formal && lake build`
- Run tests: `cd protocol && cargo test`

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
