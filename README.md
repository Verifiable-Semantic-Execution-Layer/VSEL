# VSEL — Verifiable Semantic Execution Layer

A formally verified execution layer where **if a proof is accepted, the corresponding execution is semantically valid** under a mechanized formal specification.

```
Verify(π) ⟹ SatisfiesConstraints(τ) ⟹ ValidConcreteTrace(τ_c) ⟹ ValidSIRTrace(τ_sir) ⟹ ValidFormalTrace(τ_f)
```

## What is VSEL?

VSEL is a protocol that bridges the gap between formal mathematical specifications and concrete execution. Instead of trusting that code "probably does the right thing," VSEL provides cryptographic proof that every execution trace is semantically valid — not just computationally correct, but *meaningful* under a formally verified specification.

The core insight: Lean 4 is the absolute source of truth. Rust does not invent semantics — it consumes a derived representation. The constraint engine does not have hand-written constraints — it compiles from an intermediate representation. Correctness takes absolute precedence over performance.

## Architecture

VSEL implements a five-level derivation chain where each level is a faithful realization of the level above:

```
L0: Formal Specification (Lean 4)        — Mathematical model defining correctness
 ↓  R₀₁ refinement (proven in Lean 4)
L1: SIR (Lean 4 → derived IR)            — Typed, deterministic semantic bridge
 ↓  R₁₂ refinement (differential testing + Lean 4 proofs)
L2: Concrete Execution (Rust)             — Deterministic execution engine
 ↓  R₂₃ refinement (constraint compiler, NOT hand-written)
L3: Constraint System (Rust)              — Algebraic constraints compiled from SIR/IR
 ↓  R₃₄ refinement
L4: Proof System (Rust + ZK backend)      — Cryptographic proof and verification
```

### Language-per-Layer

| Layer | Language | Role |
|-------|----------|------|
| L0-L1 | Lean 4 | Source of truth: formal spec, invariants, refinement proofs |
| SIR/IR | Derived from Lean 4 | Semantic bridge between formal spec and execution |
| L2-L4 | Rust | Execution engine, constraint compiler, proof system |
| Behavioral models | TLA+ | Model checking, counterexample generation |
| Adversarial tooling | Python | Invalid witness generators, fuzz orchestration |

## Repository Structure

```
formal/          Lean 4 formal specification and proofs (L0-L1)
├── VSEL/
│   ├── Foundations/    State, Input, Transition, Invariants
│   ├── Refinement/     Refinement proofs (R₀₁, R₁₂, R₂₃)
│   ├── Mapping/        Semantic mapping proofs (THM-1, THM-2)
│   ├── Invariants/     Local, Global, Temporal invariant proofs
│   ├── Composition/    Assume-guarantee soundness
│   └── Witness/        Witness uniqueness (LEM-6)

protocol/        Rust Cargo workspace (L2-L4)
├── crates/
│   ├── vsel-core/          Core types, state, input, transition, observable
│   ├── vsel-engine/        Deterministic execution engine and pipeline
│   ├── vsel-trace/         Trace recording, commitment chain, reconstruction
│   ├── vsel-mapping/       Semantic mapping and canonicalization
│   ├── vsel-invariants/    Invariant system (local, global, temporal, economic)
│   ├── vsel-constraints/   Constraint compiler (SIR/IR → constraints)
│   ├── vsel-crypto/        Hybrid cryptography (classical + PQC)
│   ├── vsel-proof/         Prover, verifier, witness, recursive proofs
│   ├── vsel-composition/   Assume-guarantee contracts, cross-system proofs
│   └── vsel-sir/           SIR/IR deserialization and reference interpreter
└── tests/
    ├── property/           Property-based tests (proptest)
    ├── differential/       Rust vs SIR interpreter differential tests
    ├── adversarial/        Invalid witness suite (W1-W8)
    └── edge_cases/         Edge Case Atlas coverage

tla/             TLA+ behavioral models and model checking
docs/            Formal documentation corpus (30+ documents)
paper/           Academic paper (LaTeX)
preprint/        Preprint (LaTeX)
tools/           Python adversarial tooling
scripts/         Build, test, and CI automation
audit/           Audit evidence per phase
```

## Key Properties

VSEL enforces 40 invariants across five categories:

- **Local** (5) — Per-transition correctness: determinism, closure, resource conservation, bounded mutation
- **Global** (5) — Per-state correctness: structural integrity, commitment consistency, monotonicity
- **Temporal** (5) — Per-trace correctness: no reversion, causality, completeness
- **Economic** (22) — Financial safety: leverage limits, solvency, anti-extraction, anti-manipulation
- **Cross-layer** (3) — Inter-layer consistency: execution = spec, constraints = validity, proof = trace

## Cryptographic Model

VSEL uses hybrid classical + post-quantum cryptography:

- Signatures: Ed25519 (classical) + ML-DSA/Falcon (PQC) — both must verify
- Hashing: SHA-3/BLAKE3 (long-term) + STARK-friendly hashes (proof-internal)
- Proofs: STARK base (transparent, post-quantum) with optional SNARK recursion
- Domain separation on all cryptographic operations

## Getting Started

### Prerequisites

- **Rust** (stable, latest) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Lean 4** (optional, for formal proofs) — `curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh`
- **TLA+ TLC** (optional, for model checking) — [tlaplus/tlaplus releases](https://github.com/tlaplus/tlaplus/releases)

### Build & Test

```bash
# Rust — compile all crates
cd protocol && cargo check

# Rust — run all tests (unit + property-based + SIR)
cd protocol && cargo test

# Lean 4 — build formal proofs (requires Lean 4 toolchain)
cd formal && lake build

# TLA+ — run model checking (requires TLC)
cd tla && tlc Properties -config MC.cfg
```

## Roadmap

VSEL follows an 11-phase roadmap with audit gates at every phase boundary. Each phase must achieve 100% invariant compliance, 0 unresolved findings, and 0 underconstraint vulnerabilities before proceeding.

| Phase | Name | Status |
|-------|------|--------|
| 0 | Foundations: Core Types + Formal Setup | ✅ Complete |
| 1 | Execution Ground Truth: Engine + Trace | 🔲 Next |
| 2 | Semantic Alignment: Mapping + Canonicalization | 🔲 Planned |
| 3 | Constraint Integrity: Compiler + Coverage | 🔲 Planned |
| 4 | Proof System Binding | 🔲 Planned |
| 5 | Verification Layer | 🔲 Planned |
| 6 | Composition Layer | 🔲 Planned |
| 7 | Adversarial Hardening | 🔲 Planned |
| 8 | Refinement Chain Completion | 🔲 Planned |
| 9 | Long-Term Security + Migration | 🔲 Planned |
| 10 | Production Readiness | 🔲 Planned |

## Documentation

The `docs/` directory contains the complete formal documentation corpus:

- [Whitepaper](docs/WHITEPAPER.md) — High-level protocol overview
- [Formal Specification](docs/FORMAL_SPECIFICATION.md) — Mathematical model (M = S, I, T, O)
- [State Machine](docs/STATE_MACHINE.md) — Transition classes and execution semantics
- [Invariants](docs/INVARIANTS.md) — All 40 invariant definitions
- [Economic Invariants](docs/ECONOMIC_INVARIANTS.md) — Financial safety properties
- [Proof Layer](docs/PROOF_LAYER.md) — Proof generation and verification
- [Threat Model](docs/THREAT_MODEL.md) — Adversarial assumptions
- [Roadmap](docs/ROADMAP.MD) — Phased implementation plan

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for security policy.

## License

See [LICENSE](LICENSE) for details.
