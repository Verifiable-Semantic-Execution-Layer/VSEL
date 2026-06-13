# VSEL — Verifiable Semantic Execution Layer

A verification-oriented execution layer that distinguishes cryptographic proof consistency from final semantic acceptance. Final acceptance is only valid in the trace-strict verifier path when proof, public inputs, witness, constraints, invariants, the complete execution trace, and authoritative executable or mechanized semantic evidence all verify.

```
StrictTraceVerify(π, Pub, W, C, τ, E_sem) = FullyVerified
  ⟹ CryptographicallyConsistent(π, Pub)
  ∧ WitnessConstraintVerified(W, C)
  ∧ DeterministicReplay(τ)
  ∧ AuthoritativeSemanticEvidence(E_sem)
  ⟹ ValidTrace(τ)
```

## What is VSEL?

VSEL is a protocol intended to bridge formal mathematical specifications and concrete execution. A cryptographically consistent proof is necessary but not sufficient: semantic validity requires an additional executable or mechanized semantic verifier whose evidence is bound to the proof context and the complete execution trace. The legacy `verify()` path reports cryptographic consistency only.

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
│   ├── Witness/        Witness uniqueness (LEM-6)
│   └── Checker/        Executable semantic-certificate checker (`vselCheck`)

protocol/        Rust Cargo workspace (L2-L4)
├── crates/
│   ├── vsel-core/          Core types, state, input, transition, observable
│   ├── vsel-engine/        Deterministic execution engine and pipeline
│   ├── vsel-trace/         Trace recording, commitment chain, replay resistance
│   ├── vsel-mapping/       Semantic mapping and canonicalization
│   ├── vsel-invariants/    Invariant system (local, global, temporal, economic)
│   ├── vsel-constraints/   Constraint compiler (SIR/IR → constraints)
│   ├── vsel-crypto/        Hybrid cryptography (classical + PQC), key lifecycle, migration
│   ├── vsel-proof/         Prover, verifier, witness, recursive proofs, replay guard
│   ├── vsel-composition/   Assume-guarantee contracts, cross-system proofs
│   └── vsel-sir/           SIR/IR deserialization and reference interpreter
└── tests/
    ├── property/           Property-based tests (proptest, 170 tests)
    ├── integration/        Long trace simulation (100-5000 steps)
    ├── differential/       Rust vs SIR interpreter differential tests
    ├── adversarial/        Invalid witness suite (W1-W8) [Phase 9]
    └── edge_cases/         Edge Case Atlas coverage [Phase 9]

tla/             TLA+ behavioral models (StateMachine, Invariants, TemporalProperties, Composition)
docs/            Formal documentation corpus (30+ documents)
paper/           Academic paper (LaTeX)
preprint/        Preprint (LaTeX)
audit/           Audit evidence per phase (phase_0 through phase_8)
tools/           Python adversarial tooling [Phase 9]
scripts/         Build, test, and CI automation
```

## Key Properties

VSEL enforces 40+ invariants across five categories:

- **Local** (5) — Per-transition correctness: determinism, closure, resource conservation, bounded mutation
- **Global** (5) — Per-state correctness: structural integrity, commitment consistency, monotonicity
- **Temporal** (10) — Per-trace correctness: no reversion (SAFE-5 nonce monotonicity), causality (block height + reordering attack detection), completeness, plus temporal economic invariants (TE_extraction, TE_flash, TE_sandwich, TE_manipulation, TE_velocity)
- **Economic** (22) — Financial safety: leverage limits, solvency, anti-extraction, anti-manipulation
- **Cross-layer** (3) — Inter-layer consistency: execution = spec, constraints = validity, proof = trace

## Cryptographic Model

VSEL uses hybrid classical + post-quantum cryptography:

- Signatures: Ed25519 (classical) + ML-DSA/Falcon (PQC) — both must verify
- Hashing: SHA-3/BLAKE3 (long-term) + STARK-friendly hashes (proof-internal)
- Proofs: STARK base (transparent, post-quantum) with optional SNARK recursion
- Domain separation on all cryptographic operations
- Key lifecycle management: generation, rotation, revocation
- Cryptographic migration protocols for commitment, signature, and proof migration
- Replay resistance: proof replay guard (time-window + domain binding) and trace replay detector (epoch-based + domain binding)

## Getting Started

### Prerequisites

- **Rust** (stable, latest) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Lean 4** (optional, for formal proofs) — `curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh`
- **TLA+ TLC** (optional, for model checking) — [tlaplus/tlaplus releases](https://github.com/tlaplus/tlaplus/releases)

### Build & Test

```bash
# Rust — compile all crates
cd protocol && cargo check

# Rust — run all tests (unit + property-based + integration)
cd protocol && cargo test

# Rust — run long trace simulation (includes 5000-step ignored test)
cd protocol && cargo test --test integration_long_trace -- --ignored

# Lean 4 — build formal proofs (requires Lean 4 toolchain)
cd formal && lake build

# Lean 4 — build executable semantic certificate checker
cd formal && lake build vselCheck

# TLA+ — run model checking (requires TLC)
cd tla && tlc Properties -config MC.cfg
```

## Current Status

VSEL-001 remediation is implemented at the verifier-contract level. `verify()` remains cryptographic-only, `verify_strict()` remains fail-closed without trace context, and `verify_strict_trace()` is the final semantic-acceptance path: it replays the supplied trace deterministically, checks witness/constraint binding, and requires authoritative semantic evidence. The Lean path invokes an executable certificate checker (`lake env lean --run VSEL/Checker/Main.lean`) over a canonical semantic certificate bound to proof, public inputs, witness, constraints, trace, formal-spec commitment, and discharged obligations. STARK final acceptance must use `BackendProver<B>` and `BackendCryptographicVerifier<B>` with the same real `ZkBackend`; `GenericProver<HashBackend>` and `GenericVerifier<HashBackend>` remain legacy cryptographic-consistency tools only. Relabeling hash-placeholder proofs as STARK is rejected. Plonky3 public inputs bind the complete ordered observable content through an observable digest, not only observable count. Cairo/STARK evidence uses the `CairoStarkBackend` adapter contract: metadata must be `cairo-stark/<adapter-id>`, proof bytes must be canonical VCAI/v1, and the adapter certificate must bind a canonical Cairo source-manifest hash, Sierra/CASM/executable hashes, Cairo semantic-binding report hash, Cairo trace hash, public input hash, constraint commitment, statement hash, and proof hash. The Lean semantic certificate additionally requires `cairo_source_manifest_hash`, `cairo_semantic_binding_hash`, `cairo:source_manifest_binding`, and `cairo:semantic_binding_report_binding`. Legacy `VSEL-CAIRO-STARK-V1` text envelopes and bare `cairo-stark` identifiers are rejected. The opt-in `cairo-stark-backend` feature exposes fail-closed Stone/Stwo/Scarb command adapter constructors and the checked-in `vsel-cairo-native-wrapper`; it does not vendor native tooling or imply that a Cairo proof exists without configured native commands. See `docs/CAIRO_STARK_BACKEND.md`.

The pre-production acceptance gate is `bash scripts/preproduction_acceptance.sh`.
It builds the Lean checker, builds and tests the Cairo reference target,
generates a fresh Scarb/Stwo proof, verifies it natively, packages it as
VCAI/v1 through the checked-in wrapper, verifies it through
`BackendCryptographicVerifier`, runs `verify_strict_trace`, executes the Lean
semantic-certificate checker, and runs adversarial proof-tampering tests. The
gate writes `target/preproduction/acceptance-report.json` with toolchain
versions, native execution id, SHA-3/SHA-256 hashes for the canonical Cairo
source manifest, SHA-3/SHA-256 hashes for the Cairo semantic-binding report,
and SHA-256 hashes for the generated `proof.json` and `prover_input.json`. This
gate passes the same source-manifest and semantic-binding artifacts into the
VCAI acceptance drill, where the wrapper and Lean certificate check their
hashes. It is operational evidence for the native-proof path; it is not a claim that
Lean independently replays the full VSEL semantics without the Rust executable
trace checker.

## Roadmap

VSEL follows an 11-phase roadmap with audit gates at every phase boundary. Each phase must achieve 100% invariant compliance, 0 unresolved findings, and 0 underconstraint vulnerabilities before proceeding.

| Phase | Name | Status |
|-------|------|--------|
| 0 | Foundations: Core Types + Formal Setup | ✅ Complete |
| 1 | Execution Ground Truth: Engine + Trace | ✅ Complete |
| 2 | Semantic Alignment: Mapping + Canonicalization | ✅ Complete |
| 3 | Constraint Integrity: Compiler + Coverage | ✅ Complete |
| 4 | Proof System Binding | ✅ Complete |
| 5 | Verification Authority | ✅ Complete |
| 6 | Composition Survival | ✅ Complete |
| 7 | Cryptographic Resilience | ✅ Complete |
| 8 | Temporal Robustness | ✅ Complete |
| 9 | System Hardening: Adversarial Testing | ✅ Complete — includes native proof boundary hardening |
| 10 | Pre-Production: Compliance + Final Validation | ✅ Complete — Scarb proof gate passing with VCAI/Lean acceptance |

## Phase Completion Summary

| Phase | Key Deliverables | Tests Added | Audit |
|-------|-----------------|-------------|-------|
| 0 | Core types, state machine, Lean 4 foundations, TLA+ models | 171 | ✅ |
| 1 | Execution engine, 7-step pipeline, trace engine, commitment chain | +113 | ✅ |
| 2 | Semantic mapping (μ_S, μ_Σ), canonicalization, differential testing | +83 | ✅ |
| 3 | Constraint compiler (SIR→C), coverage matrix, underconstraint analysis (U1-U8) | +84 | ✅ |
| 4 | Prover, witness construction, public inputs, domain separation, recursive proofs | +122 | ✅ |
| 5 | 7-step verification pipeline, stateful verifier, recursive verification | +109 | ✅ |
| 6 | Assume-guarantee contracts, cross-system invariants (CI-1 to CI-5), TLA+ composition | +27 | ✅ |
| 7 | Hybrid hashing (SHA-3/BLAKE3), hybrid signatures, key lifecycle, crypto migration | +97 | ✅ |
| 8 | Temporal robustness, replay resistance, long trace simulation, TLA+ temporal properties | +40 | ✅ |

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
