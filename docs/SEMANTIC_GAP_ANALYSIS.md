# Semantic Gap Analysis — VSEL Refinement Chain

## Executive Summary

This document presents a systematic analysis of every semantic gap between the VSEL Lean 4 formal specification and the Rust implementation. The refinement chain R01 to R12 to R23 to R34 connects Lean 4 proofs to executable Rust code through a series of abstraction layers, each introducing axioms and opaque types that represent unverified trust assumptions. Every axiom is a point where the formal proofs assume something about the Rust code that has not been mechanically verified.

We catalog **32 axioms** (reduced from 33 after closing A-4 by theorem) and **26 opaque functions** across 5 layers of the refinement chain. Of these:

- **0 axioms** remain closeable by Lean 4 theorem (A-4 has been closed — see §5.1)
- **17 axioms** are closeable by Rust-side property tests
- **6 axioms** are closeable by differential tests comparing Lean and Rust semantics
- **3 axioms** are closeable by static analysis of the constraint compiler
- **4 axioms** are residual trust assumptions that cannot be mechanically closed
- **2 axioms** among the residual set have zero runtime security impact (proof infrastructure only)

The 5 highest-risk axioms are identified with full adversarial exploitation analysis. The gap-closing methodology for each classification is documented with concrete test strategies. All 4 residual trust assumptions are documented with risk analysis and mitigating evidence.

**Primary source**: `docs/AXIOM_OPAQUE_CATALOG.md` (task 7.1)
**Requirements satisfied**: 8.1, 8.2, 8.5

---

## Table of Contents

1. [Refinement Chain Architecture](#1-refinement-chain-architecture)
2. [Complete Axiom Inventory](#2-complete-axiom-inventory)
3. [Complete Opaque Type and Function Catalog](#3-complete-opaque-type-and-function-catalog)
4. [Axiom Classification Summary](#4-axiom-classification-summary)
5. [Gap-Closing Methodology](#5-gap-closing-methodology)
6. [Residual Trust Assumptions](#6-residual-trust-assumptions)
7. [Critical Attack Surface Analysis](#7-critical-attack-surface-analysis)
8. [Dependency Chain Diagram](#8-dependency-chain-diagram)
9. [Requirements Traceability](#9-requirements-traceability)

---

## 1. Refinement Chain Architecture

The VSEL formal verification architecture connects the Lean 4 specification to executable Rust code through four refinement steps. Each step introduces a new abstraction layer with axioms asserting that the lower layer faithfully implements the higher layer.

```
Layer 0: Lean 4 Formal Specification
  (State, Input, Apply, Classify, Obs, ValidState, GlobalInvariantsHold)
       |
       | R01: Formal -> SIR
       |   Files: FormalToSIR.lean
       |   Axioms: R01-1..R01-5, TP-6
       |   Opaque types: SIRState, SIRInput
       v
Layer 1: Semantic Intermediate Representation (SIR)
  (SIRState, SIRInput, SIRTransition, SIR_to_Formal_State/Input)
       |
       | R12: SIR -> Concrete Execution
       |   Files: SIRToConcrete.lean
       |   Axioms: R12-5 (encoding injectivity)
       |   Opaque functions: Encode
       v
Layer 2: Concrete Rust Execution
  (State, Input, Apply, Classify, Obs -- Rust implementations)
       |
       | R23: Concrete -> Constraint System
       |   Files: ConcreteToConstraint.lean
       |   Axioms: LEM-4, LEM-5, CONST-1..CONST-3
       |   Opaque types: ConstraintSystemR23, TraceR23, SIRProgramR23
       v
Layer 3: Constraint System (ZK Circuit)
  (ConstraintSystem, SatisfiesConstraints, Compile)
       |
       | R34: Constraint -> Proof (Plonky3 STARK)
       |   Implementation: vsel-proof/src/plonky3_backend.rs
       v
Layer 4: Zero-Knowledge Proof
  (StarkProof, prove(), verify())
```

The Mapping Layer (Commutativity.lean, Observable.lean, SemanticMapping.lean) provides the bridge functions (`mu_S`, `mu_Sigma`, `mu_O`, `Apply_f`, `Obs_f`, `Derive_f`) that connect concrete Rust execution to formal Lean semantics. The Foundations Layer (Transition.lean, Invariants.lean, State.lean) provides the bedrock axioms that all refinement layers depend on.

**Key insight**: A violation at any layer invalidates all downstream layers. The Foundations Layer axioms are the most critical because they affect the entire chain.

---

## 2. Complete Axiom Inventory

### Classification Legend

| Classification | Meaning | Verification Method |
|---|---|---|
| **Closeable by theorem** | Can be derived from more primitive axioms within Lean 4 | Replace axiom with theorem in Lean |
| **Closeable by test** | Can be validated by Rust-side property tests | `proptest` with 10,000+ iterations |
| **Closeable by differential test** | Requires comparing Lean semantics against Rust behavior | `proptest` with 1,000+ iterations comparing both sides |
| **Closeable by static analysis** | Can be verified by compile-time analysis of the constraint compiler | Instrumented compiler checks |
| **Residual trust assumption** | Cannot be mechanically closed; requires structural argument | Code review + documentation |

---

### Layer 0: Foundations (Transition.lean, Invariants.lean)

These axioms are the bedrock of the entire refinement chain. Every refinement layer depends on them.

#### A-1: `apply_closure` (AX-2)

| Field | Value |
|---|---|
| **File** | `Foundations/Transition.lean` |
| **Statement** | `ValidState s -> ValidState (Apply s sigma)` |
| **Rust assumption** | The Rust `Apply` function in `vsel-core/src/transition.rs` always produces a structurally valid state when given a valid pre-state. Balance sums equal total_supply, derived state equals `Derive(canonical)`, environment domain is non-zero, and metadata monotonicity holds. |
| **Adversarial exploit** | An attacker crafts an input causing `Apply` to produce a state where `D != Derive(C)` or balance sums diverge from total_supply. Subsequent proofs built on this invalid state would be accepted by the verifier. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `transition.rs::apply()` + `state.rs::is_valid()` |

#### A-2: `initial_state_valid` (AX-3)

| Field | Value |
|---|---|
| **File** | `Foundations/Transition.lean` |
| **Statement** | `s0.metadata.sequenceIndex = 0 -> s0.metadata.previousCommitment = zeroHash -> ValidState s0` |
| **Rust assumption** | The genesis state constructor produces a state satisfying all validity predicates when sequence_index is 0 and previous_commitment is the zero hash. |
| **Adversarial exploit** | If the genesis state is invalid, the entire inductive invariant chain collapses. An attacker controlling genesis construction could create an initial state with inconsistent balances, enabling resource theft from the first transition. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Genesis state construction in `state.rs` |

#### A-3: `error_preserves_invariants` (LEM-7)

| Field | Value |
|---|---|
| **File** | `Foundations/Transition.lean` |
| **Statement** | `ValidState s -> not (ValidInput sigma) -> ValidState (Apply s sigma)` |
| **Rust assumption** | When `Apply` receives an invalid input (missing signatures, empty payload), it still produces a valid post-state. The error path does not corrupt state. |
| **Adversarial exploit** | An attacker sends malformed inputs to corrupt state through the error handling path. If error handling breaks derived state consistency or balance conservation, subsequent valid transactions operate on corrupted state. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Error handling paths in `transition.rs::apply()` |

#### A-4: `state_validity_inductive_step` (PO-SV) — CLOSED

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `ValidState s -> ValidState (Apply s sigma)` |
| **Rust assumption** | Identical to `apply_closure` (A-1). Re-statement for the inductive proof framework. |
| **Adversarial exploit** | Same as A-1. |
| **Classification** | **Closed by theorem** (derived from A-1 `apply_closure`) |
| **Note** | Previously a redundant axiom. Now a theorem: `theorem state_validity_inductive_step ... := apply_closure s sigma`. Axiom count reduced from 33 to 32. |

#### A-5: `resource_conservation_inductive_step` (PO-RC)

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `G_struct s -> G_struct (Apply s sigma)` |
| **Rust assumption** | Every transition preserves the invariant that the sum of all account balances equals `systemData.totalSupply`. No transition creates or destroys resources. |
| **Adversarial exploit** | An attacker finds a transition that increases their balance without a corresponding decrease elsewhere, enabling infinite resource creation. Most economically devastating attack vector. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Balance manipulation logic in `transition.rs::apply()` |

#### A-6: `derived_consistency_inductive_step` (PO-DC)

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `G_commit s -> G_commit (Apply s sigma)` |
| **Rust assumption** | Every transition recomputes `derived = Derive(canonical)` in the post-state. |
| **Adversarial exploit** | If derived state becomes stale, the state root no longer matches canonical data. An attacker could present a proof against the stale root while canonical state has been modified, enabling double-spend or state rollback. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `Derive` call in `transition.rs::apply()` |

#### A-7: `monotonic_metadata_inductive_step` (PO-MM)

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `G_mono s -> G_mono (Apply s sigma)` |
| **Rust assumption** | Metadata monotonicity (genesis has zero commitment, non-genesis has non-zero commitment) is preserved by every transition. |
| **Adversarial exploit** | An attacker resets the sequence index to 0 (re-genesis) or sets previous commitment to zero on a non-genesis state, breaking the causal chain and enabling trace forgery. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Metadata update logic in `transition.rs::apply()` |

#### A-8: `environment_consistency_inductive_step` (PO-ENV)

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `G_env s -> G_env (Apply s sigma)` |
| **Rust assumption** | The environment domain tag remains non-zero after every transition. |
| **Adversarial exploit** | A zero domain tag disables domain separation in cryptographic operations, enabling cross-domain replay attacks. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Environment handling in `transition.rs::apply()` |

#### A-9: `guard_exhaustiveness`

| Field | Value |
|---|---|
| **File** | `Foundations/Invariants.lean` |
| **Statement** | `exists tc : TransitionClass, Classify s sigma = tc` |
| **Rust assumption** | The Rust `Classify` function handles every possible (state, input) pair. No input falls through without classification. |
| **Adversarial exploit** | An unclassified input triggers undefined behavior or a panic, causing denial of service or unpredictable state changes. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `transition.rs::classify()` (structurally guaranteed by catch-all `noop` branch) |

---

### Layer 1: Mapping (Commutativity.lean, Observable.lean)

These axioms bridge concrete Rust execution to the formal Lean specification through semantic mapping functions.

#### A-10: `thm1_execution_commutativity` (THM-1) — CRITICAL

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `mu_S (Apply s sigma) = Apply_f (mu_S s) (mu_Sigma sigma)` |
| **Rust assumption** | The Rust `Apply` function, when its inputs and outputs are mapped through `mu_S`/`mu_Sigma`, produces the same result as the formal-side `Apply_f`. Concrete execution is faithful to the formal specification. |
| **Adversarial exploit** | The Rust implementation silently diverges from the formal spec. An attacker finds an input where the Rust transition produces a different post-state than the formal spec predicts. Since proofs are verified against formal semantics, the attacker constructs a valid-looking proof for an invalid state transition. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `mapping.rs::verify_execution_commutativity()` |
| **Risk level** | **CRITICAL** — Single most important axiom in the refinement chain |

#### A-11: `thm4_auxiliary_independence` (THM-4)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `Apply s { payload := p, auth := a, aux := aux1 } = Apply s { payload := p, auth := a, aux := aux2 }` |
| **Rust assumption** | The Rust `Apply` function ignores the `aux` field entirely. Two inputs differing only in auxiliary data produce identical post-states. |
| **Adversarial exploit** | An attacker embeds malicious data in the `aux` field that influences the transition outcome. Since `aux` is excluded from semantic content, this creates a covert channel for state manipulation that bypasses all formal verification. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `mapping.rs::verify_auxiliary_exclusion()` |

#### A-12: `thm5_derived_commutativity` (THM-5)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `mu_D (Derive c) = Derive_f (mu_C c)` |
| **Rust assumption** | The Rust `Derive` function, when mapped through `mu_C`/`mu_D`, produces the same result as formal-side `Derive_f`. Derived state computation is semantically faithful. |
| **Adversarial exploit** | The derived state (including state root / Merkle commitment) diverges between Rust and formal spec. An attacker presents a proof against a state root that does not match actual canonical data, enabling state forgery. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `mapping.rs` (derived state mapping) |

#### A-13: `tp7_input_canonicalization_idempotent` (TP-7a)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `Canonicalize_Input (Canonicalize_Input sigma) = Canonicalize_Input sigma` |
| **Rust assumption** | The Rust `canonicalize_input` function is idempotent. |
| **Adversarial exploit** | Non-idempotent canonicalization causes different nodes to disagree on canonical form, leading to consensus failures or state divergence across replicas. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `canonicalization.rs::canonicalize_input()` |

#### A-14: `tp7_state_canonicalization_idempotent` (TP-7b)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `Canonicalize_State (Canonicalize_State s) = Canonicalize_State s` |
| **Rust assumption** | The Rust `canonicalize_state` function is idempotent. |
| **Adversarial exploit** | Same as A-13 — consensus failures from non-deterministic canonical forms. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `canonicalization.rs::canonicalize_state()` |

#### A-15: `tp8_input_canonicalization_preserves_semantics` (TP-8a)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `mu_Sigma (Canonicalize_Input sigma) = mu_Sigma sigma` |
| **Rust assumption** | Canonicalizing an input does not change its formal-domain representation. |
| **Adversarial exploit** | Canonicalization silently changes the semantic meaning of an input. An attacker crafts an input whose canonical form maps to a different formal input, causing the proof system to verify a different transition than what was executed. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `canonicalization.rs` + `mapping.rs::map_input()` |

#### A-16: `tp8_state_canonicalization_preserves_semantics` (TP-8b)

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `mu_S (Canonicalize_State s) = mu_S s` |
| **Rust assumption** | Canonicalizing a state does not change its formal-domain representation. |
| **Adversarial exploit** | Same as A-15 but for states — canonicalization changes the state root, enabling proof/state mismatch attacks. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `canonicalization.rs` + `mapping.rs::map_state()` |

#### A-17: `canon_clears_aux`

| Field | Value |
|---|---|
| **File** | `Mapping/Commutativity.lean` |
| **Statement** | `Canonicalize_Input { payload := p, auth := a, aux := aux1 } = Canonicalize_Input { payload := p, auth := a, aux := aux2 }` |
| **Rust assumption** | Canonicalization normalizes the `aux` field such that two inputs differing only in `aux` produce identical canonical forms. |
| **Adversarial exploit** | Auxiliary data leaks into the canonical form, creating a side channel. Combined with a violation of THM-4, this enables aux-dependent state manipulation that survives canonicalization. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `canonicalization.rs::canonicalize_input()` |

#### A-18: `thm2_observable_commutativity` (THM-2)

| Field | Value |
|---|---|
| **File** | `Mapping/Observable.lean` |
| **Statement** | `mu_O (Obs s sigma s') = Obs_f (mu_S s) (mu_Sigma sigma) (mu_S s')` |
| **Rust assumption** | The Rust `Obs` function (events, gas used, status), when mapped through `mu_O`, produces the same result as formal-side `Obs_f`. |
| **Adversarial exploit** | Observable outputs diverge between Rust and formal spec. An attacker causes the system to emit incorrect events or status codes while the proof system believes the transition was correct. Enables "silent" attacks where the proof verifies but user-visible behavior is wrong. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `mapping.rs::verify_observable_commutativity()` |

#### A-19: `mu_Sigma_ignores_aux`

| Field | Value |
|---|---|
| **File** | `Mapping/Observable.lean` |
| **Statement** | `mu_Sigma { payload := p, auth := a, aux := aux1 } = mu_Sigma { payload := p, auth := a, aux := aux2 }` |
| **Rust assumption** | The `map_input` function ignores the `aux` field when producing the formal input representation. |
| **Adversarial exploit** | Auxiliary data influences the formal input representation, breaking the assumption that `aux` is semantically irrelevant. An attacker crafts `aux` values that change the formal input, causing proof verification to accept transitions that should be rejected. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `mapping.rs::map_input()` |

---

### Layer 2: Refinement R01 — Formal to SIR (FormalToSIR.lean)

#### A-20: `r01_state_validity` (R01-1)

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `ValidState (SIR_to_Formal_State s_sir)` |
| **Rust assumption** | Every SIR state, when mapped to the formal domain, satisfies all validity predicates. |
| **Adversarial exploit** | An attacker constructs a SIR state that maps to an invalid formal state. Since TP-1 depends on this axiom, the entire SIR-level proof chain collapses. |
| **Classification** | Closeable by test |
| **Rust counterpart** | SIR state construction + `state.rs::is_valid()` |

#### A-21: `r01_transition_correspondence` (R01-2) — CRITICAL

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `SIR_to_Formal_State (SIRTransition s_sir sigma_sir) = Apply (SIR_to_Formal_State s_sir) (SIR_to_Formal_Input sigma_sir)` |
| **Rust assumption** | The SIR transition function, when mapped to the formal domain, produces the same result as applying the formal `Apply` function to the mapped inputs. |
| **Adversarial exploit** | The SIR interpreter diverges from the formal spec. Since the constraint system is compiled from SIR, constraints verify a different computation than what the formal spec defines. |
| **Classification** | Closeable by differential test |
| **Rust counterpart** | `vsel-sir/src/interpreter.rs` + `mapping.rs` |
| **Risk level** | **CRITICAL** — SIR-level analog of THM-1 |

#### A-22: `r01_invariant_correspondence` (R01-3)

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `GlobalInvariantsHold (SIR_to_Formal_State s_sir)` |
| **Rust assumption** | All global invariants hold on every SIR state when mapped to the formal domain. |
| **Adversarial exploit** | An attacker constructs a SIR state where global invariants are violated in the formal domain. Since TP-4 depends on this, the attacker could break resource conservation or derived consistency through the SIR layer. |
| **Classification** | Closeable by test |
| **Rust counterpart** | SIR state construction + `invariants/src/global.rs` |

#### A-23: `r01_sir_complete` (R01-5) — RESIDUAL

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `exists (s_sir : SIRState) (sigma_sir : SIRInput), SIR_to_Formal_State s_sir = s /\ SIR_to_Formal_Input sigma_sir = sigma` |
| **Rust assumption** | Every formal (state, input) pair has a corresponding SIR (state, input) pair that maps to it. The SIR representation is complete. |
| **Adversarial exploit** | Some formal states have no SIR representation. The constraint system cannot express constraints for these states, creating a gap where transitions involving unreachable states are unconstrained. |
| **Classification** | **Residual trust assumption** |
| **Rust counterpart** | `vsel-sir/src/types.rs` (SIR type definitions) |

#### A-24: `tp6_resource_conservation` (TP-6) — CRITICAL

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `ValidState s -> L_cons s sigma (Apply s sigma)` |
| **Rust assumption** | For every valid state and any input, the transition preserves resource conservation (sum of balances equals total_supply). |
| **Adversarial exploit** | An attacker finds a transition that creates or destroys resources. Enables minting tokens from nothing or burning tokens without authorization. |
| **Classification** | Closeable by test |
| **Rust counterpart** | Balance manipulation in `transition.rs::apply()` |
| **Risk level** | **CRITICAL** — Direct economic impact |

---

### Layer 3: Refinement R12 — SIR to Concrete (SIRToConcrete.lean)

#### A-25: `r12_encoding_injectivity` (R12-5 / TP-11)

| Field | Value |
|---|---|
| **File** | `Refinement/SIRToConcrete.lean` |
| **Statement** | `Encode s1 = Encode s2 -> s1 = s2` |
| **Rust assumption** | The Rust state encoding function (deterministic serialization) is injective — two distinct states never produce the same byte encoding. |
| **Adversarial exploit** | Two different states produce the same encoding (a collision). An attacker presents a proof for state A while the system is actually in state B (same encoding). Enables state substitution attacks. |
| **Classification** | Closeable by test |
| **Rust counterpart** | State serialization in `state.rs` or `canonicalization.rs` |
| **Risk level** | **HIGH** — Encoding collisions enable state substitution |

**Note**: The `r12_observable_commutativity` and `r12_execution_commutativity` theorems in `SIRToConcrete.lean` are not new axioms — they delegate to `thm2_observable_commutativity` (A-18) and `thm1_execution_commutativity` (A-10) respectively.

---

### Layer 4: Refinement R23 — Concrete to Constraint (ConcreteToConstraint.lean)

#### A-26: `lem4_constraint_soundness` (LEM-4) — CRITICAL

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `SatisfiesConstraints tau cs -> ValidTraceR23 tau` |
| **Rust assumption** | If a trace satisfies all constraints in the compiled constraint system, then the trace is semantically valid. No invalid execution can satisfy the constraints. |
| **Adversarial exploit** | An attacker constructs an invalid trace (e.g., one that creates resources from nothing) that nonetheless satisfies all constraints. The proof system accepts the invalid trace. This is a **soundness break** — the most catastrophic failure mode for a ZK proof system. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `vsel-constraints/src/compiler.rs` + `vsel-constraints/src/coverage.rs` |
| **Risk level** | **CRITICAL** — Soundness break means the proof system provides no security guarantees |

#### A-27: `lem5_constraint_completeness` (LEM-5)

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `ValidTraceR23 tau -> SatisfiesConstraints tau cs` |
| **Rust assumption** | If a trace is semantically valid, then it satisfies all constraints. All valid executions are representable in the constraint system. |
| **Adversarial exploit** | A valid trace fails constraint checking. This is a **completeness break** — the proof system rejects valid executions. Causes denial of service: legitimate users cannot generate proofs for valid transactions. |
| **Classification** | Closeable by test |
| **Rust counterpart** | `vsel-constraints/src/compiler.rs` |
| **Risk level** | HIGH — Completeness breaks cause denial of service |

#### A-28: `const1_zero_unconstrained` (CONST-1)

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `AllVariablesConstrained cs` |
| **Rust assumption** | Every witness variable in the compiled constraint system is referenced by at least one constraint. |
| **Adversarial exploit** | An unconstrained witness variable can be set to any value by the prover without affecting constraint satisfaction. An attacker sets the unconstrained variable to a value that changes the semantic meaning of the trace. Classic underconstraint vulnerability. |
| **Classification** | Closeable by static analysis |
| **Rust counterpart** | `vsel-constraints/src/underconstraint.rs` |

#### A-29: `const2_no_unused_inputs` (CONST-2)

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `NoUnusedWitnessInputs cs` |
| **Rust assumption** | Every witness input influences at least one constraint output. |
| **Adversarial exploit** | An unused witness input means some aspect of the execution trace is not verified by the constraint system. An attacker modifies the unused input's corresponding trace data without detection. |
| **Classification** | Closeable by static analysis |
| **Rust counterpart** | `vsel-constraints/src/underconstraint.rs` |

#### A-30: `const3_branch_completeness` (CONST-3)

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `BranchComplete cs` |
| **Rust assumption** | For every conditional in the SIR/IR program, both branches (true and false) generate constraints. |
| **Adversarial exploit** | A missing branch means one execution path is unconstrained. An attacker triggers the unconstrained branch and provides arbitrary witness values, enabling state manipulation through the unconstrained path. |
| **Classification** | Closeable by static analysis |
| **Rust counterpart** | `vsel-constraints/src/compiler.rs` + `vsel-constraints/src/coverage.rs` |

---

### Layer 5: Inhabited Axioms (Proof Infrastructure)

#### A-31: `SIRState.inhabited`

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `Inhabited SIRState` |
| **Rust assumption** | The SIR state type has a default/zero value. Lean 4 technical requirement for opaque types. |
| **Adversarial exploit** | None — proof infrastructure axiom with no runtime behavior. |
| **Classification** | **Residual trust assumption** |

#### A-32: `SIRInput.inhabited`

| Field | Value |
|---|---|
| **File** | `Refinement/FormalToSIR.lean` |
| **Statement** | `Inhabited SIRInput` |
| **Rust assumption** | Same as A-31 but for the SIR input type. |
| **Adversarial exploit** | None — proof infrastructure axiom. |
| **Classification** | **Residual trust assumption** |

#### A-33: `ConstraintSystemR23.inhabited`

| Field | Value |
|---|---|
| **File** | `Refinement/ConcreteToConstraint.lean` |
| **Statement** | `Inhabited ConstraintSystemR23` |
| **Rust assumption** | The constraint system type has a default value. |
| **Adversarial exploit** | None — proof infrastructure axiom. |
| **Classification** | **Residual trust assumption** |

---

## 3. Complete Opaque Type and Function Catalog

Every `opaque` declaration represents a point where Lean 4 cannot reason about the implementation — it trusts that the Rust code satisfies the stated axioms. Each opaque entity is a potential semantic gap.

### Opaque Types

| ID | Opaque Type | File | Rust Counterpart | Purpose | Structural Notes |
|---|---|---|---|---|---|
| OT-1 | `SIRState` | `FormalToSIR.lean` | `vsel-sir/src/types.rs::SirState` | SIR-level state representation | Contains all formal `State` fields plus SIR-specific metadata (instruction pointers, stack frames). Formal types are a projection. |
| OT-2 | `SIRInput` | `FormalToSIR.lean` | `vsel-sir/src/types.rs::SirInput` | SIR-level input representation | Contains all formal `Input` fields plus SIR execution context. |
| OT-3 | `ConstraintSystemR23` | `ConcreteToConstraint.lean` | `vsel-constraints/src/compiler.rs::ConstraintSystem` | Compiled constraint system | Rust type contains constraint expressions, variable declarations, metadata. Lean type is purely abstract. |
| OT-4 | `TraceR23` | `ConcreteToConstraint.lean` | `vsel-trace/src/engine.rs::ExecutionTrace` | Execution trace for constraint checking | Rust type contains (pre-state, input, post-state) triples with witness data. Lean type is purely abstract. |
| OT-5 | `SIRProgramR23` | `ConcreteToConstraint.lean` | `vsel-sir/src/types.rs::SirProgram` | SIR program for constraint compilation | Rust type contains instruction sequence, type declarations, entry points. |

### Opaque Functions — Foundations Layer

| ID | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-1 | `Derive` | `State.lean` | `CanonicalState -> DerivedState` | `state.rs::derive()` — computes state root and aggregates |
| OF-2 | `DeriveEconomic` | `State.lean` | `CanonicalState -> Environment -> EconomicContext` | `state.rs::derive_economic()` — computes economic context |
| OF-3 | `EconomicallyValid` | `State.lean` | `State -> Prop` | `economic.rs::is_economically_valid()` |
| OF-4 | `Classify` | `Transition.lean` | `State -> Input -> TransitionClass` | `transition.rs::classify()` — guard evaluation |
| OF-5 | `Apply` | `Transition.lean` | `State -> Input -> State` | `transition.rs::apply()` — state transition |
| OF-6 | `Obs` | `Transition.lean` | `State -> Input -> State -> Observable` | `transition.rs::observe()` — externally visible outputs |

### Opaque Functions — Mapping Layer

| ID | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-7 | `mu_S` | `SemanticMapping.lean` | `State -> FormalState` | `mapping.rs::map_state()` |
| OF-8 | `mu_Sigma` | `SemanticMapping.lean` | `Input -> FormalInput` | `mapping.rs::map_input()` |
| OF-9 | `mu_O` | `SemanticMapping.lean` | `Observable -> FormalObservable` | `mapping.rs::map_observable()` |
| OF-10 | `Apply_f` | `SemanticMapping.lean` | `FormalState -> FormalInput -> FormalState` | SIR-level transition function (reference) |
| OF-11 | `Obs_f` | `SemanticMapping.lean` | `FormalState -> FormalInput -> FormalState -> FormalObservable` | SIR-level observable function |
| OF-12 | `Derive_f` | `SemanticMapping.lean` | `FormalState -> FormalState` | SIR-level derived state computation |
| OF-13 | `Canonicalize_Input` | `SemanticMapping.lean` | `Input -> Input` | `canonicalization.rs::canonicalize_input()` |
| OF-14 | `Canonicalize_State` | `SemanticMapping.lean` | `State -> State` | `canonicalization.rs::canonicalize_state()` |
| OF-15 | `mu_C` | `Commutativity.lean` | `CanonicalState -> FormalState` | `mapping.rs` — canonical state mapping |
| OF-16 | `mu_D` | `Commutativity.lean` | `DerivedState -> FormalState` | `mapping.rs` — derived state mapping |

### Opaque Functions — Refinement Layer

| ID | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-17 | `SIRTransition` | `FormalToSIR.lean` | `SIRState -> SIRInput -> SIRState` | `vsel-sir/src/interpreter.rs::execute()` |
| OF-18 | `SIR_to_Formal_State` | `FormalToSIR.lean` | `SIRState -> State` | `vsel-sir/src/types.rs` — formal state extraction |
| OF-19 | `SIR_to_Formal_Input` | `FormalToSIR.lean` | `SIRInput -> Input` | `vsel-sir/src/types.rs` — formal input extraction |
| OF-20 | `Encode` | `SIRToConcrete.lean` | `State -> List UInt8` | `state.rs` or `canonicalization.rs` — deterministic serialization |
| OF-21 | `SatisfiesConstraints` | `ConcreteToConstraint.lean` | `TraceR23 -> ConstraintSystemR23 -> Prop` | `vsel-constraints/src/compiler.rs::evaluate()` |
| OF-22 | `ValidTraceR23` | `ConcreteToConstraint.lean` | `TraceR23 -> Prop` | Trace validity check (all transitions valid, all invariants hold) |
| OF-23 | `AllVariablesConstrained` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/underconstraint.rs::check_all_constrained()` |
| OF-24 | `NoUnusedWitnessInputs` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/underconstraint.rs::check_no_unused()` |
| OF-25 | `BranchComplete` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/coverage.rs::check_branch_complete()` |
| OF-26 | `Compile` | `ConcreteToConstraint.lean` | `SIRProgramR23 -> ConstraintSystemR23` | `vsel-constraints/src/compiler.rs::compile()` |

---

## 4. Axiom Classification Summary

### Classification Statistics

| Classification | Count | Axiom IDs |
|---|---|---|
| Closed by theorem | 1 (was axiom, now theorem) | A-4 |
| Closeable by test | 17 | A-1, A-2, A-3, A-5, A-6, A-7, A-8, A-9, A-11, A-13, A-14, A-17, A-19, A-20, A-22, A-24, A-25 |
| Closeable by differential test | 6 | A-10, A-12, A-15, A-16, A-18, A-21 |
| Closeable by static analysis | 3 | A-28, A-29, A-30 |
| Residual trust assumption | 4 | A-23, A-31, A-32, A-33 |
| **Total axioms remaining** | **32** | (A-4 eliminated by theorem derivation) |

### Consolidated Classification Table

| ID | Axiom | File | Classification | Risk Level |
|---|---|---|---|---|
| A-1 | `apply_closure` (AX-2) | Transition.lean | Closeable by test | High |
| A-2 | `initial_state_valid` (AX-3) | Transition.lean | Closeable by test | High |
| A-3 | `error_preserves_invariants` (LEM-7) | Transition.lean | Closeable by test | High |
| A-4 | `state_validity_inductive_step` (PO-SV) | Invariants.lean | **Closed by theorem** (derived from A-1) | High |
| A-5 | `resource_conservation_inductive_step` (PO-RC) | Invariants.lean | Closeable by test | Critical |
| A-6 | `derived_consistency_inductive_step` (PO-DC) | Invariants.lean | Closeable by test | High |
| A-7 | `monotonic_metadata_inductive_step` (PO-MM) | Invariants.lean | Closeable by test | High |
| A-8 | `environment_consistency_inductive_step` (PO-ENV) | Invariants.lean | Closeable by test | Medium |
| A-9 | `guard_exhaustiveness` | Invariants.lean | Closeable by test | Medium |
| A-10 | `thm1_execution_commutativity` (THM-1) | Commutativity.lean | Closeable by differential test | **Critical** |
| A-11 | `thm4_auxiliary_independence` (THM-4) | Commutativity.lean | Closeable by test | High |
| A-12 | `thm5_derived_commutativity` (THM-5) | Commutativity.lean | Closeable by differential test | High |
| A-13 | `tp7_input_canonicalization_idempotent` (TP-7a) | Commutativity.lean | Closeable by test | Medium |
| A-14 | `tp7_state_canonicalization_idempotent` (TP-7b) | Commutativity.lean | Closeable by test | Medium |
| A-15 | `tp8_input_canonicalization_preserves_semantics` (TP-8a) | Commutativity.lean | Closeable by differential test | High |
| A-16 | `tp8_state_canonicalization_preserves_semantics` (TP-8b) | Commutativity.lean | Closeable by differential test | High |
| A-17 | `canon_clears_aux` | Commutativity.lean | Closeable by test | Medium |
| A-18 | `thm2_observable_commutativity` (THM-2) | Observable.lean | Closeable by differential test | High |
| A-19 | `mu_Sigma_ignores_aux` | Observable.lean | Closeable by test | Medium |
| A-20 | `r01_state_validity` (R01-1) | FormalToSIR.lean | Closeable by test | High |
| A-21 | `r01_transition_correspondence` (R01-2) | FormalToSIR.lean | Closeable by differential test | **Critical** |
| A-22 | `r01_invariant_correspondence` (R01-3) | FormalToSIR.lean | Closeable by test | High |
| A-23 | `r01_sir_complete` (R01-5) | FormalToSIR.lean | **Residual trust assumption** | Low |
| A-24 | `tp6_resource_conservation` (TP-6) | FormalToSIR.lean | Closeable by test | **Critical** |
| A-25 | `r12_encoding_injectivity` (R12-5) | SIRToConcrete.lean | Closeable by test | High |
| A-26 | `lem4_constraint_soundness` (LEM-4) | ConcreteToConstraint.lean | Closeable by test | **Critical** |
| A-27 | `lem5_constraint_completeness` (LEM-5) | ConcreteToConstraint.lean | Closeable by test | High |
| A-28 | `const1_zero_unconstrained` (CONST-1) | ConcreteToConstraint.lean | Closeable by static analysis | High |
| A-29 | `const2_no_unused_inputs` (CONST-2) | ConcreteToConstraint.lean | Closeable by static analysis | High |
| A-30 | `const3_branch_completeness` (CONST-3) | ConcreteToConstraint.lean | Closeable by static analysis | High |
| A-31 | `SIRState.inhabited` | FormalToSIR.lean | **Residual trust assumption** | Negligible |
| A-32 | `SIRInput.inhabited` | FormalToSIR.lean | **Residual trust assumption** | Negligible |
| A-33 | `ConstraintSystemR23.inhabited` | ConcreteToConstraint.lean | **Residual trust assumption** | Negligible |

---

## 5. Gap-Closing Methodology

### 5.1 Axioms Closeable by Theorem (1 axiom — COMPLETED)

**Target**: A-4 (`state_validity_inductive_step`) — **CLOSED**

**Method**: Replaced the axiom declaration with a theorem referencing `apply_closure` (A-1), since they are logically identical. In Lean 4:

```lean
-- Before (axiom — 33 total axioms):
axiom state_validity_inductive_step (s : State) (sigma : Input) :
  ValidState s -> ValidState (Apply s sigma)

-- After (theorem referencing A-1 — 32 total axioms):
theorem state_validity_inductive_step (s : State) (sigma : Input) :
  ValidState s -> ValidState (Apply s sigma) :=
  apply_closure s sigma
```

**Impact**: Reduced total axiom count from 33 to 32. Eliminated one redundant trust assumption. All downstream proofs (`state_validity_preserved`, `invariant_preservation`, `state_validity_after_n_transitions`, `global_invariants_after_n_transitions`) continue to compile because the theorem has the same name and type signature as the former axiom.

**Status**: ✅ Complete — implemented in `formal/VSEL/Foundations/Invariants.lean`

---

### 5.2 Axioms Closeable by Test (17 axioms)

**Targets**: A-1, A-2, A-3, A-5, A-6, A-7, A-8, A-9, A-11, A-13, A-14, A-17, A-19, A-20, A-22, A-24, A-25

**Method**: Generate Rust property-based tests using `proptest` that:

1. Generate random valid states and inputs using smart generators constrained to the valid input space
2. Execute the operation under test
3. Verify the axiom's postcondition holds

**Configuration**:
- Minimum 10,000 iterations per axiom
- Tests located in `protocol/tests/property/semantic_gap_tests.rs`
- Generator strategies constrain to structurally valid inputs (valid balances, non-zero domains, monotonic metadata)

**Test mapping**:

| Axiom | Test Strategy |
|---|---|
| A-1 (apply_closure) | Random valid state + random input -> verify `is_valid(post_state)` |
| A-2 (initial_state_valid) | Construct genesis state -> verify all validity predicates |
| A-3 (error_preserves_invariants) | Random valid state + invalid input (empty sigs, empty payload, zero domain) -> verify `is_valid(post_state)` |
| A-5 (resource_conservation) | Random valid state + random input -> verify `sum(balances) == total_supply` in post-state |
| A-6 (derived_consistency) | Random valid state + random input -> verify `post.derived == Derive(post.canonical)` |
| A-7 (metadata_monotonicity) | Random valid state + random input -> verify metadata monotonicity in post-state |
| A-8 (environment_consistency) | Random valid state + random input -> verify `post.environment.domain.hash != zero_hash` |
| A-9 (guard_exhaustiveness) | Random (state, input) pairs -> verify `classify()` returns valid `TransitionClass` without panic |
| A-11 (auxiliary_independence) | Random state + two inputs differing only in `aux` -> verify identical post-states |
| A-13 (input_canon_idempotent) | Random input -> verify `canonicalize(canonicalize(input)) == canonicalize(input)` |
| A-14 (state_canon_idempotent) | Random state -> verify `canonicalize(canonicalize(state)) == canonicalize(state)` |
| A-17 (canon_clears_aux) | Two inputs differing only in `aux` -> verify identical canonical forms |
| A-19 (mu_Sigma_ignores_aux) | Two inputs differing only in `aux` -> verify identical `map_input()` results |
| A-20 (r01_state_validity) | Random SIR state -> map to formal -> verify all validity predicates |
| A-22 (r01_invariant_correspondence) | Random SIR state -> map to formal -> verify all global invariants |
| A-24 (resource_conservation) | Random valid state + random input -> verify `L_cons` holds |
| A-25 (encoding_injectivity) | Pairs of distinct random states -> verify distinct encodings |

---

### 5.3 Axioms Closeable by Differential Test (6 axioms)

**Targets**: A-10, A-12, A-15, A-16, A-18, A-21

**Method**: Generate Rust tests that:

1. Generate random (state, input) pairs
2. Execute the operation in Rust
3. Map the result through the semantic mapping functions
4. Compare against the formal-side computation (implemented as a Rust reference oracle)
5. Verify equality

**Configuration**:
- Minimum 1,000 iterations per axiom (per design document Property 10)
- Tests located in `protocol/tests/property/semantic_gap_tests.rs`
- Requires Rust implementations of formal-side functions (`Apply_f`, `Obs_f`, `Derive_f`) or a reference oracle

**Test mapping**:

| Axiom | Test Strategy |
|---|---|
| A-10 (execution_commutativity) | Random (state, input) -> verify `map_state(apply(s, sigma)) == apply_f(map_state(s), map_input(sigma))` |
| A-12 (derived_commutativity) | Random canonical state -> verify `map_derived(derive(c)) == derive_f(map_canonical(c))` |
| A-15 (input_canon_preserves_semantics) | Random input -> verify `map_input(canonicalize(sigma)) == map_input(sigma)` |
| A-16 (state_canon_preserves_semantics) | Random state -> verify `map_state(canonicalize(s)) == map_state(s)` |
| A-18 (observable_commutativity) | Random (state, input, post-state) -> verify `map_obs(obs(s, sigma, s')) == obs_f(map_state(s), map_input(sigma), map_state(s'))` |
| A-21 (transition_correspondence) | Random SIR (state, input) -> verify `sir_to_formal(sir_transition(s, sigma)) == apply(sir_to_formal_state(s), sir_to_formal_input(sigma))` |

---

### 5.4 Axioms Closeable by Static Analysis (3 axioms)

**Targets**: A-28, A-29, A-30

**Method**: Instrument the constraint compiler to perform compile-time checks:

| Axiom | Static Analysis Check |
|---|---|
| A-28 (zero_unconstrained) | After compilation, verify every declared witness variable appears in at least one constraint expression |
| A-29 (no_unused_inputs) | After compilation, verify every input variable has a data-flow path to at least one constraint |
| A-30 (branch_completeness) | After compilation, verify every `IfThenElse` node in the SIR generated constraints for both `then` and `else` branches |

**Implementation**: These checks run as part of the constraint compilation pipeline and are verified by existing tests in:
- `vsel-constraints/src/underconstraint.rs` (A-28, A-29)
- `vsel-constraints/src/coverage.rs` (A-30)

---

### 5.5 Residual Trust Assumptions (4 axioms)

**Targets**: A-23, A-31, A-32, A-33

These axioms cannot be mechanically closed. Full analysis is provided in Section 6.

---

## 6. Residual Trust Assumptions

### 6.1 A-23: `r01_sir_complete` — SIR Completeness

| Field | Detail |
|---|---|
| **Axiom** | Every formal (state, input) pair has a corresponding SIR (state, input) pair that maps to it. |
| **Formal statement** | `exists (s_sir : SIRState) (sigma_sir : SIRInput), SIR_to_Formal_State s_sir = s /\ SIR_to_Formal_Input sigma_sir = sigma` |
| **Why it cannot be closed** | This is a universal quantifier over an infinite domain (all possible formal states and inputs). No finite test suite can verify completeness. A Lean 4 theorem would require constructing the inverse mapping, which is not possible when `SIRState` is opaque. |
| **Risk if violated** | Some formal states have no SIR representation. Constraints compiled from SIR cannot cover these states, creating verification gaps where transitions involving unreachable states are unconstrained. An attacker could exploit the gap by constructing a formal state that has no SIR counterpart, then crafting a proof that the constraint system cannot validate or invalidate. |
| **Mitigating evidence** | (1) SIR types are generated from the same schema as formal types — structural correspondence ensures every formal field has a SIR counterpart. (2) SIR serialization/deserialization round-trip tests cover all formal state constructors. (3) Code review confirms no formal state variants are missing from SIR type definitions. (4) Property tests verify that randomly generated formal states can be round-tripped through SIR encoding/decoding. |
| **Residual risk** | **LOW** — The structural correspondence argument is strong, and round-trip testing provides high confidence. The SIR is a superset of the formal types (it adds metadata, not removes fields). |

### 6.2 A-31: `SIRState.inhabited` — SIR State Inhabitedness

| Field | Detail |
|---|---|
| **Axiom** | The `SIRState` type has at least one value (is inhabited). |
| **Formal statement** | `Inhabited SIRState` |
| **Why it cannot be closed** | `SIRState` is an opaque type in Lean 4. Lean cannot construct a value of an opaque type, so it cannot prove inhabitedness. The axiom is a Lean 4 technical requirement for using opaque types in certain proof contexts (e.g., `Classical.choice`, `Decidable` instances). |
| **Risk if violated** | **None at runtime.** This axiom is only used by Lean 4 proof tactics. If violated, certain proofs would fail to compile, but no runtime behavior is affected. There is no adversarial exploitation path. |
| **Mitigating evidence** | (1) The corresponding Rust type `SirState` derives `Default`, confirming at least one value exists. (2) The axiom is trivially satisfiable — any type with at least one constructor is inhabited, and Rust structs always have at least one value (the default). |
| **Residual risk** | **NEGLIGIBLE** — Proof infrastructure axiom with zero security implications. |

### 6.3 A-32: `SIRInput.inhabited` — SIR Input Inhabitedness

| Field | Detail |
|---|---|
| **Axiom** | The `SIRInput` type has at least one value (is inhabited). |
| **Formal statement** | `Inhabited SIRInput` |
| **Why it cannot be closed** | Same reasoning as A-31 — opaque type in Lean 4. |
| **Risk if violated** | **None at runtime.** Same as A-31. |
| **Mitigating evidence** | (1) The corresponding Rust type `SirInput` derives `Default`. (2) Trivially satisfiable. |
| **Residual risk** | **NEGLIGIBLE** — Proof infrastructure axiom with zero security implications. |

### 6.4 A-33: `ConstraintSystemR23.inhabited` — Constraint System Inhabitedness

| Field | Detail |
|---|---|
| **Axiom** | The `ConstraintSystemR23` type has at least one value (is inhabited). |
| **Formal statement** | `Inhabited ConstraintSystemR23` |
| **Why it cannot be closed** | Same reasoning as A-31 — opaque type in Lean 4. |
| **Risk if violated** | **None at runtime.** Same as A-31. |
| **Mitigating evidence** | (1) The corresponding Rust type `ConstraintSystem` derives `Default`. (2) Trivially satisfiable. |
| **Residual risk** | **NEGLIGIBLE** — Proof infrastructure axiom with zero security implications. |

### Residual Trust Summary

| ID | Axiom | Risk Level | Runtime Impact | Mitigating Strength |
|---|---|---|---|---|
| A-23 | SIR Completeness | Low | Potential verification gap | Strong (structural correspondence + round-trip tests) |
| A-31 | SIRState inhabited | Negligible | None | Trivial (Rust `Default` derive) |
| A-32 | SIRInput inhabited | Negligible | None | Trivial (Rust `Default` derive) |
| A-33 | ConstraintSystemR23 inhabited | Negligible | None | Trivial (Rust `Default` derive) |

**Total residual risk**: 1 axiom with low risk (A-23) and 3 axioms with negligible risk (A-31, A-32, A-33). The 3 negligible-risk axioms are proof infrastructure with zero runtime security implications. The single low-risk axiom (SIR completeness) is mitigated by strong structural correspondence evidence.

---

## 7. Critical Attack Surface Analysis

### Highest-Risk Axioms (ordered by adversarial impact)

#### Rank 1: A-26 — `lem4_constraint_soundness` (Constraint Soundness)

**Impact**: A soundness break means invalid traces are accepted as valid. This is the single most dangerous axiom because it directly controls whether the proof system provides any security guarantees at all. If an attacker can construct an invalid trace that satisfies all constraints, they can forge proofs for arbitrary state transitions — including resource creation from nothing, unauthorized transfers, and state rollback.

**Attack vector**: Construct a trace where one transition violates resource conservation (creates tokens) but the constraint system does not detect the violation because the relevant constraint is missing or incorrectly formulated.

**Gap-closing**: Property 9 (soundness direction) — generate random invalid traces with known invariant violations and verify they fail at least one constraint.

#### Rank 2: A-10 — `thm1_execution_commutativity` (Execution Commutativity)

**Impact**: If concrete Rust execution diverges from the formal specification, the entire refinement chain is meaningless. Proofs verify formal semantics, but the system executes Rust code. Any divergence means proofs do not correspond to reality. An attacker who discovers a divergence can exploit the gap between what the proof verifies and what the system actually does.

**Attack vector**: Find an (state, input) pair where the Rust `Apply` function produces a different post-state than the formal `Apply_f`. Use this divergence to construct a proof that verifies against the formal semantics but corresponds to a different (attacker-favorable) concrete execution.

**Gap-closing**: Property 10 (differential Apply consistency) — generate 1,000+ random (state, input) pairs and verify Rust and formal semantics agree.

#### Rank 3: A-21 — `r01_transition_correspondence` (SIR Transition Correspondence)

**Impact**: The SIR-level analog of THM-1. If the SIR interpreter diverges from the formal spec, constraints compiled from SIR verify a different computation than what the formal spec defines. This is particularly dangerous because the SIR is the compilation target — all constraint systems are derived from SIR execution.

**Attack vector**: Find an SIR (state, input) pair where the SIR interpreter produces a different result than `Apply` on the mapped inputs. Exploit the divergence to generate a valid-looking proof for an invalid SIR execution.

**Gap-closing**: Differential test — generate random SIR (state, input) pairs, execute the SIR transition, map the result, and compare against `Apply` on the mapped inputs.

#### Rank 4: A-24 — `tp6_resource_conservation` (Resource Conservation)

**Impact**: Direct economic impact. A violation enables minting tokens from nothing or burning tokens without authorization. This is the most economically devastating attack vector because it directly affects the value stored in the system.

**Attack vector**: Find a transition that increases the attacker's balance without a corresponding decrease elsewhere. The total supply invariant is violated, but if the constraint system does not check this (see A-26), the proof system accepts the invalid transition.

**Gap-closing**: Property tests generate random valid states and inputs, apply the transition, and verify `sum(balances) == total_supply` in the post-state.

#### Rank 5: A-25 — `r12_encoding_injectivity` (Encoding Injectivity)

**Impact**: Encoding collisions enable state substitution attacks. If two different states produce the same encoding, an attacker can present a proof for state A while the system is actually in state B. The proof verifies against the encoding, but the actual state is different.

**Attack vector**: Find two distinct states `s1 != s2` where `Encode(s1) == Encode(s2)`. Present a proof for `s1` (which has favorable balances) while the system is in `s2` (which has the attacker's actual balances).

**Gap-closing**: Property tests generate pairs of distinct random states, encode both, and verify the encodings differ. Structural analysis of the encoding format (deterministic serialization with length prefixes) provides additional confidence.

---

## 8. Dependency Chain Diagram

The axioms form a trust chain where downstream axioms depend on upstream ones. A violation at any layer invalidates all downstream layers.

```
                    TRUST CHAIN ARCHITECTURE
                    ========================

    ┌─────────────────────────────────────────────────────┐
    │              Layer 0: FOUNDATIONS                     │
    │                                                      │
    │  AX-2 (apply_closure)          AX-3 (initial_valid) │
    │  LEM-7 (error_preserves)                             │
    │  PO-SV, PO-RC, PO-DC, PO-MM, PO-ENV                │
    │  guard_exhaustiveness                                │
    │                                                      │
    │  9 axioms — ALL downstream layers depend on these    │
    └──────────────────────┬──────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │              Layer 1: MAPPING                         │
    │                                                      │
    │  THM-1 (execution_commutativity)     ◄── CRITICAL   │
    │  THM-2 (observable_commutativity)                    │
    │  THM-4 (auxiliary_independence)                      │
    │  THM-5 (derived_commutativity)                      │
    │  TP-7a/b (canonicalization_idempotent)               │
    │  TP-8a/b (canonicalization_preserves_semantics)      │
    │  canon_clears_aux, mu_Sigma_ignores_aux             │
    │                                                      │
    │  10 axioms — Bridge concrete to formal               │
    └──────────────────────┬──────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │         Layer 2: R01 (Formal → SIR)                  │
    │                                                      │
    │  R01-1 (state_validity)                              │
    │  R01-2 (transition_correspondence) ◄── CRITICAL     │
    │  R01-3 (invariant_correspondence)                    │
    │  R01-5 (sir_complete)              ◄── RESIDUAL     │
    │  TP-6  (resource_conservation)     ◄── CRITICAL     │
    │                                                      │
    │  5 axioms + 3 inhabited axioms                       │
    └──────────────────────┬──────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │         Layer 3: R12 (SIR → Concrete)                │
    │                                                      │
    │  R12-5 (encoding_injectivity)      ◄── HIGH RISK   │
    │                                                      │
    │  1 axiom (others are theorem references)             │
    └──────────────────────┬──────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────┐
    │      Layer 4: R23 (Concrete → Constraint)            │
    │                                                      │
    │  LEM-4 (constraint_soundness)      ◄── CRITICAL    │
    │  LEM-5 (constraint_completeness)                     │
    │  CONST-1 (zero_unconstrained)                        │
    │  CONST-2 (no_unused_inputs)                          │
    │  CONST-3 (branch_completeness)                       │
    │                                                      │
    │  5 axioms — Final link to ZK proofs                  │
    └─────────────────────────────────────────────────────┘
```

### Cascade Analysis

If a Foundation Layer axiom (e.g., A-1 `apply_closure`) is violated:
- All 10 Mapping Layer axioms become unreliable (they assume valid states)
- All 8 R01 axioms become unreliable (they depend on valid state transitions)
- R12 encoding injectivity may still hold (independent of state validity)
- R23 constraint soundness/completeness become unreliable (constraints assume valid transitions)
- **Result**: Complete refinement chain collapse

If a Mapping Layer axiom (e.g., A-10 `execution_commutativity`) is violated:
- R01 transition correspondence (A-21) becomes unreliable (it depends on THM-1)
- R12 execution commutativity theorem becomes invalid (it delegates to THM-1)
- R23 constraints may verify the wrong computation
- **Result**: Proofs verify formal semantics but concrete execution diverges

If a Constraint Layer axiom (e.g., A-26 `constraint_soundness`) is violated:
- The proof system accepts invalid traces
- All upstream layers remain valid (the formal spec is correct)
- **Result**: Soundness break — proofs provide no security guarantees

---

## 9. Requirements Traceability

### Requirement 8.1: Axiom and Opaque Type Catalog

| Acceptance Criterion | Status | Evidence |
|---|---|---|
| Catalog every axiom in the refinement chain | **Complete** | 33 axioms cataloged in Section 2 (32 remain after A-4 closed by theorem) |
| Include axiom statement | **Complete** | Formal Lean 4 statement for each axiom |
| Include Rust implementation assumption | **Complete** | Documented for each axiom |
| Include adversarial exploitation analysis | **Complete** | Documented for each axiom |
| Include verification method classification | **Complete** | 5 classifications applied to all 33 axioms (1 now closed by theorem) |

### Requirement 8.2: Opaque Type Boundary Catalog

| Acceptance Criterion | Status | Evidence |
|---|---|---|
| Identify every opaque type boundary | **Complete** | 5 opaque types cataloged in Section 3 |
| Document Rust counterpart | **Complete** | Rust file and type name for each |
| Document structural correspondence | **Complete** | Field-level correspondence notes for each type |
| Catalog opaque functions | **Complete** | 26 opaque functions cataloged in Section 3 |

### Requirement 8.5: Residual Trust Assumptions

| Acceptance Criterion | Status | Evidence |
|---|---|---|
| Document each residual axiom | **Complete** | 4 residual axioms in Section 6 |
| Explain why it cannot be closed | **Complete** | Detailed reasoning for each |
| Assess risk if violated | **Complete** | Risk level and attack scenario for each |
| Provide mitigating evidence | **Complete** | Multiple evidence items per axiom |

### Cross-Reference to Other Requirements

| Requirement | Relevant Sections | Status |
|---|---|---|
| 8.3 (Property tests for axiom behavior) | Section 5.2, 5.3 — test strategies defined | Tests implemented in task 7.3 |
| 8.4 (Differential Apply tests) | Section 5.3 — A-10, A-21 test strategies | Tests implemented in task 7.4 |
| 8.6 (Lean 4 theorem strengthening) | Section 5.1 — A-4 elimination | **Complete** — A-4 replaced with theorem in `Invariants.lean` |
| 8.7 (Critical finding remediation) | Section 7 — attack surface analysis | Monitoring via gap-closing tests |

---

## Appendix A: Source Files Analyzed

| File | Layer | Axioms | Opaque Types | Opaque Functions |
|---|---|---|---|---|
| `formal/VSEL/Foundations/Transition.lean` | 0 | 3 (AX-2, AX-3, LEM-7) | 0 | 3 (Classify, Apply, Obs) |
| `formal/VSEL/Foundations/Invariants.lean` | 0 | 5 (PO-RC, PO-DC, PO-MM, PO-ENV, guard_exhaustiveness) + 1 theorem (PO-SV, derived from AX-2) | 0 | 0 |
| `formal/VSEL/Foundations/State.lean` | 0 | 0 | 0 | 3 (Derive, DeriveEconomic, EconomicallyValid) |
| `formal/VSEL/Mapping/Commutativity.lean` | 1 | 8 (THM-1, THM-4, THM-5, TP-7a/b, TP-8a/b, canon_clears_aux) | 0 | 2 (mu_C, mu_D) |
| `formal/VSEL/Mapping/Observable.lean` | 1 | 2 (THM-2, mu_Sigma_ignores_aux) | 0 | 0 |
| `formal/VSEL/Mapping/SemanticMapping.lean` | 1 | 0 | 0 | 8 (mu_S, mu_Sigma, mu_O, Apply_f, Obs_f, Derive_f, Canonicalize_Input, Canonicalize_State) |
| `formal/VSEL/Refinement/FormalToSIR.lean` | 2 | 8 (R01-1..R01-5, TP-6, SIRState.inhabited, SIRInput.inhabited) | 2 (SIRState, SIRInput) | 3 (SIRTransition, SIR_to_Formal_State, SIR_to_Formal_Input) |
| `formal/VSEL/Refinement/SIRToConcrete.lean` | 3 | 1 (R12-5) | 0 | 1 (Encode) |
| `formal/VSEL/Refinement/ConcreteToConstraint.lean` | 4 | 6 (LEM-4, LEM-5, CONST-1..3, ConstraintSystemR23.inhabited) | 3 (ConstraintSystemR23, TraceR23, SIRProgramR23) | 6 (SatisfiesConstraints, ValidTraceR23, AllVariablesConstrained, NoUnusedWitnessInputs, BranchComplete, Compile) |
| **Total** | | **32 axioms** (1 closed by theorem) | **5 opaque types** | **26 opaque functions** |

---

## Appendix B: Glossary

| Term | Definition |
|---|---|
| **Axiom** | An unproven assumption in Lean 4. Every axiom is a trust assumption that an auditor will attack. |
| **Opaque type** | A Lean 4 type whose internal structure is hidden. Lean cannot reason about its fields or constructors. |
| **Opaque function** | A Lean 4 function whose implementation is hidden. Lean trusts the stated signature but cannot verify behavior. |
| **Semantic gap** | The distance between what the Lean 4 specification proves and what the Rust implementation does. |
| **Refinement** | A formal relationship where a lower-level implementation faithfully preserves the properties of a higher-level specification. |
| **Soundness** | The property that the proof system never accepts invalid proofs. A soundness break is the most catastrophic failure. |
| **Completeness** | The property that the proof system accepts all valid proofs. A completeness break causes denial of service. |
| **Differential test** | A test that compares the behavior of two implementations (Lean semantics vs. Rust code) on the same inputs. |
| **Residual trust assumption** | An axiom that cannot be mechanically verified and must be accepted based on structural arguments and code review. |
