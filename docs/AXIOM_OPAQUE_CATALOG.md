# Axiom & Opaque Type Catalog — VSEL Refinement Chain

## Purpose

This document catalogs every `axiom` declaration and every `opaque` type/function
in the VSEL Lean 4 refinement chain. It serves as the primary input for
`SEMANTIC_GAP_ANALYSIS.md` (task 7.2) and satisfies Requirements 8.1 and 8.2.

**Scope**: Three refinement files and their transitive dependencies:
- `formal/VSEL/Refinement/FormalToSIR.lean` (R01: Formal Spec to SIR)
- `formal/VSEL/Refinement/SIRToConcrete.lean` (R12: SIR to Concrete)
- `formal/VSEL/Refinement/ConcreteToConstraint.lean` (R23: Concrete to Constraint)
- `formal/VSEL/Mapping/SemanticMapping.lean` (mapping functions)
- `formal/VSEL/Mapping/Commutativity.lean` (commutativity axioms)
- `formal/VSEL/Mapping/Observable.lean` (observable axioms)
- `formal/VSEL/Foundations/State.lean` (state types, Derive)
- `formal/VSEL/Foundations/Transition.lean` (Apply, Classify, Obs)
- `formal/VSEL/Foundations/Input.lean` (input types)
- `formal/VSEL/Foundations/Invariants.lean` (invariant axioms)

---

## Part 1: Complete Axiom Inventory

### Classification Legend

| Classification | Meaning |
|---|---|
| **Closeable by theorem** | Can be derived from more primitive axioms within Lean 4 |
| **Closeable by test** | Can be validated by Rust-side unit or property tests |
| **Closeable by differential test** | Requires comparing Lean semantics against Rust behavior |
| **Residual trust assumption** | Cannot be mechanically closed; requires code review + structural argument |

---

### Layer 0: Foundations (Transition.lean, Invariants.lean)

These axioms are the bedrock. Every refinement layer depends on them.

---

#### AX-2: `apply_closure`

- **File**: `Foundations/Transition.lean`
- **Statement**: `ValidState s -> ValidState (Apply s sigma)`
- **What it assumes about Rust**: The Rust `Apply` function in `vsel-core/src/transition.rs` always produces a structurally valid state when given a valid pre-state. Specifically: balance sums equal total_supply, derived state equals `Derive(canonical)`, environment domain is non-zero, and metadata monotonicity holds.
- **Adversarial exploit if violated**: An attacker crafts an input that causes `Apply` to produce a state where `D != Derive(C)` (derived inconsistency) or where balance sums diverge from total_supply. Subsequent proofs built on this invalid state would be accepted by the verifier, enabling state corruption or resource creation from nothing.
- **Classification**: **Closeable by test** — Property-based tests can generate random valid states and inputs, apply the transition, and verify all validity predicates hold on the post-state.
- **Rust counterpart**: `transition.rs::apply()` + `state.rs::is_valid()`

---

#### AX-3: `initial_state_valid`

- **File**: `Foundations/Transition.lean`
- **Statement**: `s0.metadata.sequenceIndex = 0 -> s0.metadata.previousCommitment = zeroHash -> ValidState s0`
- **What it assumes about Rust**: The genesis state constructor in Rust produces a state satisfying all validity predicates when sequence_index is 0 and previous_commitment is the zero hash.
- **Adversarial exploit if violated**: If the genesis state is invalid, the entire inductive invariant chain collapses. An attacker who controls genesis construction could create an initial state with inconsistent balances, enabling resource theft from the first transition onward.
- **Classification**: **Closeable by test** — Unit test that constructs the genesis state and verifies all validity predicates.
- **Rust counterpart**: Genesis state construction in `state.rs`

---

#### LEM-7: `error_preserves_invariants`

- **File**: `Foundations/Transition.lean`
- **Statement**: `ValidState s -> not (ValidInput sigma) -> ValidState (Apply s sigma)`
- **What it assumes about Rust**: When `Apply` receives an invalid input (missing signatures, empty payload, etc.), it still produces a valid post-state. The error path does not corrupt state.
- **Adversarial exploit if violated**: An attacker sends malformed inputs to corrupt state through the error handling path. If error handling breaks derived state consistency or balance conservation, subsequent valid transactions operate on corrupted state.
- **Classification**: **Closeable by test** — Property tests generate invalid inputs (empty sigs, empty payload, zero domain) and verify post-state validity.
- **Rust counterpart**: Error handling paths in `transition.rs::apply()`

---

#### PO-SV: `state_validity_inductive_step` — CLOSED BY THEOREM

- **File**: `Foundations/Invariants.lean`
- **Statement**: `ValidState s -> ValidState (Apply s sigma)`
- **What it assumes about Rust**: Identical to `apply_closure` (AX-2). This is a re-statement for the inductive invariant proof framework.
- **Adversarial exploit if violated**: Same as AX-2.
- **Classification**: **Closed by theorem** — This was equivalent to `apply_closure` and has been replaced by a theorem referencing AX-2 directly. The axiom declaration `axiom state_validity_inductive_step ...` has been replaced with `theorem state_validity_inductive_step ... := apply_closure s sigma`.
- **Note**: Previously redundant with `apply_closure`. Now eliminated as an axiom, reducing the total axiom count from 33 to 32. All downstream proofs remain valid because the theorem has the same name and type signature.

---

#### PO-RC: `resource_conservation_inductive_step`

- **File**: `Foundations/Invariants.lean`
- **Statement**: `G_struct s -> G_struct (Apply s sigma)`
- **What it assumes about Rust**: Every transition preserves the invariant that the sum of all account balances equals `systemData.totalSupply`. No transition creates or destroys resources.
- **Adversarial exploit if violated**: An attacker finds a transition that increases their balance without a corresponding decrease elsewhere, enabling infinite resource creation. This is the most economically devastating attack vector.
- **Classification**: **Closeable by test** — Property tests generate random valid states and inputs, apply the transition, and verify `sum(balances) == totalSupply` in the post-state.
- **Rust counterpart**: Balance manipulation logic in `transition.rs::apply()`

---

#### PO-DC: `derived_consistency_inductive_step`

- **File**: `Foundations/Invariants.lean`
- **Statement**: `G_commit s -> G_commit (Apply s sigma)`
- **What it assumes about Rust**: Every transition recomputes `derived = Derive(canonical)` in the post-state. The Rust `Apply` function always calls `Derive` on the new canonical state.
- **Adversarial exploit if violated**: If derived state becomes stale, the state root (a Merkle commitment) no longer matches the canonical data. An attacker could present a proof against the stale root while the canonical state has been modified, enabling double-spend or state rollback.
- **Classification**: **Closeable by test** — Property tests verify `post.derived == Derive(post.canonical)` after every transition.
- **Rust counterpart**: `Derive` call in `transition.rs::apply()`

---

#### PO-MM: `monotonic_metadata_inductive_step`

- **File**: `Foundations/Invariants.lean`
- **Statement**: `G_mono s -> G_mono (Apply s sigma)`
- **What it assumes about Rust**: Metadata monotonicity (genesis has zero commitment, non-genesis has non-zero commitment) is preserved by every transition.
- **Adversarial exploit if violated**: An attacker could reset the sequence index to 0 (re-genesis) or set the previous commitment to zero on a non-genesis state, breaking the causal chain and enabling trace forgery.
- **Classification**: **Closeable by test** — Property tests verify metadata monotonicity in post-states.
- **Rust counterpart**: Metadata update logic in `transition.rs::apply()`

---

#### PO-ENV: `environment_consistency_inductive_step`

- **File**: `Foundations/Invariants.lean`
- **Statement**: `G_env s -> G_env (Apply s sigma)`
- **What it assumes about Rust**: The environment domain tag remains non-zero after every transition.
- **Adversarial exploit if violated**: A zero domain tag could disable domain separation in cryptographic operations, enabling cross-domain replay attacks.
- **Classification**: **Closeable by test** — Property tests verify `post.environment.executionDomain.hash != zeroHash`.
- **Rust counterpart**: Environment handling in `transition.rs::apply()`

---

#### `guard_exhaustiveness`

- **File**: `Foundations/Invariants.lean`
- **Statement**: `exists tc : TransitionClass, Classify s sigma = tc`
- **What it assumes about Rust**: The Rust `Classify` function handles every possible (state, input) pair. No input falls through without classification.
- **Adversarial exploit if violated**: An unclassified input could trigger undefined behavior or a panic in the transition function, causing denial of service or unpredictable state changes.
- **Classification**: **Closeable by test** — Property tests generate random (state, input) pairs and verify `Classify` returns a valid `TransitionClass` without panicking. Also structurally guaranteed by the if-else chain in Rust (the final `noop` branch is a catch-all).
- **Rust counterpart**: `transition.rs::classify()`

---

### Layer 1: Mapping (Commutativity.lean, Observable.lean)

These axioms bridge the concrete Rust execution to the formal Lean specification.

---

#### THM-1: `thm1_execution_commutativity`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `mu_S (Apply s sigma) = Apply_f (mu_S s) (mu_Sigma sigma)`
- **What it assumes about Rust**: The Rust `Apply` function, when its inputs and outputs are mapped through `mu_S`/`mu_Sigma`, produces the same result as the formal-side `Apply_f`. This is the fundamental semantic preservation property — concrete execution is faithful to the formal specification.
- **Adversarial exploit if violated**: The Rust implementation silently diverges from the formal spec. An attacker finds an input where the Rust transition produces a different post-state than the formal spec predicts. Since proofs are verified against the formal semantics, the attacker could construct a valid-looking proof for an invalid state transition.
- **Classification**: **Closeable by differential test** — Generate random (state, input) pairs, compute `Apply` in Rust, map through `mu_S`/`mu_Sigma`, and compare against the formal `Apply_f` semantics. This is Property 10 in the design document.
- **Rust counterpart**: `mapping.rs::verify_execution_commutativity()`
- **Risk level**: **CRITICAL** — This is the single most important axiom in the entire refinement chain.

---

#### THM-4: `thm4_auxiliary_independence`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `Apply s { payload := p, auth := a, aux := aux1 } = Apply s { payload := p, auth := a, aux := aux2 }`
- **What it assumes about Rust**: The Rust `Apply` function ignores the `aux` field entirely. Two inputs differing only in auxiliary data produce identical post-states.
- **Adversarial exploit if violated**: An attacker embeds malicious data in the `aux` field that influences the transition outcome. Since `aux` is not constrained by the proof system (it's explicitly excluded from semantic content), this creates a covert channel for state manipulation that bypasses all formal verification.
- **Classification**: **Closeable by test** — Property tests generate random states and inputs, vary only the `aux` field, and verify identical post-states.
- **Rust counterpart**: `mapping.rs::verify_auxiliary_exclusion()`

---

#### THM-5: `thm5_derived_commutativity`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `mu_D (Derive c) = Derive_f (mu_C c)`
- **What it assumes about Rust**: The Rust `Derive` function, when its input and output are mapped through `mu_C`/`mu_D`, produces the same result as the formal-side `Derive_f`. Derived state computation is semantically faithful.
- **Adversarial exploit if violated**: The derived state (including the state root / Merkle commitment) diverges between Rust and the formal spec. An attacker could present a proof against a state root that doesn't match the actual canonical data, enabling state forgery.
- **Classification**: **Closeable by differential test** — Generate random canonical states, compute `Derive` in Rust, map through `mu_C`/`mu_D`, and compare against `Derive_f`.
- **Rust counterpart**: `mapping.rs` (derived state mapping)

---

#### TP-7a: `tp7_input_canonicalization_idempotent`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `Canonicalize_Input (Canonicalize_Input sigma) = Canonicalize_Input sigma`
- **What it assumes about Rust**: The Rust `canonicalize_input` function is idempotent — applying it twice yields the same result as applying it once.
- **Adversarial exploit if violated**: Non-idempotent canonicalization could cause different nodes to disagree on the canonical form of an input, leading to consensus failures or state divergence across replicas.
- **Classification**: **Closeable by test** — Property tests generate random inputs, canonicalize twice, and verify equality.
- **Rust counterpart**: `canonicalization.rs::canonicalize_input()`

---

#### TP-7b: `tp7_state_canonicalization_idempotent`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `Canonicalize_State (Canonicalize_State s) = Canonicalize_State s`
- **What it assumes about Rust**: The Rust `canonicalize_state` function is idempotent.
- **Adversarial exploit if violated**: Same as TP-7a — consensus failures from non-deterministic canonical forms.
- **Classification**: **Closeable by test** — Property tests generate random states, canonicalize twice, and verify equality.
- **Rust counterpart**: `canonicalization.rs::canonicalize_state()`

---

#### TP-8a: `tp8_input_canonicalization_preserves_semantics`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `mu_Sigma (Canonicalize_Input sigma) = mu_Sigma sigma`
- **What it assumes about Rust**: Canonicalizing an input does not change its formal-domain representation. The mapping function `mu_Sigma` produces the same output for both the original and canonicalized input.
- **Adversarial exploit if violated**: Canonicalization silently changes the semantic meaning of an input. An attacker crafts an input whose canonical form maps to a different formal input, causing the proof system to verify a different transition than what was actually executed.
- **Classification**: **Closeable by differential test** — Generate random inputs, canonicalize, map both through `mu_Sigma`, and verify equality.
- **Rust counterpart**: `canonicalization.rs` + `mapping.rs::map_input()`

---

#### TP-8b: `tp8_state_canonicalization_preserves_semantics`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `mu_S (Canonicalize_State s) = mu_S s`
- **What it assumes about Rust**: Canonicalizing a state does not change its formal-domain representation.
- **Adversarial exploit if violated**: Same as TP-8a but for states — canonicalization changes the state root, enabling proof/state mismatch attacks.
- **Classification**: **Closeable by differential test** — Generate random states, canonicalize, map both through `mu_S`, and verify equality.
- **Rust counterpart**: `canonicalization.rs` + `mapping.rs::map_state()`

---

#### `canon_clears_aux`

- **File**: `Mapping/Commutativity.lean`
- **Statement**: `Canonicalize_Input { payload := p, auth := a, aux := aux1 } = Canonicalize_Input { payload := p, auth := a, aux := aux2 }`
- **What it assumes about Rust**: Canonicalization normalizes the `aux` field such that two inputs differing only in `aux` produce identical canonical forms.
- **Adversarial exploit if violated**: Auxiliary data leaks into the canonical form, creating a side channel. Combined with a violation of THM-4, this could enable aux-dependent state manipulation that survives canonicalization.
- **Classification**: **Closeable by test** — Property tests generate inputs differing only in `aux`, canonicalize both, and verify equality.
- **Rust counterpart**: `canonicalization.rs::canonicalize_input()`

---

#### THM-2: `thm2_observable_commutativity`

- **File**: `Mapping/Observable.lean`
- **Statement**: `mu_O (Obs s sigma s') = Obs_f (mu_S s) (mu_Sigma sigma) (mu_S s')`
- **What it assumes about Rust**: The Rust `Obs` function (which computes externally visible outputs like events, gas used, status), when mapped through `mu_O`, produces the same result as the formal-side `Obs_f`.
- **Adversarial exploit if violated**: The observable outputs diverge between Rust and the formal spec. An attacker could cause the system to emit incorrect events or status codes while the proof system believes the transition was correct. This enables "silent" attacks where the proof verifies but the user-visible behavior is wrong.
- **Classification**: **Closeable by differential test** — Generate random (state, input, post-state) triples, compute `Obs` in Rust, map through `mu_O`, and compare against `Obs_f`.
- **Rust counterpart**: `mapping.rs::verify_observable_commutativity()`

---

#### `mu_Sigma_ignores_aux`

- **File**: `Mapping/Observable.lean`
- **Statement**: `mu_Sigma { payload := p, auth := a, aux := aux1 } = mu_Sigma { payload := p, auth := a, aux := aux2 }`
- **What it assumes about Rust**: The `map_input` function in Rust ignores the `aux` field when producing the formal input representation.
- **Adversarial exploit if violated**: Auxiliary data influences the formal input representation, breaking the assumption that `aux` is semantically irrelevant. An attacker could craft `aux` values that change the formal input, causing proof verification to accept transitions that should be rejected.
- **Classification**: **Closeable by test** — Property tests generate inputs differing only in `aux`, map both through `mu_Sigma`, and verify equality.
- **Rust counterpart**: `mapping.rs::map_input()`

---

### Layer 2: Refinement R01 — Formal to SIR (FormalToSIR.lean)

---

#### R01-1: `r01_state_validity`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `ValidState (SIR_to_Formal_State s_sir)`
- **What it assumes about Rust**: Every SIR state, when mapped to the formal domain, satisfies all validity predicates (balance conservation, derived consistency, environment validity, metadata monotonicity).
- **Adversarial exploit if violated**: An attacker constructs a SIR state that maps to an invalid formal state. Since TP-1 (SIR refines formal) depends on this axiom, the entire SIR-level proof chain collapses — proofs generated from invalid SIR states would be accepted.
- **Classification**: **Closeable by test** — Property tests generate random SIR states, map to formal states, and verify all validity predicates.
- **Rust counterpart**: SIR state construction + `state.rs::is_valid()`

---

#### R01-2: `r01_transition_correspondence`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `SIR_to_Formal_State (SIRTransition s_sir sigma_sir) = Apply (SIR_to_Formal_State s_sir) (SIR_to_Formal_Input sigma_sir)`
- **What it assumes about Rust**: The SIR transition function, when mapped to the formal domain, produces the same result as applying the formal `Apply` function to the mapped inputs. SIR execution is faithful to the formal specification.
- **Adversarial exploit if violated**: The SIR interpreter diverges from the formal spec. An attacker finds an input where the SIR produces a different post-state than `Apply`. Since the constraint system is compiled from SIR, this means the constraints verify a different computation than what the formal spec defines.
- **Classification**: **Closeable by differential test** — Generate random SIR (state, input) pairs, execute the SIR transition, map the result, and compare against `Apply` on the mapped inputs.
- **Rust counterpart**: `vsel-sir/src/interpreter.rs` + `mapping.rs`
- **Risk level**: **CRITICAL** — This is the SIR-level analog of THM-1.

---

#### R01-3: `r01_invariant_correspondence`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `GlobalInvariantsHold (SIR_to_Formal_State s_sir)`
- **What it assumes about Rust**: All global invariants (state validity, resource conservation, derived consistency, metadata monotonicity, environment consistency) hold on every SIR state when mapped to the formal domain.
- **Adversarial exploit if violated**: An attacker constructs a SIR state where global invariants are violated in the formal domain. Since TP-4 (global invariant preservation) depends on this, the attacker could break resource conservation or derived consistency through the SIR layer.
- **Classification**: **Closeable by test** — Property tests generate random SIR states, map to formal states, and verify all global invariants.
- **Rust counterpart**: SIR state construction + `invariants/src/global.rs`

---

#### R01-5: `r01_sir_complete`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `exists (s_sir : SIRState) (sigma_sir : SIRInput), SIR_to_Formal_State s_sir = s /\ SIR_to_Formal_Input sigma_sir = sigma`
- **What it assumes about Rust**: Every formal (state, input) pair has a corresponding SIR (state, input) pair that maps to it. The SIR representation is complete — no formal state is unreachable from SIR.
- **Adversarial exploit if violated**: Some formal states have no SIR representation. The constraint system (compiled from SIR) cannot express constraints for these states, creating a gap where transitions involving unreachable states are unconstrained.
- **Classification**: **Residual trust assumption** — Completeness is a universal quantifier over all formal states, which cannot be exhaustively tested. It requires structural argument: the SIR is generated from the same type definitions as the formal spec, so every formal state has a corresponding SIR encoding.
- **Mitigating evidence**: (a) SIR types are generated from the same schema as formal types, (b) the SIR serialization/deserialization round-trips all formal states in property tests, (c) code review confirms no formal state constructors are missing from SIR.
- **Rust counterpart**: `vsel-sir/src/types.rs` (SIR type definitions)

---

#### TP-6: `tp6_resource_conservation`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `ValidState s -> L_cons s sigma (Apply s sigma)`
- **What it assumes about Rust**: For every valid state and any input, the transition preserves resource conservation (sum of balances equals total_supply in both pre and post states).
- **Adversarial exploit if violated**: An attacker finds a transition that creates or destroys resources. This is the most economically devastating attack — it enables minting tokens from nothing or burning tokens without authorization.
- **Classification**: **Closeable by test** — Property tests generate random valid states and inputs, apply the transition, and verify `L_cons` holds. This is a strengthening of PO-RC that also requires `ValidState` as a precondition.
- **Rust counterpart**: Balance manipulation in `transition.rs::apply()`
- **Risk level**: **CRITICAL** — Direct economic impact.

---

### Layer 3: Refinement R12 — SIR to Concrete (SIRToConcrete.lean)

---

#### R12-5 / TP-11: `r12_encoding_injectivity`

- **File**: `Refinement/SIRToConcrete.lean`
- **Statement**: `Encode s1 = Encode s2 -> s1 = s2`
- **What it assumes about Rust**: The Rust state encoding function (deterministic serialization) is injective — two distinct states never produce the same byte encoding.
- **Adversarial exploit if violated**: Two different states produce the same encoding (a collision). An attacker could present a proof for state A while the system is actually in state B (which has the same encoding). This enables state substitution attacks — the proof verifies against the encoding, but the actual state is different.
- **Classification**: **Closeable by test** — Property tests generate pairs of distinct random states, encode both, and verify the encodings differ. Additionally, the encoding format can be analyzed structurally: if the encoding is a deterministic serialization that includes all state fields with length prefixes, injectivity follows from the serialization format.
- **Rust counterpart**: State serialization in `state.rs` or `canonicalization.rs`
- **Risk level**: **HIGH** — Encoding collisions enable state substitution.

---

#### Note on `thm2_observable_commutativity` in R12

The `r12_observable_commutativity` theorem in `SIRToConcrete.lean` is not a new axiom — it delegates to `thm2_observable_commutativity` from `Observable.lean`, which is already cataloged above. No additional axiom is introduced at this layer for observable commutativity.

---

### Layer 4: Refinement R23 — Concrete to Constraint (ConcreteToConstraint.lean)

---

#### LEM-4: `lem4_constraint_soundness`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `SatisfiesConstraints tau cs -> ValidTraceR23 tau`
- **What it assumes about Rust**: If a trace satisfies all constraints in the compiled constraint system, then the trace is semantically valid (all transitions are valid, all invariants hold). No invalid execution can satisfy the constraints.
- **Adversarial exploit if violated**: An attacker constructs an invalid trace (e.g., one that creates resources from nothing) that nonetheless satisfies all constraints. The proof system accepts the invalid trace, and the verifier cannot distinguish it from a valid execution. This is a **soundness break** — the most catastrophic failure mode for a ZK proof system.
- **Classification**: **Closeable by test** — Generate random invalid traces (with known invariant violations) and verify they fail at least one constraint. This is Property 9 (soundness direction) in the design document.
- **Rust counterpart**: `vsel-constraints/src/compiler.rs` (constraint compilation) + `vsel-constraints/src/coverage.rs`
- **Risk level**: **CRITICAL** — A soundness break means the proof system provides no security guarantees.

---

#### LEM-5: `lem5_constraint_completeness`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `ValidTraceR23 tau -> SatisfiesConstraints tau cs`
- **What it assumes about Rust**: If a trace is semantically valid, then it satisfies all constraints. All valid executions are representable in the constraint system.
- **Adversarial exploit if violated**: A valid trace fails constraint checking. This is a **completeness break** — the proof system rejects valid executions. While less catastrophic than a soundness break (no security violation), it causes denial of service: legitimate users cannot generate proofs for valid transactions.
- **Classification**: **Closeable by test** — Generate random valid traces and verify they satisfy all constraints. This is Property 9 (completeness direction) in the design document.
- **Rust counterpart**: `vsel-constraints/src/compiler.rs`
- **Risk level**: **HIGH** — Completeness breaks cause denial of service.

---

#### CONST-1: `const1_zero_unconstrained`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `AllVariablesConstrained cs`
- **What it assumes about Rust**: Every witness variable in the compiled constraint system is referenced by at least one constraint. No variable is "free" (unconstrained).
- **Adversarial exploit if violated**: An unconstrained witness variable can be set to any value by the prover without affecting constraint satisfaction. An attacker sets the unconstrained variable to a value that changes the semantic meaning of the trace while still satisfying all constraints. This is a classic underconstraint vulnerability.
- **Classification**: **Closeable by static analysis** — The constraint compiler can be instrumented to check that every declared witness variable appears in at least one constraint. This is a compile-time check, not a runtime property.
- **Rust counterpart**: `vsel-constraints/src/underconstraint.rs` (underconstraint analysis)

---

#### CONST-2: `const2_no_unused_inputs`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `NoUnusedWitnessInputs cs`
- **What it assumes about Rust**: Every witness input influences at least one constraint output. No input is ignored by the constraint system.
- **Adversarial exploit if violated**: An unused witness input means some aspect of the execution trace is not verified by the constraint system. An attacker could modify the unused input's corresponding trace data without detection.
- **Classification**: **Closeable by static analysis** — The constraint compiler can check that every input variable has a data-flow path to at least one constraint.
- **Rust counterpart**: `vsel-constraints/src/underconstraint.rs`

---

#### CONST-3: `const3_branch_completeness`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `BranchComplete cs`
- **What it assumes about Rust**: For every conditional in the SIR/IR program, both branches (true and false) generate constraints in the constraint system.
- **Adversarial exploit if violated**: A missing branch means one execution path is unconstrained. An attacker triggers the unconstrained branch and provides arbitrary witness values for that path, enabling state manipulation through the unconstrained branch.
- **Classification**: **Closeable by static analysis** — The constraint compiler can verify that every `IfThenElse` node in the SIR generates constraints for both the `then` and `else` branches.
- **Rust counterpart**: `vsel-constraints/src/compiler.rs` (branch handling) + `vsel-constraints/src/coverage.rs`

---

### Layer 5: SIR Types (FormalToSIR.lean — Inhabited axioms)

---

#### `SIRState.inhabited`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `Inhabited SIRState`
- **What it assumes about Rust**: The SIR state type has a default/zero value. This is a Lean 4 technical requirement for opaque types used in certain proof contexts.
- **Adversarial exploit if violated**: No direct exploit — this is a proof infrastructure axiom. If violated, certain Lean 4 proof tactics would fail, but no runtime behavior is affected.
- **Classification**: **Residual trust assumption** — This is a Lean 4 technical requirement with no Rust counterpart. It's satisfied by construction (any Rust struct with `Default` has an inhabited type).
- **Mitigating evidence**: Rust `Default` derive on SIR types.

---

#### `SIRInput.inhabited`

- **File**: `Refinement/FormalToSIR.lean`
- **Statement**: `Inhabited SIRInput`
- **What it assumes about Rust**: Same as `SIRState.inhabited` but for the SIR input type.
- **Classification**: **Residual trust assumption** — Same reasoning as above.

---

#### `ConstraintSystemR23.inhabited`

- **File**: `Refinement/ConcreteToConstraint.lean`
- **Statement**: `Inhabited ConstraintSystemR23`
- **What it assumes about Rust**: The constraint system type has a default value.
- **Classification**: **Residual trust assumption** — Same reasoning as above.

---

---

## Part 2: Complete Opaque Type and Function Catalog

Every `opaque` declaration represents a point where Lean 4 cannot reason about
the implementation — it trusts that the Rust code satisfies the stated axioms.
Each opaque entity is a potential semantic gap.

---

### Opaque Types

| # | Opaque Type | File | Rust Counterpart | Purpose |
|---|---|---|---|---|
| OT-1 | `SIRState` | `FormalToSIR.lean` | `vsel-sir/src/types.rs::SirState` | SIR-level state representation |
| OT-2 | `SIRInput` | `FormalToSIR.lean` | `vsel-sir/src/types.rs::SirInput` | SIR-level input representation |
| OT-3 | `ConstraintSystemR23` | `ConcreteToConstraint.lean` | `vsel-constraints/src/compiler.rs::ConstraintSystem` | Compiled constraint system |
| OT-4 | `TraceR23` | `ConcreteToConstraint.lean` | `vsel-trace/src/engine.rs::ExecutionTrace` | Execution trace for constraint checking |
| OT-5 | `SIRProgramR23` | `ConcreteToConstraint.lean` | `vsel-sir/src/types.rs::SirProgram` | SIR program for constraint compilation |

**Structural correspondence notes**:
- `SIRState` and `SIRInput` are opaque wrappers around the SIR type system. The Rust types contain all fields present in the formal `State` and `Input` types, plus SIR-specific metadata (instruction pointers, stack frames). The formal types are a projection of the SIR types.
- `ConstraintSystemR23` wraps the compiled constraint system. The Rust type contains constraint expressions, variable declarations, and metadata. The Lean type is purely abstract — no fields are visible.
- `TraceR23` wraps the execution trace. The Rust type contains a sequence of (pre-state, input, post-state) triples with witness data. The Lean type is purely abstract.
- `SIRProgramR23` wraps the SIR program. The Rust type contains the instruction sequence, type declarations, and entry points.

---

### Opaque Functions — Foundations Layer

| # | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-1 | `Derive` | `State.lean` | `CanonicalState -> DerivedState` | `state.rs::derive()` — computes state root and aggregates from canonical state |
| OF-2 | `DeriveEconomic` | `State.lean` | `CanonicalState -> Environment -> EconomicContext` | `state.rs::derive_economic()` — computes economic context from canonical state + environment |
| OF-3 | `EconomicallyValid` | `State.lean` | `State -> Prop` | `economic.rs::is_economically_valid()` — checks all economic invariants |
| OF-4 | `Classify` | `Transition.lean` | `State -> Input -> TransitionClass` | `transition.rs::classify()` — determines transition class via guard evaluation |
| OF-5 | `Apply` | `Transition.lean` | `State -> Input -> State` | `transition.rs::apply()` — executes the state transition |
| OF-6 | `Obs` | `Transition.lean` | `State -> Input -> State -> Observable` | `transition.rs::observe()` — computes externally visible outputs |

---

### Opaque Functions — Mapping Layer

| # | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-7 | `mu_S` | `SemanticMapping.lean` | `State -> FormalState` | `mapping.rs::map_state()` — maps concrete state to formal representation |
| OF-8 | `mu_Sigma` | `SemanticMapping.lean` | `Input -> FormalInput` | `mapping.rs::map_input()` — maps concrete input to formal representation |
| OF-9 | `mu_O` | `SemanticMapping.lean` | `Observable -> FormalObservable` | `mapping.rs::map_observable()` — maps concrete observable to formal representation |
| OF-10 | `Apply_f` | `SemanticMapping.lean` | `FormalState -> FormalInput -> FormalState` | SIR-level transition function (the "reference" implementation) |
| OF-11 | `Obs_f` | `SemanticMapping.lean` | `FormalState -> FormalInput -> FormalState -> FormalObservable` | SIR-level observable function |
| OF-12 | `Derive_f` | `SemanticMapping.lean` | `FormalState -> FormalState` | SIR-level derived state computation |
| OF-13 | `Canonicalize_Input` | `SemanticMapping.lean` | `Input -> Input` | `canonicalization.rs::canonicalize_input()` — normalizes input to canonical form |
| OF-14 | `Canonicalize_State` | `SemanticMapping.lean` | `State -> State` | `canonicalization.rs::canonicalize_state()` — normalizes state to canonical form |
| OF-15 | `mu_C` | `Commutativity.lean` | `CanonicalState -> FormalState` | `mapping.rs` — maps canonical state component to formal representation |
| OF-16 | `mu_D` | `Commutativity.lean` | `DerivedState -> FormalState` | `mapping.rs` — maps derived state component to formal representation |

---

### Opaque Functions — Refinement Layer

| # | Opaque Function | File | Signature | Rust Counterpart |
|---|---|---|---|---|
| OF-17 | `SIRTransition` | `FormalToSIR.lean` | `SIRState -> SIRInput -> SIRState` | `vsel-sir/src/interpreter.rs::execute()` — SIR interpreter |
| OF-18 | `SIR_to_Formal_State` | `FormalToSIR.lean` | `SIRState -> State` | `vsel-sir/src/types.rs` — extracts formal state from SIR state |
| OF-19 | `SIR_to_Formal_Input` | `FormalToSIR.lean` | `SIRInput -> Input` | `vsel-sir/src/types.rs` — extracts formal input from SIR input |
| OF-20 | `Encode` | `SIRToConcrete.lean` | `State -> List UInt8` | `state.rs` or `canonicalization.rs` — deterministic state serialization |
| OF-21 | `SatisfiesConstraints` | `ConcreteToConstraint.lean` | `TraceR23 -> ConstraintSystemR23 -> Prop` | `vsel-constraints/src/compiler.rs::evaluate()` — constraint satisfaction check |
| OF-22 | `ValidTraceR23` | `ConcreteToConstraint.lean` | `TraceR23 -> Prop` | Trace validity check (all transitions valid, all invariants hold) |
| OF-23 | `AllVariablesConstrained` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/underconstraint.rs::check_all_constrained()` |
| OF-24 | `NoUnusedWitnessInputs` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/underconstraint.rs::check_no_unused()` |
| OF-25 | `BranchComplete` | `ConcreteToConstraint.lean` | `ConstraintSystemR23 -> Prop` | `vsel-constraints/src/coverage.rs::check_branch_complete()` |
| OF-26 | `Compile` | `ConcreteToConstraint.lean` | `SIRProgramR23 -> ConstraintSystemR23` | `vsel-constraints/src/compiler.rs::compile()` — SIR to constraint system |

---

## Part 3: Classification Summary

### Axiom Classification Table

| # | Axiom | File | Classification | Risk if Violated |
|---|---|---|---|---|
| A-1 | `apply_closure` (AX-2) | Transition.lean | Closeable by test | State corruption |
| A-2 | `initial_state_valid` (AX-3) | Transition.lean | Closeable by test | Inductive chain collapse |
| A-3 | `error_preserves_invariants` (LEM-7) | Transition.lean | Closeable by test | Error-path state corruption |
| A-4 | `state_validity_inductive_step` (PO-SV) | Invariants.lean | **Closed by theorem** (derived from AX-2) | State corruption |
| A-5 | `resource_conservation_inductive_step` (PO-RC) | Invariants.lean | Closeable by test | Resource creation/destruction |
| A-6 | `derived_consistency_inductive_step` (PO-DC) | Invariants.lean | Closeable by test | Stale state root |
| A-7 | `monotonic_metadata_inductive_step` (PO-MM) | Invariants.lean | Closeable by test | Trace forgery |
| A-8 | `environment_consistency_inductive_step` (PO-ENV) | Invariants.lean | Closeable by test | Cross-domain replay |
| A-9 | `guard_exhaustiveness` | Invariants.lean | Closeable by test | Unclassified input panic |
| A-10 | `thm1_execution_commutativity` (THM-1) | Commutativity.lean | Closeable by differential test | **CRITICAL**: Spec divergence |
| A-11 | `thm4_auxiliary_independence` (THM-4) | Commutativity.lean | Closeable by test | Covert aux channel |
| A-12 | `thm5_derived_commutativity` (THM-5) | Commutativity.lean | Closeable by differential test | State root forgery |
| A-13 | `tp7_input_canonicalization_idempotent` (TP-7a) | Commutativity.lean | Closeable by test | Consensus failure |
| A-14 | `tp7_state_canonicalization_idempotent` (TP-7b) | Commutativity.lean | Closeable by test | Consensus failure |
| A-15 | `tp8_input_canonicalization_preserves_semantics` (TP-8a) | Commutativity.lean | Closeable by differential test | Proof/execution mismatch |
| A-16 | `tp8_state_canonicalization_preserves_semantics` (TP-8b) | Commutativity.lean | Closeable by differential test | Proof/execution mismatch |
| A-17 | `canon_clears_aux` | Commutativity.lean | Closeable by test | Aux side channel |
| A-18 | `thm2_observable_commutativity` (THM-2) | Observable.lean | Closeable by differential test | Silent observable divergence |
| A-19 | `mu_Sigma_ignores_aux` | Observable.lean | Closeable by test | Aux influences formal input |
| A-20 | `r01_state_validity` (R01-1) | FormalToSIR.lean | Closeable by test | SIR proof chain collapse |
| A-21 | `r01_transition_correspondence` (R01-2) | FormalToSIR.lean | Closeable by differential test | **CRITICAL**: SIR divergence |
| A-22 | `r01_invariant_correspondence` (R01-3) | FormalToSIR.lean | Closeable by test | SIR invariant violation |
| A-23 | `r01_sir_complete` (R01-5) | FormalToSIR.lean | **Residual trust assumption** | Unreachable formal states |
| A-24 | `tp6_resource_conservation` (TP-6) | FormalToSIR.lean | Closeable by test | **CRITICAL**: Resource theft |
| A-25 | `r12_encoding_injectivity` (R12-5) | SIRToConcrete.lean | Closeable by test | State substitution |
| A-26 | `lem4_constraint_soundness` (LEM-4) | ConcreteToConstraint.lean | Closeable by test | **CRITICAL**: Soundness break |
| A-27 | `lem5_constraint_completeness` (LEM-5) | ConcreteToConstraint.lean | Closeable by test | Denial of service |
| A-28 | `const1_zero_unconstrained` (CONST-1) | ConcreteToConstraint.lean | Closeable by static analysis | Underconstraint exploit |
| A-29 | `const2_no_unused_inputs` (CONST-2) | ConcreteToConstraint.lean | Closeable by static analysis | Unverified trace data |
| A-30 | `const3_branch_completeness` (CONST-3) | ConcreteToConstraint.lean | Closeable by static analysis | Unconstrained branch |
| A-31 | `SIRState.inhabited` | FormalToSIR.lean | **Residual trust assumption** | None (proof infrastructure) |
| A-32 | `SIRInput.inhabited` | FormalToSIR.lean | **Residual trust assumption** | None (proof infrastructure) |
| A-33 | `ConstraintSystemR23.inhabited` | ConcreteToConstraint.lean | **Residual trust assumption** | None (proof infrastructure) |

---

### Classification Statistics

| Classification | Count | Axiom IDs |
|---|---|---|
| Closed by theorem | 1 (no longer an axiom) | A-4 |
| Closeable by test | 17 | A-1, A-2, A-3, A-5, A-6, A-7, A-8, A-9, A-11, A-13, A-14, A-17, A-19, A-20, A-22, A-24, A-25 |
| Closeable by differential test | 6 | A-10, A-12, A-15, A-16, A-18, A-21 |
| Closeable by static analysis | 3 | A-28, A-29, A-30 |
| Residual trust assumption | 4 | A-23, A-31, A-32, A-33 |
| **Total axioms remaining** | **32** | (A-4 eliminated by theorem derivation) |

---

### Residual Trust Assumptions (cannot be mechanically closed)

#### A-23: `r01_sir_complete` — SIR Completeness

- **Axiom**: Every formal (state, input) pair has a corresponding SIR representation.
- **Why it cannot be closed**: This is a universal quantifier over an infinite domain (all possible formal states and inputs). No finite test suite can verify completeness. A Lean 4 theorem would require constructing the inverse mapping, which is not possible when `SIRState` is opaque.
- **Risk if violated**: Some formal states have no SIR representation. Constraints compiled from SIR cannot cover these states, creating verification gaps.
- **Mitigating evidence**:
  1. SIR types are generated from the same schema as formal types (structural correspondence)
  2. SIR serialization/deserialization round-trip tests cover all formal state constructors
  3. Code review confirms no formal state variants are missing from SIR type definitions
  4. Property tests verify that randomly generated formal states can be round-tripped through SIR
- **Residual risk**: LOW — The structural correspondence argument is strong, and round-trip testing provides high confidence.

#### A-31, A-32, A-33: Inhabited Axioms

- **Axiom**: `SIRState`, `SIRInput`, and `ConstraintSystemR23` have default values.
- **Why they cannot be closed**: These are Lean 4 technical requirements for opaque types. They cannot be proven because the types are opaque — Lean cannot construct a value of an opaque type.
- **Risk if violated**: None at runtime. These axioms are only used by Lean 4 proof tactics that require `Inhabited` instances. If violated, certain proofs would fail to compile, but no runtime behavior is affected.
- **Mitigating evidence**:
  1. All corresponding Rust types derive `Default`
  2. The axioms are trivially satisfiable — any type with at least one value is inhabited
- **Residual risk**: NEGLIGIBLE — These are proof infrastructure axioms with no security implications.

---

## Part 4: Critical Attack Surface Analysis

### Highest-Risk Axioms (ordered by adversarial impact)

1. **A-26: `lem4_constraint_soundness`** — A soundness break means invalid traces are accepted as valid. This is the single most dangerous axiom because it directly controls whether the proof system provides any security guarantees at all.

2. **A-10: `thm1_execution_commutativity`** — If concrete execution diverges from the formal spec, the entire refinement chain is meaningless. Proofs verify formal semantics, but the system executes Rust code. Divergence means proofs don't correspond to reality.

3. **A-21: `r01_transition_correspondence`** — The SIR-level analog of THM-1. If the SIR interpreter diverges from the formal spec, constraints compiled from SIR verify the wrong computation.

4. **A-24: `tp6_resource_conservation`** — Direct economic impact. A violation enables minting tokens from nothing.

5. **A-25: `r12_encoding_injectivity`** — Encoding collisions enable state substitution attacks where a proof for state A is accepted for state B.

### Dependency Chain

The axioms form a trust chain where downstream axioms depend on upstream ones:

```
Foundations Layer (AX-2, AX-3, LEM-7, PO-*)
    |
    v
Mapping Layer (THM-1, THM-2, THM-4, THM-5, TP-7, TP-8)
    |
    v
R01: Formal -> SIR (R01-1..5, TP-6)
    |
    v
R12: SIR -> Concrete (R12-5/TP-11)
    |
    v
R23: Concrete -> Constraint (LEM-4, LEM-5, CONST-1..3)
```

A violation at any layer invalidates all downstream layers. The Foundations layer
axioms are the most critical because they affect the entire chain.

---

## Part 5: Gap-Closing Methodology

### For axioms closeable by test (17 axioms)

Generate Rust property-based tests using `proptest` that:
1. Generate random valid states and inputs
2. Execute the operation under test
3. Verify the axiom's postcondition holds

Minimum 10,000 iterations per axiom. Tests are added to
`protocol/tests/property/semantic_gap_tests.rs`.

### For axioms closeable by differential test (6 axioms)

Generate Rust tests that:
1. Generate random (state, input) pairs
2. Execute the operation in Rust
3. Map the result through the semantic mapping functions
4. Compare against the formal-side computation
5. Verify equality

These tests require a Rust implementation of the formal-side functions
(`Apply_f`, `Obs_f`, `Derive_f`) or a reference oracle. Minimum 1,000
iterations per axiom. Tests are added to
`protocol/tests/property/semantic_gap_tests.rs`.

### For axioms closeable by static analysis (3 axioms)

Instrument the constraint compiler to perform compile-time checks:
1. CONST-1: After compilation, verify every declared witness variable appears in at least one constraint
2. CONST-2: After compilation, verify every input variable has a data-flow path to a constraint
3. CONST-3: After compilation, verify every `IfThenElse` node generated constraints for both branches

These checks run as part of the constraint compilation pipeline and are
verified by existing tests in `vsel-constraints/src/underconstraint.rs`
and `vsel-constraints/src/coverage.rs`.

### For axioms closeable by theorem (1 axiom — COMPLETED)

The `state_validity_inductive_step` (A-4) axiom has been replaced with a theorem
referencing `apply_closure` (A-1). The Lean 4 declaration in
`formal/VSEL/Foundations/Invariants.lean` now reads:

```lean
theorem state_validity_inductive_step (s : State) (sigma : Input) :
  ValidState s → ValidState (Apply s sigma) :=
  apply_closure s sigma
```

This reduces the total axiom count from 33 to 32.

### For residual trust assumptions (4 axioms)

Document in `SEMANTIC_GAP_ANALYSIS.md` with:
- The axiom statement
- Why it cannot be closed
- The risk if violated
- Mitigating evidence (code review, structural argument, round-trip tests)
