# VSEL TLA+ Model Checking Configurations

## Overview

The VSEL TLA+ model uses bounded model checking via TLC to verify invariants
and temporal properties. Because bounded model checking can only prove properties
within the explored state space, we provide three parameterized configurations
at increasing scale. For unbounded guarantees, see the inductive invariant proofs
in `formal/VSEL/Foundations/Invariants.lean`.

**Remediates:** L-001 from ULTRA_ADVERSARIAL_AUDIT.md — "bounded model checking
cannot prove unbounded properties."

## Configurations

| Config | Accounts | MaxBalance | MaxSeqIndex | CI Schedule | Expected Runtime |
|--------|----------|------------|-------------|-------------|------------------|
| `MC_small.cfg` | 3 | 10 | 5 | Per-commit / PR gate | 5–30 seconds |
| `MC_medium.cfg` | 5 | 100 | 5 | Nightly | 5–30 minutes |
| `MC_large.cfg` | 10 | 1,000 | 4 | Weekly | 2–8 hours |

### MC_small.cfg (Fast CI)

- **Accounts:** `{"A", "B", "C"}`
- **MaxBalance:** 10
- **MaxSeqIndex:** 5
- **State space:** ~50,000–100,000 reachable states
- **Purpose:** Fast feedback on every commit. Catches regressions in transition
  logic, guard classification, and invariant definitions.
- **Usage:** `tlc Properties -config MC_small.cfg`

### MC_medium.cfg (Nightly CI)

- **Accounts:** `{"A", "B", "C", "D", "E"}`
- **MaxBalance:** 100
- **MaxSeqIndex:** 5
- **State space:** ~1,000,000–10,000,000 reachable states
- **Purpose:** Exercises a wider balance range with more accounts, catching
  arithmetic edge cases (e.g., dust threshold interactions, concentration
  limits) that the small model misses. The larger account set tests guard
  logic with more sender/receiver combinations.
- **Usage:** `tlc Properties -config MC_medium.cfg -workers auto`

### MC_large.cfg (Weekly Deep Check)

- **Accounts:** `{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}`
- **MaxBalance:** 1,000
- **MaxSeqIndex:** 4 (reduced to compensate for larger branching factor)
- **State space:** Very large; TLC explores as many states as feasible
  within the depth bound. May not exhaust the full space.
- **Purpose:** Provides the strongest bounded guarantee. With 10 accounts
  and balance range 0–1000, this exercises realistic-scale interactions
  including multi-party transfers, deposit/withdraw sequences, and
  economic invariant boundary conditions.
- **Usage:** `tlc Properties -config MC_large.cfg -workers auto`
- **Note:** Consider `-dfid` (depth-first iterative deepening) if BFS
  exhausts available memory.

## Properties Checked

All three configurations check the same set of properties:

### Core Properties
1. **StateValidity** — all reachable states satisfy `ValidState(s)`
2. **ResourceConservation** — `SumBalances = total_supply` at every state
3. **GuardExhaustiveness** — every `(s, σ)` handled by at least one class
4. **GuardDisjointness** — exactly one class selected after priority resolution
5. **TransitionDeterminism** — `Classify` always returns a valid class
6. **DerivedConsistency** — `D = Derive(C)` after every transition

### Supporting Invariants
- **TypeOK** — type invariant for all state variables
- **T_no_revert, T_causal, T_complete** — temporal invariants
- **E_cost, G_solvency, G_dust** — economic invariants
- **AllErrorPathsPreserveState** — error paths don't mutate canonical state
- **PriorityCorrectness, NoopIsCatchAll** — guard priority ordering

### Temporal Properties
- **NoRollbackTemporal** — `[][seq_index' >= seq_index]_vars`
- **CausalOrderingTemporal** — `[][timestamp' >= timestamp]_vars`

## Relationship to Inductive Proofs

Bounded model checking verifies properties for all states reachable within
the parameter bounds. For unbounded guarantees (arbitrary number of accounts,
arbitrary balance values, arbitrary trace lengths), the Lean 4 inductive
invariant proofs in `formal/VSEL/Foundations/Invariants.lean` provide:

- **StateValidity inductive proof:** If `ValidState(s)` holds and
  `Apply(s, σ) = s'`, then `ValidState(s')` holds.
- **ResourceConservation inductive proof:** If resource conservation holds
  for state `s` and `Apply(s, σ) = s'`, then resource conservation holds
  for `s'`.
- **GuardExhaustiveness:** Structural property of the `Classify` function
  (proven by construction in both TLA+ and Lean 4).

Together, bounded model checking (TLA+) and inductive proofs (Lean 4) provide
complementary assurance: TLA+ finds concrete counterexamples in finite models,
while Lean 4 proves properties hold for all possible states.
