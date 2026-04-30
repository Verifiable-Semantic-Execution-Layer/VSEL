# TLC Model Checking Audit Evidence

## Overview

This directory contains structured audit evidence from TLC (TLA+ Model Checker) execution
against the VSEL protocol's TLA+ specifications. TLC performs exhaustive state space
exploration to verify that behavioral invariants and temporal properties hold across all
reachable states.

## Methodology

### Tool

- **TLC2** Version 2026.04.27.203507 (rev: e3142ca)
- Breadth-first search model checking with 14 workers on 14 cores
- 3641 MB heap + 64 MB offheap memory
- MSBDiskFPSet fingerprint storage, DiskStateQueue

### Specifications Under Test

- **Properties.tla** — top-level specification importing all modules:
  - `StateMachine.tla` — core VSEL state machine definition
  - `Invariants.tla` — safety invariants (state validity, resource conservation, etc.)
  - `TransitionPartitioning.tla` — guard exhaustiveness, disjointness, determinism
  - `ErrorHandling.tla` — error path preservation invariants
  - `TemporalProperties.tla` — liveness and temporal ordering properties
- **Composition.tla** — two-system composition model:
  - Models two independent VSEL systems (A and B) with cross-system transfers
  - Verifies cross-system conservation, shared state consistency, and no-escape invariants
- **Git commits**: `73b354b7ed910c4a05c906b0fa4606aba387ab47` (Properties), `90e8dd4a8367c413e439fa3d298fa91334fb14ba` (Composition)

### Configuration

**MC_micro.cfg** (Properties.tla — completed successfully):

| Parameter | Value |
|-----------|-------|
| AccountIDs | {"A", "B"} |
| MaxBalance | 3 |
| MaxSeqIndex | 3 |
| DustThreshold | 1 |
| MaxFeeRateBps | 10000 |
| CHECK_DEADLOCK | FALSE |

**MC_small_completed.cfg** (Properties.tla — completed successfully, expanded state space):

| Parameter | Value |
|-----------|-------|
| AccountIDs | {"A", "B"} |
| MaxBalance | 5 |
| MaxSeqIndex | 4 |
| DustThreshold | 1 |
| MaxFeeRateBps | 10000 |
| CHECK_DEADLOCK | FALSE |

**Composition_MC.cfg** (Composition.tla — completed successfully):

| Parameter | Value |
|-----------|-------|
| AccountIDs_A | {"a1", "a2"} |
| AccountIDs_B | {"b1", "b2"} |
| MaxBalance | 5 |
| MaxSeqIndex | 2 |
| TOTAL_SUPPLY | 10 |
| CHECK_DEADLOCK | FALSE |

## Results Summary

### MC_micro.cfg — Complete Exhaustive Verification

| Metric | Value |
|--------|-------|
| Outcome | **No error found** |
| States generated | 25,780 |
| Distinct states | 20,195 |
| States left on queue | 0 (complete) |
| Search depth | 4 |
| Initial states | 16 |
| Execution time | 46 seconds |
| Fingerprint collision probability | 6.1×10⁻¹² |

**All 28 properties passed** — zero counterexamples found.

### Properties Verified

#### Core Invariants (7)

| Invariant | Status | Description |
|-----------|--------|-------------|
| StateValidity | ✅ PASS | All reachable states satisfy ValidState |
| ResourceConservation | ✅ PASS | Total(C_s) = Total(C_s') + Δ_fees |
| TraceResourceConservation | ✅ PASS | Resource conservation across full traces |
| GuardExhaustiveness | ✅ PASS | Every (state, input) handled by exactly one class |
| GuardDisjointness | ✅ PASS | No (state, input) triggers two classes |
| TransitionDeterminism | ✅ PASS | Apply produces unique result |
| DerivedConsistency | ✅ PASS | D = Derive(C) after every transition |

#### Supporting Invariants (12)

| Invariant | Status | Description |
|-----------|--------|-------------|
| TypeOK | ✅ PASS | Type invariant |
| T_no_revert | ✅ PASS | No state reversion |
| T_causal | ✅ PASS | Causal ordering of transitions |
| T_complete | ✅ PASS | Trace completeness |
| E_cost | ✅ PASS | Economic cost invariant |
| G_solvency | ✅ PASS | Global solvency |
| G_dust | ✅ PASS | Dust threshold enforcement |
| AllErrorPathsPreserveState | ✅ PASS | Error paths preserve state |
| ErrorPathConservation | ✅ PASS | Error paths conserve resources |
| ErrorPathDerivedConsistency | ✅ PASS | Error paths maintain derived consistency |
| PriorityCorrectness | ✅ PASS | Transition priority ordering |
| NoopIsCatchAll | ✅ PASS | Noop handles all unmatched inputs |

#### Temporal State Predicates (7)

| Property | Status | Description |
|----------|--------|-------------|
| NoRollback | ✅ PASS | No state rollback |
| CausalOrdering | ✅ PASS | Causal ordering maintained |
| NoHiddenTransitions | ✅ PASS | No hidden state transitions |
| EventualProgress | ✅ PASS | System makes progress |
| BoundedTraceLength | ✅ PASS | Trace length bounded |
| TraceMonotonic | ✅ PASS | Trace indices monotonically increase |
| CommitmentProgression | ✅ PASS | Commitments progress forward |

#### True Temporal Properties (2)

| Property | Status | Description |
|----------|--------|-------------|
| NoRollbackTemporal | ✅ PASS | [][¬Rollback]_vars |
| CausalOrderingTemporal | ✅ PASS | [][CausalOrder]_vars |

### MC_small_completed.cfg — Expanded Exhaustive Verification

MC_small_completed.cfg increases MaxBalance from 3→5 and MaxSeqIndex from 3→4 (same 2
accounts) to explore a 63.5x larger state space than MC_micro while remaining tractable.

| Metric | Value |
|--------|-------|
| Outcome | **No error found** |
| States generated | 1,829,910 |
| Distinct states | 1,282,043 |
| States left on queue | 0 (complete) |
| Search depth | 5 |
| Initial states | 36 |
| Execution time | 6 minutes 21 seconds |
| Fingerprint collision probability (calculated) | 3.8×10⁻⁸ |
| Fingerprint collision probability (actual) | 5.3×10⁻⁷ |

**All 28 properties passed** — zero counterexamples found across 1.28 million distinct states.

This represents a 63.5x expansion over MC_micro's 20,195 distinct states. The wider
balance range (0–5 vs 0–3) exercises more arithmetic edge cases in resource conservation,
solvency, and dust threshold invariants. The deeper trace depth (MaxSeqIndex=4 vs 3)
explores longer transition sequences, providing stronger evidence for temporal properties.

### Composition_MC.cfg — Complete Exhaustive Verification

| Metric | Value |
|--------|-------|
| Outcome | **No error found** |
| States generated | 126,218 |
| Distinct states | 7,154 |
| States left on queue | 0 (complete) |
| Search depth | 4 |
| Initial states | 146 |
| Execution time | 3 seconds |
| Fingerprint collision probability | 4.6×10⁻¹¹ |

**All 5 composition invariants passed** — zero counterexamples found.

#### Composition Invariants (5)

| Invariant | Status | Description |
|-----------|--------|-------------|
| TypeOK | ✅ PASS | Both systems remain well-typed (balances, supplies, indices) |
| CrossSystemConservation | ✅ PASS | total_supply_a + total_supply_b = TOTAL_SUPPLY (CI-1) |
| SharedStateConsistency | ✅ PASS | Shared state value is well-typed (CI-2) |
| NoCompositionEscape | ✅ PASS | Both systems remain valid with structural validity (CI-3) |
| AllCompositionInvariants | ✅ PASS | Conjunction of all composition invariants |

#### Composition Model Details

The Composition.tla specification models two independent VSEL systems (A and B) interacting
through cross-system transfers and shared state. Six transition types are modeled:

1. **DoTransfer_A** — internal transfer within system A (preserves total_supply_a)
2. **DoTransfer_B** — internal transfer within system B (preserves total_supply_b)
3. **CrossTransfer_AtoB** — atomic cross-system transfer A→B (debits A, credits B)
4. **CrossTransfer_BtoA** — atomic cross-system transfer B→A (debits B, credits A)
5. **UpdateSharedState_A** — system A updates shared storage
6. **UpdateSharedState_B** — system B updates shared storage

Cross-system transfers atomically debit one system and credit the other, preserving the
global conservation invariant `total_supply_a + total_supply_b = TOTAL_SUPPLY`. Internal
transfers preserve each system's individual total supply. The model verifies that no
sequence of transitions can violate conservation, type safety, or structural validity.

## Scalability Analysis

### State Space Growth Model

The VSEL TLA+ specification's state space grows super-exponentially with both account
count and balance range. The following table summarizes all configurations tested:

| Config | Accounts | MaxBalance | MaxSeqIndex | Distinct States | Time | Outcome |
|--------|----------|------------|-------------|-----------------|------|---------|
| MC_micro | 2 | 3 | 3 | 20,195 | 46s | ✅ Complete |
| MC_small_completed | 2 | 5 | 4 | 1,282,043 | 6m 21s | ✅ Complete |
| MC_small | 3 | 10 | 5 | 4,999,194+ | 76+ min | ❌ Intractable |
| MC_medium | 5 | 100 | 5 | — | — | ❌ Intractable (initial states) |

**Key observations**:
- Increasing MaxBalance from 3→5 (same accounts, +1 depth) caused **63.5x** state growth
- Adding a third account with MaxBalance=10 caused state space explosion beyond 5M states
- MC_medium could not even finish computing initial states within 120 seconds — with 5
  accounts and MaxBalance=100, the initial state space is (101)⁵ ≈ 10.5 billion balance
  combinations

### MC_small.cfg — Intractable

MC_small.cfg (3 accounts, MaxBalance=10, MaxSeqIndex=5) was attempted but proved
intractable for exhaustive model checking:

| Metric | Value |
|--------|-------|
| States generated (before termination) | 9,325,554 |
| Distinct states (before termination) | 4,999,194 |
| States remaining on queue | 4,843,078 |
| Runtime before termination | 76+ minutes |
| Outcome | **Did not complete** |

Multiple strategies were attempted:
- **BFS** (default): 9.3M+ states in 76 minutes, queue still growing
- **DFID** (depth-first iterative deepening): also intractable
- **Simulation mode**: random sampling, not exhaustive
- **Reduced configs**: various parameter reductions attempted

### MC_medium.cfg — Intractable (Initial State Computation)

MC_medium.cfg (5 accounts, MaxBalance=100, MaxSeqIndex=5) was attempted but could not
even finish computing initial states:

| Metric | Value |
|--------|-------|
| Initial states computed (before timeout) | 1,024+ |
| Runtime before timeout | 120 seconds |
| Outcome | **Could not finish computing initial states** |

With 5 accounts and MaxBalance=100, the initial state space alone is (101)⁵ ≈ 10.5
billion balance combinations. This is vastly beyond practical model checking limits.
The MC_medium configuration is documented as a target for future hardware advances or
symbolic model checking approaches.

### Growth Analysis

The state space grows combinatorially with account count and balance range. Moving from
2 accounts with MaxBalance=3 (20K states) to 2 accounts with MaxBalance=5 (1.28M states)
shows a 63.5x growth factor. Adding a third account with MaxBalance=10 causes a state
space explosion exceeding practical limits. The combinatorial explosion is driven by:

1. **Balance combinations**: grow as (MaxBalance+1)^|AccountIDs|
2. **Trace depth**: grows with MaxSeqIndex
3. **Transition fan-out**: grows with account count × balance range

### Why Model Checking Results Are Valid

1. **Complete exhaustive exploration at two scales**: TLC explored all 20,195 distinct
   reachable states under MC_micro and all 1,282,043 distinct reachable states under
   MC_small_completed — both with 0 states remaining on queue. The entire state space
   was checked at both parameter scales.

2. **Same specification, same properties**: Both configs check the identical TLA+
   specification (Properties.tla) and all 28 properties. The only difference is the
   parameter instantiation.

3. **Parameterized specification**: The VSEL TLA+ specification is parameterized over
   AccountIDs, MaxBalance, and MaxSeqIndex. All invariants and temporal properties are
   universally quantified over these parameters. Properties holding across 1.28 million
   states (63.5x more than the baseline) provides strong evidence of correctness.

4. **Acceptable fingerprint collision risk**: The probability that TLC missed a state due
   to fingerprint collision is 6.1×10⁻¹² (MC_micro) and 5.3×10⁻⁷ (MC_small_completed),
   providing high confidence in completeness within the explored parameter spaces.

5. **Complementary verification**: TLC model checking complements the Lean 4 theorem
   proofs (which are parameter-independent) and Rust property-based tests (which test
   with randomized large values). Together, these three verification layers provide
   defense in depth.

## Evidence Files

| File | Description |
|------|-------------|
| `properties_micro_evidence.json` | Structured JSON evidence for MC_micro.cfg run (Properties.tla) — 20,195 distinct states |
| `properties_expanded_evidence.json` | Structured JSON evidence for MC_small_completed.cfg run (Properties.tla) — 1,282,043 distinct states |
| `composition_evidence.json` | Structured JSON evidence for Composition_MC.cfg run (Composition.tla) |
| `README.md` | This document — methodology and results |

## Requirements Traceability

| Requirement | Acceptance Criterion | Evidence |
|-------------|---------------------|----------|
| R5.1 | Execute TLC against Properties.tla, archive output | `properties_micro_evidence.json`, `properties_expanded_evidence.json` |
| R5.2 | Execute TLC against Composition.tla, archive output | `composition_evidence.json` |
| R5.3 | Verify 6 core invariants pass | All 7 core invariants PASS at both MC_micro and MC_small_completed scales |
| R5.4 | Verify supporting invariants pass | All 12 supporting invariants PASS at both scales |
| R5.5 | Verify temporal properties pass | All 9 temporal properties PASS at both scales |
| R5.6 | Execute with expanded config, document state space | `properties_expanded_evidence.json` — 1.28M states (63.5x MC_micro); MC_medium documented as intractable |
| R5.7 | Store results as structured audit evidence | All evidence files with required fields |

## Reproduction

To reproduce the MC_micro verification (Properties.tla):

```bash
cd tla/
java -jar tla2tools.jar -workers auto Properties -config MC_micro.cfg
```

Expected runtime: ~46 seconds on a 14-core machine with 4GB heap.

To reproduce the MC_small_completed expanded verification (Properties.tla):

```bash
cd tla/
java -XX:+UseParallelGC -Xmx4g -jar tla2tools.jar -config MC_small_completed.cfg Properties.tla -workers auto -metadir /tmp/tlc_expanded
```

Expected runtime: ~6 minutes on a 14-core machine with 4GB heap.

To reproduce the Composition verification (Composition.tla):

```bash
cd tla/
java -XX:+UseParallelGC -Xmx4g -jar tla2tools.jar -config Composition_MC.cfg Composition.tla -workers auto -metadir /tmp/tlc_composition
```

Expected runtime: ~3 seconds on a 14-core machine with 4GB heap.
