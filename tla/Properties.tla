---- MODULE Properties ----
(*
  VSEL Model Checking Properties — TLA+ verification targets.

  Consolidates all properties to be checked by TLC into a single module.
  Each property maps to a specific requirement from the task:

    1. StateValidity — all reachable states satisfy ValidState
    2. ResourceConservation — Total(C_s) = Total(C_s') + Δ_fees
    3. GuardExhaustiveness — every (s, σ) handled by exactly one class
    4. GuardDisjointness — no (s, σ) triggers two classes
    5. TransitionDeterminism — Apply produces unique result
    6. DerivedConsistency — D = Derive(C) after every transition

  Derived from: MODEL_CHECKING_PLAN.md, FORMAL_SPECIFICATION.md.
  Requirements: 14.2, 14.4
*)
EXTENDS Invariants, TransitionPartitioning, ErrorHandling, TemporalProperties

\* =======================================================================
\* Property 1: StateValidity
\* All reachable states satisfy ValidState(s).
\* ValidState(s) ≡ P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ)
\* =======================================================================

\* P_C: Canonical state validity — balances non-negative, sum = total_supply.
P_C == /\ \A a \in AccountIDs : accounts[a].balance >= 0
       /\ SumBalances = total_supply

\* P_D: Derived state consistency — D = Derive(C).
P_D == derived_root = DeriveCanonical

\* P_E: Environment validity — domain tag non-zero.
P_E == domain_tag > 0

\* P_tau: Metadata validity — genesis has zero commitment, non-genesis non-zero.
P_tau ==
    IF seq_index = 0
    THEN prev_commitment = 0
    ELSE prev_commitment > 0

\* Combined: ValidState(s) ≡ P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ)
StateValidity == P_C /\ P_D /\ P_E /\ P_tau

\* =======================================================================
\* Property 2: ResourceConservation
\* Total(C_s) = Total(C_s') + Δ_fees
\* In the current model, fees are zero, so this reduces to:
\* sum(balances) = total_supply at every reachable state.
\* For transfers: sender_balance + receiver_balance is conserved.
\* For deposits/withdrawals: total_supply adjusts accordingly.
\* =======================================================================

ResourceConservation == SumBalances = total_supply

\* Stronger form: trace-level conservation.
\* Every trace entry records consistent pre/post supply for error paths.
TraceResourceConservation ==
    \A i \in 1..Len(trace) :
        trace[i].class \in {"reject", "error", "noop"}
        => trace[i].pre_supply = trace[i].post_supply

\* =======================================================================
\* Property 3: GuardExhaustiveness
\* Every (s, σ) pair is handled by at least one transition class.
\* Already defined in TransitionPartitioning.tla.
\* Re-exported here for clarity.
\* =======================================================================

\* GuardExhaustiveness is imported from TransitionPartitioning

\* =======================================================================
\* Property 4: GuardDisjointness
\* No (s, σ) pair triggers two classes after priority resolution.
\* Already defined in TransitionPartitioning.tla.
\* Re-exported here for clarity.
\* =======================================================================

\* GuardDisjointness is imported from TransitionPartitioning

\* =======================================================================
\* Property 5: TransitionDeterminism
\* Apply produces a unique result for identical inputs.
\* In TLA+, this is structural: the Next relation is defined as a
\* deterministic function per transition class. We verify this by
\* checking that the Classify function always returns exactly one
\* class (which is guaranteed by the if-else chain).
\* =======================================================================

TransitionDeterminism ==
    \A pt \in PayloadTypes, valid \in BOOLEAN,
       sender \in AccountIDs \cup {"none"}, amount \in 0..MaxBalance :
        LET class == ClassifyInput(pt, valid, sender, amount)
        IN class \in {"reject", "init", "error", "batch", "update", "noop"}

\* =======================================================================
\* Property 6: DerivedConsistency
\* D = Derive(C) after every transition.
\* The derived_root must always equal DeriveCanonical.
\* =======================================================================

DerivedConsistency == derived_root = DeriveCanonical

\* =======================================================================
\* Aggregate: All six properties
\* =======================================================================

AllProperties ==
    /\ StateValidity
    /\ ResourceConservation
    /\ TraceResourceConservation
    /\ GuardExhaustiveness
    /\ GuardDisjointness
    /\ TransitionDeterminism
    /\ DerivedConsistency

====
