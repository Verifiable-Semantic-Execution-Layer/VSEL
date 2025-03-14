---- MODULE Invariants ----
(*
  VSEL Invariant Definitions — TLA+ behavioral model.

  Defines all invariant predicates grouped by category:
    - Local invariants (per transition)
    - Global invariants (per state)
    - Temporal invariants (over traces)
    - Economic invariants (per state)

  Derived from: INVARIANTS.md, ECONOMIC_INVARIANTS.md,
  FORMAL_SPECIFICATION.md §3.
  Requirements: 14.1, 14.2, 14.3, 14.4
*)
EXTENDS StateMachine

\* =======================================================================
\* LOCAL INVARIANTS — checked on every transition (pre, input, post)
\* Mirrors: protocol/crates/vsel-invariants/src/local.rs
\* =======================================================================

\* L_state: Pre/post validity — both pre and post states must be valid.
\* In the TLA+ model, validity means balances are non-negative and
\* total_supply is consistent.
L_state ==
    /\ \A a \in AccountIDs : accounts[a].balance >= 0
    /\ total_supply >= 0

\* L_cons: Resource conservation — sum of all account balances equals
\* total_supply in the current state.
L_cons == SumBalances = total_supply

\* L_bounded: Bounded mutation — derived state must be consistent with
\* canonical state. D = Derive(C).
L_bounded == derived_root = DeriveCanonical

\* L_det: Deterministic transition — Apply is a function.
\* In TLA+, this is structural: the Next relation is defined functionally
\* per class. We check it indirectly via TypeOK + other invariants.
\* (Stated for documentation; not separately checkable in TLC.)

\* All local invariants combined.
LocalInvariantsHold ==
    /\ L_state
    /\ L_cons
    /\ L_bounded

\* =======================================================================
\* GLOBAL INVARIANTS — checked on every reachable state
\* Mirrors: protocol/crates/vsel-invariants/src/global.rs
\* =======================================================================

\* G_valid: State validity — ValidState(s) must hold.
\* Combines canonical validity, derived consistency, environment, metadata.
G_valid ==
    /\ \A a \in AccountIDs : accounts[a].balance >= 0
    /\ total_supply >= 0
    /\ derived_root = DeriveCanonical

\* G_struct: Structural integrity — all account balances sum to total_supply.
G_struct == SumBalances = total_supply

\* G_commit: Commitment consistency — D = Derive(C).
G_commit == derived_root = DeriveCanonical

\* G_mono: Monotonic metadata — genesis has zero commitment,
\* non-genesis has non-zero commitment.
G_mono ==
    IF seq_index = 0
    THEN prev_commitment = 0
    ELSE prev_commitment > 0

\* G_env: Environment consistency — domain tag must not be zero.
G_env == domain_tag > 0

\* All global invariants combined.
GlobalInvariantsHold ==
    /\ G_valid
    /\ G_struct
    /\ G_commit
    /\ G_mono
    /\ G_env

\* =======================================================================
\* TEMPORAL INVARIANTS — checked over traces
\* Mirrors: protocol/crates/vsel-invariants/src/temporal.rs
\* =======================================================================

\* T_valid: Trace validity — all states in the trace must be valid.
\* Checked as a state invariant (every reachable state is valid).
T_valid == G_valid

\* T_no_revert: No state reversion — sequence indices strictly increasing.
\* Checked as: if trace has entries, each entry's seq < current seq_index.
T_no_revert ==
    Len(trace) > 0 =>
        trace[Len(trace)].seq < seq_index

\* T_cons: Cumulative resource consistency — total_supply balance invariant
\* holds at every step of the trace.
\* Checked as a state invariant: L_cons holds in every reachable state.
T_cons == L_cons

\* T_causal: Causality preservation — timestamps non-decreasing.
\* Checked as: if trace has entries, last entry timestamp <= current.
T_causal ==
    Len(trace) > 0 =>
        trace[Len(trace)].ts <= timestamp

\* T_complete: No hidden transitions — sequence indices are contiguous.
\* Checked as: seq_index equals the length of the trace.
T_complete == seq_index = Len(trace)

\* All temporal invariants combined.
TemporalInvariantsHold ==
    /\ T_valid
    /\ T_no_revert
    /\ T_cons
    /\ T_causal
    /\ T_complete

\* =======================================================================
\* ECONOMIC INVARIANTS — checked on states
\* Mirrors: protocol/crates/vsel-invariants/src/economic.rs
\* =======================================================================

\* E_cost: Fee rate in basis points must not exceed 10000 (100%).
E_cost == fee_rate_bps <= MaxFeeRateBps

\* G_solvency: System must be solvent — sum of balances = total_supply.
G_solvency == SumBalances = total_supply

\* G_dust: No account below dust threshold (except zero balance).
G_dust ==
    \A a \in AccountIDs :
        accounts[a].balance = 0 \/ accounts[a].balance >= DustThreshold

\* All economic invariants combined.
EconomicInvariantsHold ==
    /\ E_cost
    /\ G_solvency
    /\ G_dust

\* =======================================================================
\* AGGREGATE — all invariants
\* =======================================================================

AllInvariantsHold ==
    /\ LocalInvariantsHold
    /\ GlobalInvariantsHold
    /\ TemporalInvariantsHold
    /\ EconomicInvariantsHold

====
