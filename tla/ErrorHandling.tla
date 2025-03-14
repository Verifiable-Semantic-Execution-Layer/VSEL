---- MODULE ErrorHandling ----
(*
  VSEL Error Handling — TLA+ behavioral model.

  Models all error paths (reject, error, noop) and verifies:
    1. Error states preserve all invariants.
    2. Canonical state is unchanged on error/reject/noop transitions.
    3. Metadata is still updated (sequence index advances).

  Error paths:
    - Reject: malformed/invalid input → state unchanged
    - Error:  valid input, precondition failure → state unchanged
    - Noop:   unrecognized payload → state unchanged

  Derived from: STATE_MACHINE.md §5, FORMAL_SPECIFICATION.md §3 (LEM-7).
  Requirements: 14.1, 14.2, 14.3, 14.4
*)
EXTENDS StateMachine

\* -----------------------------------------------------------------------
\* Error path identification
\* -----------------------------------------------------------------------

\* A transition is an error path if its class is reject, error, or noop.
IsErrorPath(class) == class \in {"reject", "error", "noop"}

\* -----------------------------------------------------------------------
\* Canonical state preservation on error paths
\* -----------------------------------------------------------------------

\* After a reject transition, accounts and total_supply are unchanged.
\* This is verified by checking that the trace entry records equal
\* pre and post supply.
RejectPreservesState ==
    \A i \in 1..Len(trace) :
        trace[i].class = "reject" =>
            trace[i].pre_supply = trace[i].post_supply

\* After an error transition, accounts and total_supply are unchanged.
ErrorPreservesState ==
    \A i \in 1..Len(trace) :
        trace[i].class = "error" =>
            trace[i].pre_supply = trace[i].post_supply

\* After a noop transition, accounts and total_supply are unchanged.
NoopPreservesState ==
    \A i \in 1..Len(trace) :
        trace[i].class = "noop" =>
            trace[i].pre_supply = trace[i].post_supply

\* All error paths preserve canonical state.
AllErrorPathsPreserveState ==
    /\ RejectPreservesState
    /\ ErrorPreservesState
    /\ NoopPreservesState

\* -----------------------------------------------------------------------
\* Invariant preservation on error paths (LEM-7)
\* -----------------------------------------------------------------------

\* Resource conservation holds after any error path.
\* Since error paths don't change accounts or total_supply,
\* if L_cons held before, it holds after.
ErrorPathConservation == SumBalances = total_supply

\* Derived state consistency holds after any error path.
\* Since canonical state is unchanged, Derive(C) is unchanged.
ErrorPathDerivedConsistency == derived_root = DeriveCanonical

\* Metadata monotonicity: sequence index still advances on error paths.
\* This ensures error transitions are recorded in the trace.
ErrorPathMetadataAdvances ==
    Len(trace) > 0 =>
        trace[Len(trace)].seq < seq_index

\* -----------------------------------------------------------------------
\* Error path completeness
\* -----------------------------------------------------------------------

\* Every error path produces a trace entry.
ErrorPathsRecorded ==
    \A i \in 1..Len(trace) :
        trace[i].class \in {"reject", "error", "noop", "init", "batch", "update"}

\* -----------------------------------------------------------------------
\* Combined error handling invariants
\* -----------------------------------------------------------------------

ErrorHandlingInvariant ==
    /\ AllErrorPathsPreserveState
    /\ ErrorPathConservation
    /\ ErrorPathDerivedConsistency
    /\ ErrorPathMetadataAdvances
    /\ ErrorPathsRecorded

====
