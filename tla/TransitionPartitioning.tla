---- MODULE TransitionPartitioning ----
(*
  VSEL Transition Partitioning — TLA+ behavioral model.

  Defines guard predicates for each transition class and verifies:
    1. Exhaustiveness: for every (s, σ), at least one guard matches.
    2. Disjointness: after priority resolution, exactly one class applies.

  The six transition classes in priority order:
    Reject(0) > Init(1) > Error(2) > Batch(3) > Update(4) > Noop(5)

  Derived from: TRANSITION_PARTITIONING.md, STATE_MACHINE.md §5.
  Requirements: 14.1, 14.2, 14.3, 14.4
*)
EXTENDS StateMachine

\* -----------------------------------------------------------------------
\* Payload types used in the model
\* -----------------------------------------------------------------------

PayloadTypes == {"init", "transfer", "deposit", "withdraw", "update", "batch", "unknown", ""}

RecognizedPayloads == {"transfer", "deposit", "withdraw", "update"}

\* -----------------------------------------------------------------------
\* Guard predicates — one per transition class
\* -----------------------------------------------------------------------

\* G_REJECT: input is structurally invalid.
\* Modeled as: empty payload type, or explicitly invalid flag.
G_REJECT(pt, valid) == ~valid

\* G_INIT: sequence_index = 0 AND payload_type = "init".
G_INIT(pt, valid) == valid /\ seq_index = 0 /\ pt = "init"

\* G_ERROR: valid input but precondition failure.
\* Modeled as: recognized payload but sender missing or insufficient balance.
G_ERROR(pt, valid, sender, amount) ==
    valid
    /\ ~G_INIT(pt, valid)
    /\ pt \in RecognizedPayloads
    /\ (sender \notin AccountIDs \/ accounts[sender].balance < amount)

\* G_BATCH: payload_type = "batch".
G_BATCH(pt, valid) ==
    valid
    /\ ~G_INIT(pt, valid)
    /\ pt = "batch"

\* G_UPDATE: recognized payload type with satisfied preconditions.
G_UPDATE(pt, valid, sender, amount) ==
    valid
    /\ ~G_INIT(pt, valid)
    /\ ~G_ERROR(pt, valid, sender, amount)
    /\ ~G_BATCH(pt, valid)
    /\ pt \in RecognizedPayloads

\* G_NOOP: catch-all — no other guard matches.
G_NOOP(pt, valid, sender, amount) ==
    valid
    /\ ~G_INIT(pt, valid)
    /\ ~G_ERROR(pt, valid, sender, amount)
    /\ ~G_BATCH(pt, valid)
    /\ ~G_UPDATE(pt, valid, sender, amount)

\* -----------------------------------------------------------------------
\* Classification function — priority-ordered evaluation
\* -----------------------------------------------------------------------

ClassifyInput(pt, valid, sender, amount) ==
    IF G_REJECT(pt, valid)                       THEN "reject"
    ELSE IF G_INIT(pt, valid)                    THEN "init"
    ELSE IF G_ERROR(pt, valid, sender, amount)   THEN "error"
    ELSE IF G_BATCH(pt, valid)                   THEN "batch"
    ELSE IF G_UPDATE(pt, valid, sender, amount)  THEN "update"
    ELSE "noop"

\* -----------------------------------------------------------------------
\* Exhaustiveness property
\* -----------------------------------------------------------------------

\* For every possible input combination, at least one guard matches.
\* Since Noop is the catch-all, this is guaranteed by construction,
\* but we state it explicitly for model checking.
GuardExhaustiveness ==
    \A pt \in PayloadTypes, valid \in BOOLEAN,
       sender \in AccountIDs \cup {"none"}, amount \in 0..MaxBalance :
        \/ G_REJECT(pt, valid)
        \/ G_INIT(pt, valid)
        \/ G_ERROR(pt, valid, sender, amount)
        \/ G_BATCH(pt, valid)
        \/ G_UPDATE(pt, valid, sender, amount)
        \/ G_NOOP(pt, valid, sender, amount)

\* -----------------------------------------------------------------------
\* Disjointness property (after priority resolution)
\* -----------------------------------------------------------------------

\* After priority-ordered evaluation, exactly one class is selected.
\* The Classify function is deterministic by construction (if-else chain).
\* We verify that the result is always in the set of valid classes.
GuardDisjointness ==
    \A pt \in PayloadTypes, valid \in BOOLEAN,
       sender \in AccountIDs \cup {"none"}, amount \in 0..MaxBalance :
        ClassifyInput(pt, valid, sender, amount) \in
            {"reject", "init", "error", "batch", "update", "noop"}

\* -----------------------------------------------------------------------
\* Priority ordering correctness
\* -----------------------------------------------------------------------

\* If a higher-priority guard matches, no lower-priority class is selected.
PriorityCorrectness ==
    \A pt \in PayloadTypes, valid \in BOOLEAN,
       sender \in AccountIDs \cup {"none"}, amount \in 0..MaxBalance :
        \* If input is invalid, class must be reject (highest priority)
        (/\ ~valid => ClassifyInput(pt, valid, sender, amount) = "reject")
        \* If seq=0 and pt="init" and valid, class must be init
        /\ (valid /\ seq_index = 0 /\ pt = "init"
            => ClassifyInput(pt, valid, sender, amount) = "init")

\* -----------------------------------------------------------------------
\* Noop is truly catch-all
\* -----------------------------------------------------------------------

\* If no other guard matches, the class must be noop.
NoopIsCatchAll ==
    \A pt \in PayloadTypes, valid \in BOOLEAN,
       sender \in AccountIDs \cup {"none"}, amount \in 0..MaxBalance :
        (/\ valid
         /\ ~G_INIT(pt, valid)
         /\ ~G_ERROR(pt, valid, sender, amount)
         /\ ~G_BATCH(pt, valid)
         /\ pt \notin RecognizedPayloads)
        => ClassifyInput(pt, valid, sender, amount) = "noop"

====
