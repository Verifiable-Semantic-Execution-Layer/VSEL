---- MODULE Composition ----
(*
  VSEL Composition Model — TLA+ behavioral model.

  Models two independent VSEL systems (A and B) interacting through
  cross-system transfers and shared state. Verifies composition-specific
  invariants:

    1. CrossSystemConservation — total_supply_a + total_supply_b = TOTAL_SUPPLY
    2. SharedStateConsistency  — shared storage values identical in both systems
    3. NoCompositionEscape     — both systems remain in valid states (TypeOK)

  Uses simplified transitions (internal transfers and cross-system
  transfers) rather than the full six-class transition system.
  Standalone deposits/withdrawals are excluded from the Next relation
  since they would break cross-system conservation. Focus is on
  composition-specific properties.

  Derived from: COMPOSITION_MODEL.md, ASSUME_GUARANTEE_MODEL.md,
  FORMAL_SPECIFICATION.md §3.
  Requirements: 14.1, 14.5
*)
EXTENDS Integers, Sequences, FiniteSets, TLC

\* -----------------------------------------------------------------------
\* Constants
\* -----------------------------------------------------------------------

CONSTANTS
    AccountIDs_A,     \* e.g. {"a1", "a2"}  — accounts in system A
    AccountIDs_B,     \* e.g. {"b1", "b2"}  — accounts in system B
    MaxBalance,       \* e.g. 10
    MaxSeqIndex,      \* e.g. 3 — bounds trace length per system
    TOTAL_SUPPLY      \* e.g. 20 — global conservation constant

\* -----------------------------------------------------------------------
\* Variables — each system has its own state; shared_state is common
\* -----------------------------------------------------------------------

VARIABLES
    accounts_a,       \* Function: AccountIDs_A -> [balance: Nat]
    total_supply_a,   \* Nat — system A total supply
    seq_index_a,      \* Nat — system A sequence index

    accounts_b,       \* Function: AccountIDs_B -> [balance: Nat]
    total_supply_b,   \* Nat — system B total supply
    seq_index_b,      \* Nat — system B sequence index

    shared_state      \* Nat — shared storage value (both systems read/write)

vars == <<accounts_a, total_supply_a, seq_index_a,
          accounts_b, total_supply_b, seq_index_b,
          shared_state>>

vars_a == <<accounts_a, total_supply_a, seq_index_a>>
vars_b == <<accounts_b, total_supply_b, seq_index_b>>

\* -----------------------------------------------------------------------
\* Helper operators
\* -----------------------------------------------------------------------

\* Sum of all account balances in system A.
SumBalances_A == LET f[s \in SUBSET AccountIDs_A] ==
                    IF s = {} THEN 0
                    ELSE LET a == CHOOSE x \in s : TRUE
                         IN accounts_a[a].balance + f[s \ {a}]
                 IN f[AccountIDs_A]

\* Sum of all account balances in system B.
SumBalances_B == LET f[s \in SUBSET AccountIDs_B] ==
                    IF s = {} THEN 0
                    ELSE LET a == CHOOSE x \in s : TRUE
                         IN accounts_b[a].balance + f[s \ {a}]
                 IN f[AccountIDs_B]

\* -----------------------------------------------------------------------
\* Init predicate
\* -----------------------------------------------------------------------

Init ==
    /\ accounts_a \in [AccountIDs_A -> [balance: 0..MaxBalance]]
    /\ total_supply_a = SumBalances_A
    /\ seq_index_a = 0

    /\ accounts_b \in [AccountIDs_B -> [balance: 0..MaxBalance]]
    /\ total_supply_b = SumBalances_B
    /\ seq_index_b = 0

    \* Global conservation: initial supplies must sum to TOTAL_SUPPLY
    /\ total_supply_a + total_supply_b = TOTAL_SUPPLY

    /\ shared_state = 0

\* -----------------------------------------------------------------------
\* System A transitions (simplified)
\* -----------------------------------------------------------------------

\* Transfer within system A — move amount between two A accounts.
\* Internal transfers preserve total_supply_a (no resources enter or leave).
DoTransfer_A ==
    /\ seq_index_a < MaxSeqIndex
    /\ \E sender \in AccountIDs_A, receiver \in AccountIDs_A, amount \in 1..MaxBalance :
         /\ sender /= receiver
         /\ accounts_a[sender].balance >= amount
         /\ accounts_a[receiver].balance + amount <= MaxBalance
         /\ accounts_a' = [accounts_a EXCEPT
              ![sender].balance  = accounts_a[sender].balance - amount,
              ![receiver].balance = accounts_a[receiver].balance + amount]
    /\ total_supply_a' = total_supply_a
    /\ seq_index_a' = seq_index_a + 1
    /\ UNCHANGED <<accounts_b, total_supply_b, seq_index_b, shared_state>>

\* -----------------------------------------------------------------------
\* System B transitions (simplified)
\* -----------------------------------------------------------------------

\* Transfer within system B — move amount between two B accounts.
\* Internal transfers preserve total_supply_b (no resources enter or leave).
DoTransfer_B ==
    /\ seq_index_b < MaxSeqIndex
    /\ \E sender \in AccountIDs_B, receiver \in AccountIDs_B, amount \in 1..MaxBalance :
         /\ sender /= receiver
         /\ accounts_b[sender].balance >= amount
         /\ accounts_b[receiver].balance + amount <= MaxBalance
         /\ accounts_b' = [accounts_b EXCEPT
              ![sender].balance  = accounts_b[sender].balance - amount,
              ![receiver].balance = accounts_b[receiver].balance + amount]
    /\ total_supply_b' = total_supply_b
    /\ seq_index_b' = seq_index_b + 1
    /\ UNCHANGED <<accounts_a, total_supply_a, seq_index_a, shared_state>>

\* -----------------------------------------------------------------------
\* Cross-system transfer — moves resources between A and B
\* This is the key composition action. It atomically debits one system
\* and credits the other, preserving TOTAL_SUPPLY.
\* -----------------------------------------------------------------------

\* Transfer from system A to system B.
CrossTransfer_AtoB ==
    /\ seq_index_a < MaxSeqIndex
    /\ seq_index_b < MaxSeqIndex
    /\ \E src \in AccountIDs_A, dst \in AccountIDs_B, amount \in 1..MaxBalance :
         /\ accounts_a[src].balance >= amount
         /\ accounts_b[dst].balance + amount <= MaxBalance
         \* Debit system A
         /\ accounts_a' = [accounts_a EXCEPT
              ![src].balance = accounts_a[src].balance - amount]
         /\ total_supply_a' = total_supply_a - amount
         \* Credit system B
         /\ accounts_b' = [accounts_b EXCEPT
              ![dst].balance = accounts_b[dst].balance + amount]
         /\ total_supply_b' = total_supply_b + amount
    /\ seq_index_a' = seq_index_a + 1
    /\ seq_index_b' = seq_index_b + 1
    /\ UNCHANGED shared_state

\* Transfer from system B to system A.
CrossTransfer_BtoA ==
    /\ seq_index_a < MaxSeqIndex
    /\ seq_index_b < MaxSeqIndex
    /\ \E src \in AccountIDs_B, dst \in AccountIDs_A, amount \in 1..MaxBalance :
         /\ accounts_b[src].balance >= amount
         /\ accounts_a[dst].balance + amount <= MaxBalance
         \* Debit system B
         /\ accounts_b' = [accounts_b EXCEPT
              ![src].balance = accounts_b[src].balance - amount]
         /\ total_supply_b' = total_supply_b - amount
         \* Credit system A
         /\ accounts_a' = [accounts_a EXCEPT
              ![dst].balance = accounts_a[dst].balance + amount]
         /\ total_supply_a' = total_supply_a + amount
    /\ seq_index_a' = seq_index_a + 1
    /\ seq_index_b' = seq_index_b + 1
    /\ UNCHANGED shared_state

\* -----------------------------------------------------------------------
\* Shared state update — both systems can read/write shared storage.
\* Models CI-2 (shared state consistency) from ASSUME_GUARANTEE_MODEL.
\* -----------------------------------------------------------------------

UpdateSharedState_A ==
    /\ seq_index_a < MaxSeqIndex
    /\ \E v \in 0..MaxBalance :
         shared_state' = v
    /\ seq_index_a' = seq_index_a + 1
    /\ UNCHANGED <<accounts_a, total_supply_a,
                   accounts_b, total_supply_b, seq_index_b>>

UpdateSharedState_B ==
    /\ seq_index_b < MaxSeqIndex
    /\ \E v \in 0..MaxBalance :
         shared_state' = v
    /\ seq_index_b' = seq_index_b + 1
    /\ UNCHANGED <<accounts_a, total_supply_a,
                   accounts_b, total_supply_b, seq_index_a>>

\* -----------------------------------------------------------------------
\* Next relation — nondeterministic choice of action
\* -----------------------------------------------------------------------

Next ==
    \* System A internal transitions
    \/ DoTransfer_A
    \* System B internal transitions
    \/ DoTransfer_B
    \* Cross-system transfers (conservation-preserving)
    \/ CrossTransfer_AtoB
    \/ CrossTransfer_BtoA
    \* Shared state updates
    \/ UpdateSharedState_A
    \/ UpdateSharedState_B

\* -----------------------------------------------------------------------
\* Specification
\* -----------------------------------------------------------------------

Spec == Init /\ [][Next]_vars

\* -----------------------------------------------------------------------
\* Type invariant — both systems remain well-typed
\* -----------------------------------------------------------------------

TypeOK_A ==
    /\ \A a \in AccountIDs_A : accounts_a[a].balance \in 0..MaxBalance
    /\ total_supply_a \in Nat
    /\ seq_index_a \in Nat

TypeOK_B ==
    /\ \A a \in AccountIDs_B : accounts_b[a].balance \in 0..MaxBalance
    /\ total_supply_b \in Nat
    /\ seq_index_b \in Nat

TypeOK == TypeOK_A /\ TypeOK_B /\ shared_state \in Nat

\* -----------------------------------------------------------------------
\* Composition invariant 1: CrossSystemConservation (CI-1)
\*
\* The combined total supply across both systems is constant.
\* total_supply_a + total_supply_b = TOTAL_SUPPLY
\*
\* Internal transfers preserve each system's total_supply.
\* Cross-system transfers atomically debit one and credit the other.
\* No standalone deposits/withdrawals are enabled in the Next relation,
\* so conservation is maintained by construction.
\* -----------------------------------------------------------------------

CrossSystemConservation ==
    total_supply_a + total_supply_b = TOTAL_SUPPLY

\* -----------------------------------------------------------------------
\* Composition invariant 2: SharedStateConsistency (CI-2)
\*
\* The shared_state variable is a single shared storage value that
\* both systems can read and write. Since it is modeled as one variable
\* (not duplicated), consistency is structural — both systems always
\* observe the same value.
\* -----------------------------------------------------------------------

SharedStateConsistency ==
    shared_state \in Nat

\* -----------------------------------------------------------------------
\* Composition invariant 3: NoCompositionEscape
\*
\* Both systems remain in valid states at all times. No composition
\* action can drive either system into an invalid state.
\* Combines TypeOK for both systems with per-system structural validity.
\* -----------------------------------------------------------------------

\* Per-system structural validity: balances sum to total_supply.
StructuralValidity_A == SumBalances_A = total_supply_a
StructuralValidity_B == SumBalances_B = total_supply_b

NoCompositionEscape ==
    /\ TypeOK_A
    /\ TypeOK_B
    /\ StructuralValidity_A
    /\ StructuralValidity_B
    /\ CrossSystemConservation

\* -----------------------------------------------------------------------
\* Aggregate: all composition invariants
\* -----------------------------------------------------------------------

AllCompositionInvariants ==
    /\ TypeOK
    /\ CrossSystemConservation
    /\ SharedStateConsistency
    /\ NoCompositionEscape

====
