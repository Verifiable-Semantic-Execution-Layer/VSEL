---- MODULE StateMachine ----
(*
  VSEL State Machine — TLA+ behavioral model.

  Models the labeled transition system M = (S, I, T, O) with six
  transition classes in priority order:
    Reject(0) > Init(1) > Error(2) > Batch(3) > Update(4) > Noop(5)

  Uses a small finite model (2-3 accounts, bounded values) suitable
  for TLC model checking.

  Derived from: STATE_MACHINE.md, TRANSITION_PARTITIONING.md,
  FORMAL_SPECIFICATION.md §3.
  Requirements: 14.1, 14.2, 14.3, 14.4
*)
EXTENDS Integers, Sequences, FiniteSets, TLC

\* -----------------------------------------------------------------------
\* Constants — small finite model for bounded model checking
\* -----------------------------------------------------------------------

CONSTANTS
    AccountIDs,       \* e.g. {"A", "B", "C"}
    MaxBalance,       \* e.g. 10
    MaxSeqIndex,      \* e.g. 5 — bounds the trace length
    DustThreshold,    \* e.g. 1
    MaxFeeRateBps     \* e.g. 10000

\* -----------------------------------------------------------------------
\* Variables
\* -----------------------------------------------------------------------

VARIABLES
    accounts,         \* Function: AccountIDs -> [balance: 0..MaxBalance, nonce: Nat]
    total_supply,     \* Nat — system-level total supply
    derived_root,     \* Nat — abstract hash of canonical state
    seq_index,        \* Nat — monotonically increasing sequence index
    prev_commitment,  \* Nat — 0 = zero hash, >0 = non-zero
    timestamp,        \* Nat — non-decreasing timestamp
    epoch,            \* Nat — current epoch
    domain_tag,       \* Nat — execution domain (must be > 0)
    fee_rate_bps,     \* Nat — fee rate in basis points
    trace,            \* Sequence of trace entries
    input_type,       \* Current input payload type (for observable)
    input_valid       \* Whether current input is structurally valid

vars == <<accounts, total_supply, derived_root, seq_index,
          prev_commitment, timestamp, epoch, domain_tag,
          fee_rate_bps, trace, input_type, input_valid>>

\* -----------------------------------------------------------------------
\* Helper operators
\* -----------------------------------------------------------------------

\* Sum of all account balances.
SumBalances == LET S == {accounts[a].balance : a \in AccountIDs}
               IN LET f[s \in SUBSET AccountIDs] ==
                    IF s = {} THEN 0
                    ELSE LET a == CHOOSE x \in s : TRUE
                         IN accounts[a].balance + f[s \ {a}]
                  IN f[AccountIDs]

\* Abstract Derive(C) — deterministic hash of canonical state.
\* Modeled as sum of balances * 31 + total_supply (injective for small models).
DeriveCanonical == SumBalances * 31 + total_supply

\* -----------------------------------------------------------------------
\* Transition class guards
\* -----------------------------------------------------------------------

\* G_REJECT: input is structurally invalid.
GuardReject(pt, valid) == ~valid

\* G_INIT: sequence_index = 0 AND payload_type = "init".
GuardInit(pt, valid) == valid /\ seq_index = 0 /\ pt = "init"

\* G_ERROR: valid input but precondition failure.
\* Modeled as: transfer from non-existent account or insufficient balance.
GuardError(pt, valid, sender, amount) ==
    valid
    /\ ~GuardInit(pt, valid)
    /\ pt = "transfer"
    /\ (sender \notin AccountIDs \/ accounts[sender].balance < amount)

\* G_BATCH: payload_type = "batch".
GuardBatch(pt, valid) ==
    valid
    /\ ~GuardInit(pt, valid)
    /\ pt = "batch"

\* G_UPDATE: recognized payload type with satisfied preconditions.
GuardUpdate(pt, valid, sender, amount) ==
    valid
    /\ ~GuardInit(pt, valid)
    /\ ~GuardError(pt, valid, sender, amount)
    /\ ~GuardBatch(pt, valid)
    /\ pt \in {"transfer", "deposit", "withdraw", "update"}

\* G_NOOP: catch-all — no other guard matches.
GuardNoop(pt, valid, sender, amount) ==
    valid
    /\ ~GuardInit(pt, valid)
    /\ ~GuardError(pt, valid, sender, amount)
    /\ ~GuardBatch(pt, valid)
    /\ ~GuardUpdate(pt, valid, sender, amount)


\* -----------------------------------------------------------------------
\* Classification — returns exactly one class per (state, input)
\* -----------------------------------------------------------------------

Classify(pt, valid, sender, amount) ==
    IF GuardReject(pt, valid)                    THEN "reject"
    ELSE IF GuardInit(pt, valid)                 THEN "init"
    ELSE IF GuardError(pt, valid, sender, amount) THEN "error"
    ELSE IF GuardBatch(pt, valid)                THEN "batch"
    ELSE IF GuardUpdate(pt, valid, sender, amount) THEN "update"
    ELSE "noop"

\* -----------------------------------------------------------------------
\* Transition implementations
\* -----------------------------------------------------------------------

\* REJECT — state unchanged, malformed input.
ApplyReject ==
    /\ UNCHANGED <<accounts, total_supply>>

\* INIT — initialize system with genesis state.
ApplyInit ==
    /\ total_supply' = SumBalances
    /\ UNCHANGED accounts

\* ERROR — valid input but precondition failure; state unchanged.
ApplyError ==
    /\ UNCHANGED <<accounts, total_supply>>

\* BATCH — modeled as a noop at this abstraction level.
\* Full batch semantics = sequential application (LEM-9).
ApplyBatch ==
    /\ UNCHANGED <<accounts, total_supply>>

\* UPDATE (transfer) — move amount from sender to receiver.
ApplyTransfer(sender, receiver, amount) ==
    /\ sender \in AccountIDs
    /\ receiver \in AccountIDs
    /\ sender /= receiver
    /\ accounts[sender].balance >= amount
    /\ amount > 0
    /\ accounts' = [accounts EXCEPT
         ![sender].balance  = accounts[sender].balance - amount,
         ![sender].nonce    = accounts[sender].nonce + 1,
         ![receiver].balance = accounts[receiver].balance + amount]
    /\ total_supply' = total_supply

\* UPDATE (deposit) — increase an account balance and total supply.
ApplyDeposit(target, amount) ==
    /\ target \in AccountIDs
    /\ amount > 0
    /\ accounts[target].balance + amount <= MaxBalance
    /\ total_supply + amount <= MaxBalance * Cardinality(AccountIDs)
    /\ accounts' = [accounts EXCEPT
         ![target].balance = accounts[target].balance + amount]
    /\ total_supply' = total_supply + amount

\* UPDATE (withdraw) — decrease an account balance and total supply.
ApplyWithdraw(target, amount) ==
    /\ target \in AccountIDs
    /\ amount > 0
    /\ accounts[target].balance >= amount
    /\ accounts' = [accounts EXCEPT
         ![target].balance = accounts[target].balance - amount]
    /\ total_supply' = total_supply - amount

\* NOOP — unrecognized payload; state unchanged.
ApplyNoop ==
    /\ UNCHANGED <<accounts, total_supply>>

\* -----------------------------------------------------------------------
\* Metadata update — common to all transitions
\* -----------------------------------------------------------------------

UpdateMetadata(class) ==
    /\ seq_index' = seq_index + 1
    /\ prev_commitment' = IF seq_index = 0 THEN 1 ELSE prev_commitment + 1
    /\ timestamp' = timestamp  \* non-decreasing (could increase)
    /\ epoch' = epoch
    /\ derived_root' = DeriveCanonical'
    /\ input_type' = class
    /\ input_valid' = TRUE

\* Record a trace entry.
RecordTrace(class) ==
    trace' = Append(trace, [
        index       |-> seq_index,
        class       |-> class,
        pre_supply  |-> total_supply,
        post_supply |-> total_supply',
        seq         |-> seq_index,
        ts          |-> timestamp
    ])

\* -----------------------------------------------------------------------
\* Init predicate
\* -----------------------------------------------------------------------

Init ==
    /\ accounts \in [AccountIDs -> [balance: 0..MaxBalance, nonce: {0}]]
    /\ total_supply = SumBalances
    /\ derived_root = DeriveCanonical
    /\ seq_index = 0
    /\ prev_commitment = 0   \* zero hash for genesis
    /\ timestamp = 0
    /\ epoch = 0
    /\ domain_tag = 1        \* must be non-zero
    /\ fee_rate_bps = 0
    /\ trace = <<>>
    /\ input_type = "none"
    /\ input_valid = TRUE

\* -----------------------------------------------------------------------
\* Next relation — nondeterministic choice of transition
\* -----------------------------------------------------------------------

\* Reject transition.
DoReject ==
    /\ seq_index < MaxSeqIndex
    /\ ApplyReject
    /\ UpdateMetadata("reject")
    /\ RecordTrace("reject")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Init transition (only at sequence 0).
DoInit ==
    /\ seq_index = 0
    /\ seq_index < MaxSeqIndex
    /\ ApplyInit
    /\ UpdateMetadata("init")
    /\ RecordTrace("init")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Error transition.
DoError ==
    /\ seq_index < MaxSeqIndex
    /\ ApplyError
    /\ UpdateMetadata("error")
    /\ RecordTrace("error")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Batch transition.
DoBatch ==
    /\ seq_index < MaxSeqIndex
    /\ ApplyBatch
    /\ UpdateMetadata("batch")
    /\ RecordTrace("batch")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Transfer transition.
DoTransfer ==
    /\ seq_index < MaxSeqIndex
    /\ \E sender \in AccountIDs, receiver \in AccountIDs, amount \in 1..MaxBalance :
         /\ sender /= receiver
         /\ ApplyTransfer(sender, receiver, amount)
    /\ UpdateMetadata("update")
    /\ RecordTrace("update")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Deposit transition.
DoDeposit ==
    /\ seq_index < MaxSeqIndex
    /\ \E target \in AccountIDs, amount \in 1..MaxBalance :
         ApplyDeposit(target, amount)
    /\ UpdateMetadata("update")
    /\ RecordTrace("update")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Withdraw transition.
DoWithdraw ==
    /\ seq_index < MaxSeqIndex
    /\ \E target \in AccountIDs, amount \in 1..MaxBalance :
         ApplyWithdraw(target, amount)
    /\ UpdateMetadata("update")
    /\ RecordTrace("update")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

\* Noop transition.
DoNoop ==
    /\ seq_index < MaxSeqIndex
    /\ ApplyNoop
    /\ UpdateMetadata("noop")
    /\ RecordTrace("noop")
    /\ UNCHANGED <<domain_tag, fee_rate_bps>>

Next ==
    \/ DoReject
    \/ DoInit
    \/ DoError
    \/ DoBatch
    \/ DoTransfer
    \/ DoDeposit
    \/ DoWithdraw
    \/ DoNoop

\* -----------------------------------------------------------------------
\* Specification
\* -----------------------------------------------------------------------

Spec == Init /\ [][Next]_vars

\* -----------------------------------------------------------------------
\* Type invariant
\* -----------------------------------------------------------------------

TypeOK ==
    /\ \A a \in AccountIDs :
         /\ accounts[a].balance \in 0..MaxBalance * Cardinality(AccountIDs)
         /\ accounts[a].nonce \in Nat
    /\ total_supply \in Nat
    /\ seq_index \in Nat
    /\ prev_commitment \in Nat
    /\ timestamp \in Nat
    /\ epoch \in Nat
    /\ domain_tag \in Nat \ {0}
    /\ fee_rate_bps \in 0..MaxFeeRateBps

====
