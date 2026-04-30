---- MODULE Properties_TTrace_1777476376 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, Properties

_expression ==
    LET Properties_TEExpression == INSTANCE Properties_TEExpression
    IN Properties_TEExpression!expression
----

_trace ==
    LET Properties_TETrace == INSTANCE Properties_TETrace
    IN Properties_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        prev_commitment = (5)
        /\
        trace = (<<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 1, ts |-> 0, index |-> 1], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 2, ts |-> 0, index |-> 2], [class |-> "noop", pre_supply |-> 9, post_supply |-> 9, seq |-> 3, ts |-> 0, index |-> 3], [class |-> "reject", pre_supply |-> 9, post_supply |-> 9, seq |-> 4, ts |-> 0, index |-> 4]>>)
        /\
        total_supply = (9)
        /\
        input_valid = (TRUE)
        /\
        input_type = ("reject")
        /\
        epoch = (0)
        /\
        accounts = ([A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]])
        /\
        derived_root = (288)
        /\
        seq_index = (5)
        /\
        fee_rate_bps = (0)
        /\
        domain_tag = (1)
        /\
        timestamp = (0)
    )
----

_init ==
    /\ epoch = _TETrace[1].epoch
    /\ total_supply = _TETrace[1].total_supply
    /\ accounts = _TETrace[1].accounts
    /\ input_type = _TETrace[1].input_type
    /\ seq_index = _TETrace[1].seq_index
    /\ input_valid = _TETrace[1].input_valid
    /\ trace = _TETrace[1].trace
    /\ prev_commitment = _TETrace[1].prev_commitment
    /\ derived_root = _TETrace[1].derived_root
    /\ domain_tag = _TETrace[1].domain_tag
    /\ fee_rate_bps = _TETrace[1].fee_rate_bps
    /\ timestamp = _TETrace[1].timestamp
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ epoch  = _TETrace[i].epoch
        /\ epoch' = _TETrace[j].epoch
        /\ total_supply  = _TETrace[i].total_supply
        /\ total_supply' = _TETrace[j].total_supply
        /\ accounts  = _TETrace[i].accounts
        /\ accounts' = _TETrace[j].accounts
        /\ input_type  = _TETrace[i].input_type
        /\ input_type' = _TETrace[j].input_type
        /\ seq_index  = _TETrace[i].seq_index
        /\ seq_index' = _TETrace[j].seq_index
        /\ input_valid  = _TETrace[i].input_valid
        /\ input_valid' = _TETrace[j].input_valid
        /\ trace  = _TETrace[i].trace
        /\ trace' = _TETrace[j].trace
        /\ prev_commitment  = _TETrace[i].prev_commitment
        /\ prev_commitment' = _TETrace[j].prev_commitment
        /\ derived_root  = _TETrace[i].derived_root
        /\ derived_root' = _TETrace[j].derived_root
        /\ domain_tag  = _TETrace[i].domain_tag
        /\ domain_tag' = _TETrace[j].domain_tag
        /\ fee_rate_bps  = _TETrace[i].fee_rate_bps
        /\ fee_rate_bps' = _TETrace[j].fee_rate_bps
        /\ timestamp  = _TETrace[i].timestamp
        /\ timestamp' = _TETrace[j].timestamp

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("Properties_TTrace_1777476376.json", _TETrace)

=============================================================================

 Note that you can extract this module `Properties_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `Properties_TEExpression.tla` file takes precedence 
  over the module `Properties_TEExpression` below).

---- MODULE Properties_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, Properties

expression == 
    [
        \* To hide variables of the `Properties` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        epoch |-> epoch
        ,total_supply |-> total_supply
        ,accounts |-> accounts
        ,input_type |-> input_type
        ,seq_index |-> seq_index
        ,input_valid |-> input_valid
        ,trace |-> trace
        ,prev_commitment |-> prev_commitment
        ,derived_root |-> derived_root
        ,domain_tag |-> domain_tag
        ,fee_rate_bps |-> fee_rate_bps
        ,timestamp |-> timestamp
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_epochUnchanged |-> epoch = epoch'
        
        \* Format the `epoch` variable as Json value.
        \* ,_epochJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(epoch)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_epochModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].epoch # _TETrace[s-1].epoch
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE Properties_TETrace ----
\*EXTENDS IOUtils, TLC, Properties
\*
\*trace == IODeserialize("Properties_TTrace_1777476376.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE Properties_TETrace ----
EXTENDS TLC, Properties

trace == 
    <<
    ([prev_commitment |-> 0,trace |-> <<>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "none",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 0,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0]),
    ([prev_commitment |-> 1,trace |-> <<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0]>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "error",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 1,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0]),
    ([prev_commitment |-> 2,trace |-> <<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 1, ts |-> 0, index |-> 1]>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "error",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 2,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0]),
    ([prev_commitment |-> 3,trace |-> <<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 1, ts |-> 0, index |-> 1], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 2, ts |-> 0, index |-> 2]>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "error",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 3,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0]),
    ([prev_commitment |-> 4,trace |-> <<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 1, ts |-> 0, index |-> 1], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 2, ts |-> 0, index |-> 2], [class |-> "noop", pre_supply |-> 9, post_supply |-> 9, seq |-> 3, ts |-> 0, index |-> 3]>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "noop",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 4,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0]),
    ([prev_commitment |-> 5,trace |-> <<[class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 0, ts |-> 0, index |-> 0], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 1, ts |-> 0, index |-> 1], [class |-> "error", pre_supply |-> 9, post_supply |-> 9, seq |-> 2, ts |-> 0, index |-> 2], [class |-> "noop", pre_supply |-> 9, post_supply |-> 9, seq |-> 3, ts |-> 0, index |-> 3], [class |-> "reject", pre_supply |-> 9, post_supply |-> 9, seq |-> 4, ts |-> 0, index |-> 4]>>,total_supply |-> 9,input_valid |-> TRUE,input_type |-> "reject",epoch |-> 0,accounts |-> [A |-> [balance |-> 3, nonce |-> 0], B |-> [balance |-> 6, nonce |-> 0], C |-> [balance |-> 0, nonce |-> 0]],derived_root |-> 288,seq_index |-> 5,fee_rate_bps |-> 0,domain_tag |-> 1,timestamp |-> 0])
    >>
----


=============================================================================

---- CONFIG Properties_TTrace_1777476376 ----
CONSTANTS
    AccountIDs = { "A" , "B" , "C" }
    MaxBalance = 10
    MaxSeqIndex = 5
    DustThreshold = 1
    MaxFeeRateBps = 10000

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Wed Apr 29 11:26:31 CLT 2026