VSEL/docs/adversarial/INVARIANT_ATTACK_MATRIX.md
```

**Verifiable Semantic Execution Layer (VSEL)**

# Stage 4: Invariant Adversarial Testing — Attack Matrix

## 1. Purpose

This document presents the complete invariant attack matrix for VSEL adversarial security audit Stage 4. Where Stage 3 analyzed semantic intent attacks, Stage 4 systematically interrogates every invariant class under 14 distinct adversarial attack vectors.

The methodology is adversarial by design:

> For every invariant class, we assume an adversary whose sole objective is to violate the invariant while appearing to satisfy all verification mechanisms.

If an invariant can be violated while the proof remains valid, the invariant is illusory. If an invariant can be satisfied vacuously—true but meaningless—the specification is incomplete. If an invariant can be weakened through configuration drift, the system lacks operational integrity.

This matrix is not merely documentation. It is an attack plan against the system's own correctness claims.

---

## 2. Invariant Taxonomy

VSEL defines invariants across 16 distinct classes, each representing a distinct correctness surface. The classes are not arbitrary; they map to specific architectural boundaries, failure modes, and adversarial capabilities.

### Class Definitions

| Class | Description | Primary Failure Mode |
|-------|-------------|---------------------|
| **Safety** | Invariants ensuring nothing bad ever happens | Violation enables catastrophic state |
| **Liveness** | Invariants ensuring something good eventually happens | Violation enables indefinite blocking |
| **Authorization** | Invariants constraining who may execute | Violation enables privilege escalation |
| **Economic** | Invariants preserving economic semantics | Violation enables value extraction |
| **Governance** | Invariants constraining protocol evolution | Violation enables capture |
| **State Transition** | Invariants governing valid transitions | Violation enables invalid state reachability |
| **Temporal** | Invariants over time and sequences | Violation enables ordering attacks |
| **Ordering** | Invariants constraining execution order | Violation enables race conditions |
| **Conservation** | Invariants preserving quantities | Violation enables inflation/deflation |
| **Access Control** | Invariants constraining resource access | Violation enables unauthorized access |
| **Upgrade** | Invariants preserving correctness across changes | Violation enables malicious transformation |
| **Trace Integrity** | Invariants ensuring complete observation | Violation enables hidden execution |
| **Policy Consistency** | Invariants ensuring policy intent preservation | Violation enables policy subversion |
| **Cryptographic Binding** | Invariants ensuring cryptographic integrity | Violation enables proof forgery |
| **Cross-Domain** | Invariants across system boundaries | Violation enables composition attacks |
| **Semantic Equivalence** | Invariants ensuring meaning preservation | Violation enables semantic collapse |

---

## 3. Attack Vector Taxonomy

Each invariant class is tested against 14 attack vectors representing distinct adversarial strategies:

| Vector | Description | Adversarial Goal |
|--------|-------------|------------------|
| **V1: Bypass** | Direct circumvention | Execute forbidden action without triggering check |
| **V2: Vacuous Satisfaction** | Trivial truth | Make invariant true by making it meaningless |
| **V3: Configuration Weakening** | Parameter manipulation | Reduce invariant strength via config change |
| **V4: Reordering** | Sequence manipulation | Break invariant by changing execution order |
| **V5: Partial Execution** | Incomplete processing | Satisfy invariant on subset while violating whole |
| **V6: Concurrency** | Parallel execution | Exploit race conditions to violate invariant |
| **V7: Rollback** | State reversion | Violate temporal invariants via rollback |
| **V8: Omitted Traces** | Incomplete history | Violate by hiding transitions from observation |
| **V9: Ambiguous Semantic Mapping** | Interpretation fuzzing | Exploit mapping gaps to violate intent |
| **V10: Upgrade Exploitation** | Version manipulation | Violate invariant across protocol versions |
| **V11: Policy Drift** | Gradual weakening | Slowly erode invariant via policy changes |
| **V12: Test Passage** | Test evasion | Violate invariant while passing all tests |
| **V13: Local Verification Passage** | Local check evasion | Violate while local checks pass |
| **V14: Proof Validity Preservation** | Proof forgery | Violate invariant while proof remains valid |

---

## 4. Safety Invariants — Attack Matrix

**Definition**: Invariants ensuring "nothing bad ever happens." Safety properties are prefix-closed: once violated, always violated.

**VSEL Mapping**: L_valid, L_state, L_bounded, G_valid, G_struct, X_exec

### Attack Vector Analysis

#### V1: Bypass — Can safety invariants be bypassed?

**Attack**: Execute invalid transition via unchecked code path.

**Mechanism**: Exploit error handling path that skips validation. Error recovery transitions in `Apply(s, σ)` may produce `s_error` where `¬ValidState(s_error)`.

**Preconditions**:
- Error path exists in implementation
- Error state construction bypasses `ValidState` check
- Constraint system accepts error transitions without semantic validation

**Construction**:
1. Craft input `σ_invalid` triggering error branch
2. Verify `Apply_error(s, σ_invalid)` produces state violating `G_valid`
3. Proof verifies because error transitions underconstrained

**Observable Signal**: Error state with invalid field values accepted by verifier

**Severity**: Critical

**Mitigation**: 
- All paths through `Apply` must satisfy postcondition `ValidState(s')`
- Error states must be explicitly enumerated and validated
- Constraint system must encode error path invariants

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can safety be satisfied vacuously?

**Attack**: Empty state space makes safety trivially true.

**Mechanism**: Define `Safe(s) ≡ s ∈ ∅`. No reachable state exists, so safety holds vacuously—but system is useless.

**Preconditions**:
- Initialization produces no valid states
- Transition relation is empty
- Specification defines safety over empty set

**Construction**:
```haskell
I = ∅
T = ∅
Safe(s) = True  -- vacuously, no s to check
```

**Observable Signal**: System accepts no inputs, produces no states, "perfectly safe"

**Severity**: High

**Mitigation**: 
- Non-emptiness requirement: `∃ s ∈ Reachable(I, T)`
- Initialization must produce at least one valid state
- Test suite must verify non-trivial execution

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can safety be weakened by configuration?

**Attack**: Relax `δ_max` bound to allow arbitrary mutation.

**Mechanism**: `L_bounded` depends on parameter `δ_max`. Governance action increases `δ_max` to `|S|`, effectively removing bound.

**Preconditions**:
- `δ_max` is governance-parameterized
- No lower bound on `δ_max` in protocol
- Configuration change doesn't require safety re-verification

**Construction**:
1. Propose governance action: `δ_max ← |S|`
2. Action passes (meets governance threshold)
3. All transitions now "satisfy" bounded mutation invariant
4. Single transition can rewrite entire state

**Observable Signal**: Governance proposal to increase state mutation bounds

**Severity**: Critical

**Mitigation**:
- Hard upper bound on `δ_max` in protocol (cannot be changed)
- Configuration changes require invariant re-verification
- Safety-critical parameters immutable

**Regression Test Required**: Yes

---

#### V4: Reordering — Can safety be broken by reordering?

**Attack**: Reorder transitions to reach unsafe state via safe intermediate steps.

**Mechanism**: Individual transitions preserve safety, but sequence does not. `Safe(s) ∧ Safe(s') ∧ Safe(s'')` but `¬Safe(s''')` via accumulation.

**Preconditions**:
- Safety is not truly prefix-closed (specification error)
- Multiple transitions interact to violate safety
- Constraint system only checks per-transition safety

**Construction**:
```haskell
-- Each step safe
Apply(s0, σ1) = s1  -- Safe(s1)
Apply(s1, σ2) = s2  -- Safe(s2)
Apply(s2, σ3) = s3  -- ¬Safe(s3), but individually each step OK
```

**Observable Signal**: Safety violation after sequence of individually safe transitions

**Severity**: Critical

**Mitigation**:
- Prove safety is prefix-closed: `Safe(s) ∧ (s,σ,s') ∈ T ⟹ Safe(s')`
- Temporal safety invariants: `□Safe(τ)`
- Model checking for safety violation sequences

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can safety be broken by partial execution?

**Attack**: Execute transition partially, leaving state in inconsistent intermediate form.

**Mechanism**: Atomic transaction partially executes before failure. Recovery leaves state partially modified, violating `G_struct`.

**Preconditions**:
- Transaction spans multiple state modifications
- Failure recovery doesn't roll back all modifications
- Constraint system treats partial state as valid

**Construction**:
1. Begin multi-step transaction `T = [m1, m2, m3]`
2. Execute `m1` (modifies field A)
3. `m2` fails (insufficient resource for field B)
4. Recovery keeps `m1` modification, leaves field B unchanged
5. Result: state where A modified, B stale—structural invariant violated

**Observable Signal**: Inconsistent state after partial transaction failure

**Severity**: Critical

**Mitigation**:
- Atomicity enforcement: all-or-nothing semantics
- State snapshots before transaction
- Constraint encoding of atomic operations

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can safety be broken by concurrency?

**Attack**: Interleave transitions to violate safety through race condition.

**Mechanism**: Concurrent execution of `Apply(s, σ1)` and `Apply(s, σ2)` produces interleaving where safety invariant broken.

**Preconditions**:
- Concurrent execution model
- Shared state access
- No proper isolation mechanisms

**Construction**:
```
Thread 1: Read balance_A = 100
Thread 2: Read balance_A = 100
Thread 1: Write balance_A = 50 (spent 50)
Thread 2: Write balance_A = 50 (spent 50, based on stale read)
Result: balance_A = 50, but 100 total spent—conservation violated
```

**Observable Signal**: State inconsistent with transaction log

**Severity**: Critical

**Mitigation**:
- Deterministic ordering: VSEL's sequential execution model
- State locking during transitions
- Constraint system enforces sequential semantics

**Regression Test Required**: Yes

---

#### V7: Rollback — Can safety be broken by rollback?

**Attack**: Roll back to previous state violating monotonicity requirements.

**Mechanism**: `T_no_revert` requires `¬∃ i < j: s_i = s_j ∧ rollback(i,j)`. Rollback violates this.

**Preconditions**:
- State reversion mechanism exists
- Rollback not prevented by protocol
- Constraint system accepts rolled-back traces

**Construction**:
1. Execute trace `τ = [s0, s1, s2]`
2. System rolls back to `s1` (reverting `s2`)
3. Execute `s3` from `s1`
4. Result: `s_1` appears twice in trace with different futures—temporal violation

**Observable Signal**: Duplicate state in trace with divergent continuations

**Severity**: High

**Mitigation**:
- Append-only state history
- Cryptographic chaining preventing rollback
- `T_no_revert` enforced in constraints

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can safety be broken by omitted traces?

**Attack**: Hide transition that violates safety from trace recording.

**Mechanism**: `T_complete` requires `AllTransitionsRecorded(τ)`. Omission violates this while appearing to satisfy safety on partial trace.

**Preconditions**:
- Trace recording mechanism incomplete
- Hidden transitions modify state
- Verification only checks recorded trace

**Construction**:
1. Execute hidden transition `σ_hidden` producing `s_bad`
2. Record only legitimate transitions `τ_visible`
3. Verify `Safe(τ_visible)` — passes
4. Actual state `s_bad` violates safety

**Observable Signal**: State/Trace mismatch—state reflects unrecorded transitions

**Severity**: Critical

**Mitigation**:
- Complete trace recording mandatory
- State commitment includes full trace
- `TraceCompleteness` proof obligation

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can safety be broken by ambiguous semantic mapping?

**Attack**: Exploit mapping ambiguity to interpret unsafe state as safe.

**Mechanism**: Mapping `μ: C_c → C_f` ambiguous for certain states. Concrete state `s_c` maps to multiple formal states; one safe, one unsafe.

**Preconditions**:
- Semantic mapping non-injective
- Constraint system uses "safe" interpretation
- Execution produces "unsafe" interpretation

**Construction**:
1. Create concrete state `s_c` with ambiguous encoding
2. `μ(s_c) = {s_safe, s_unsafe}`
3. Execution targets `s_unsafe`
4. Proof uses `s_safe` interpretation
5. Safety holds in proof, violated in execution

**Observable Signal**: Same concrete state validates under different semantic interpretations

**Severity**: Critical

**Mitigation**:
- Injective semantic mapping (THM-1)
- Canonical encoding without ambiguity
- Mapping validation in verification

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can safety be broken by an upgrade?

**Attack**: Upgrade changes safety definition, retroactively invalidating previous proofs.

**Mechanism**: New version defines `Safe'` differently from `Safe`. Old proofs no longer guarantee safety under new definition.

**Preconditions**:
- Safety predicate versioned
- Old proofs accepted under new version
- No migration validation

**Construction**:
1. Prove execution under `Safe` version 1
2. Upgrade to version 2 with stricter `Safe'`
3. Execution now violates `Safe'`
4. Old proof still valid (version 1 verifier)

**Observable Signal**: Historical proofs accepted under incompatible safety definitions

**Severity**: High

**Mitigation**:
- Safety invariants immutable across upgrades
- Version-specific verification
- Proof invalidation on breaking changes

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can safety be broken by policy drift?

**Attack**: Gradual relaxation of safety requirements through "minor" policy updates.

**Mechanism**: Series of small policy changes each "clarifying" safety, collectively weakening to meaninglessness.

**Preconditions**:
- Safety defined in policy (not protocol)
- Policy update mechanism
- No cumulative impact analysis

**Construction**:
1. Initial: `Safe(s) ≡ ValidState(s) ∧ Conservation(s) ∧ EconomicValid(s)`
2. Update 1: Remove `EconomicValid` (deemed "non-safety")
3. Update 2: Relax `Conservation` epsilon to 1%
4. Update 3: Relax `ValidState` to exclude certain checks
5. Result: `Safe(s) ≡ True` for most states

**Observable Signal**: Policy changelog showing progressive relaxation

**Severity**: High

**Mitigation**:
- Safety invariants in protocol (immutable)
- Policy cannot override safety
- Mandatory safety regression tests

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can safety be broken while all tests pass?

**Attack**: Construct execution satisfying test oracle but violating safety.

**Mechanism**: Tests cover finite cases; safety violation in uncovered case.

**Preconditions**:
- Test coverage incomplete
- Safety violation in untested code path
- Property-based tests don't cover edge case

**Construction**:
1. Identify safety check in implementation
2. Find input combination not in test corpus
3. Construct input triggering safety violation
4. All existing tests pass; new execution violates safety

**Observable Signal**: Safety violation in production not caught by test suite

**Severity**: High

**Mitigation**:
- Formal verification (exhaustive, not sampled)
- Model checking of safety properties
- Mutation testing for safety checks

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can safety be broken while local verification passes?

**Attack**: Satisfy local safety check while violating global safety.

**Mechanism**: Local check `Safe_local(s)` passes, but `Safe_global(s)` fails.

**Preconditions**:
- Local verification incomplete
- Global safety depends on non-local state
- Constraint system only checks local properties

**Construction**:
1. Local state `s_local` satisfies `Safe_local`
2. Global context `s_global` makes `Safe_global` fail
3. Local verification accepts
4. Global safety violated

**Observable Signal**: Local validation passes, global invariant violated

**Severity**: Critical

**Mitigation**:
- Global safety invariants in all verification
- Cross-reference validation
- Complete state verification, not local

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can safety be broken while the proof remains valid?

**Attack**: Violate safety invariant while satisfying constraint system.

**Mechanism**: Underconstrained constraint system accepts semantically invalid witness. Safety holds in specification, not in constraints.

**Preconditions**:
- Constraint system underconstrained
- Safety not fully encoded in constraints
- Verifier accepts underconstrained proof

**Construction**:
1. Construct execution violating `Safe`
2. Find witness satisfying constraints (underconstrained)
3. Generate proof over witness
4. Proof verifies (constraints satisfied)
5. Safety violated (semantics not preserved)

**Observable Signal**: Verifiable proof for unsafe execution

**Severity**: Catastrophic

**Mitigation**:
- Constraint coverage analysis
- Semantic preservation proofs (THM-1)
- Formal verification of constraint completeness

**Regression Test Required**: Yes

---

## 5. Liveness Invariants — Attack Matrix

**Definition**: Invariants ensuring "something good eventually happens." Liveness properties are suffix-closed: once satisfied, always satisfied.

**VSEL Mapping**: Progress, termination, availability guarantees

### Attack Vector Analysis

#### V1: Bypass — Can liveness be bypassed?

**Attack**: Prevent required action from ever executing.

**Mechanism**: Infinite loop, blocking, or censorship preventing progress.

**Preconditions**:
- Execution can be blocked
- No progress guarantee mechanism
- No timeout or liveness enforcement

**Construction**:
```haskell
-- Intended: Eventually(s_good)
-- Attack: Never(s_good)
while True:
  -- do nothing, prevent progress
```

**Observable Signal**: System stuck, no progress despite valid inputs

**Severity**: Critical

**Mitigation**:
- Progress guarantees in specification
- Timeout mechanisms
- Fairness assumptions explicit

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can liveness be satisfied vacuously?

**Attack**: Define liveness over empty event set.

**Mechanism**: `Live(τ) ≡ ∃ e ∈ τ: Good(e)` where `Good` is empty set. No event can satisfy, so liveness is impossible.

**Preconditions**:
- Liveness predicate unsatisfiable
- Good events undefined or unreachable
- Specification error

**Construction**:
```haskell
Good = ∅
Live(τ) = ∃ e ∈ τ: e ∈ Good  -- Never satisfied
```

**Observable Signal**: No execution ever satisfies liveness, system always "fails" liveness check

**Severity**: High

**Mitigation**:
- Liveness achievability proof: `∃ τ: Live(τ)`
- Reachability analysis for good states
- Test demonstrating liveness satisfaction

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can liveness be weakened by configuration?

**Attack**: Extend timeout to infinity, effectively removing liveness requirement.

**Mechanism**: Liveness requires progress within `T_max`. Governance increases `T_max` to unbounded.

**Preconditions**:
- `T_max` configurable
- No upper bound enforcement
- Governance control over liveness parameters

**Construction**:
1. Current: `T_max = 100 blocks`
2. Proposal: `T_max = 2^64` (practically infinite)
3. Liveness requirement effectively removed

**Observable Signal**: Timeout parameter grows without bound

**Severity**: High

**Mitigation**:
- Hard limits on liveness timeouts
- Liveness requirements in protocol (not configurable)
- Mandatory maximum timeouts

**Regression Test Required**: Yes

---

#### V4: Reordering — Can liveness be broken by reordering?

**Attack**: Reorder events such that liveness precondition never satisfied.

**Mechanism**: Liveness requires `A` before `B`. Reorder to `B` before `A`, preventing `B`'s precondition.

**Preconditions**:
- Event ordering affects liveness
- No total order enforcement
- Reordering possible in execution

**Construction**:
```
Intended: [A, B, C] where B requires A
Attack: [B, A, C] where B fails (A not yet happened)
Result: B never succeeds, liveness fails
```

**Observable Signal**: Events executing out of dependency order

**Severity**: Critical

**Mitigation**:
- Causality enforcement: `Order(σ_i) ⇒ Order(s_i)`
- Partial order constraints in specification
- Dependency validation before execution

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can liveness be broken by partial execution?

**Attack**: Execute partial transaction that never completes, blocking liveness.

**Mechanism**: Long-running operation partially executes, never reaches completion checkpoint.

**Preconditions**:
- Operations can be partially executed
- No completion requirement
- Resource exhaustion blocking completion

**Construction**:
1. Begin complex multi-step operation
2. Consume resources on step 1
3. Insufficient resources for step 2
4. Operation hangs, never completes
5. Liveness property (eventual completion) violated

**Observable Signal**: Operations started but never completed

**Severity**: High

**Mitigation**:
- Atomic operation semantics
- Resource reservation before execution
- Timeout and cancellation mechanisms

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can liveness be broken by concurrency?

**Attack**: Concurrent execution causes deadlock, violating liveness.

**Mechanism**: Circular wait between concurrent operations prevents any from completing.

**Preconditions**:
- Concurrent resource acquisition
- Lock ordering not enforced
- Deadlock possible

**Construction**:
```
Thread 1: Acquire A, wait for B
Thread 2: Acquire B, wait for A
Result: Deadlock, neither progresses
```

**Observable Signal**: System deadlock, no progress despite activity

**Severity**: Critical

**Mitigation**:
- Deterministic execution model (VSEL sequential)
- Resource ordering invariants
- Deadlock detection and resolution

**Regression Test Required**: Yes

---

#### V7: Rollback — Can liveness be broken by rollback?

**Attack**: Rollback progress, resetting liveness counter.

**Mechanism**: Liveness requires `N` steps within window. Rollback resets progress to 0.

**Preconditions**:
- Progress tracking cumulative
- Rollback mechanism exists
- Progress can be reversed

**Construction**:
1. Execute 99 steps toward liveness goal (100 required)
2. Rollback to step 50
3. Progress reset, window expires
4. Liveness violated

**Observable Signal**: Progress counter decreasing, liveness deadline missed

**Severity**: High

**Mitigation**:
- Monotonic progress tracking
- Rollback prevention
- Liveness window independent of progress metric

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can liveness be broken by omitted traces?

**Attack**: Omit progress events from trace, making liveness unverifiable.

**Mechanism**: Liveness check requires complete trace. Hidden progress events make it appear liveness failed.

**Preconditions**:
- Progress events in trace
- Trace recording incomplete
- Liveness verification trace-dependent

**Construction**:
1. Execute 100 progress steps
2. Record only 50 in trace (omission)
3. Verify liveness: only 50 recorded, need 100
4. Liveness appears violated (actually satisfied)

**Observable Signal**: Trace/execution mismatch, liveness false negative

**Severity**: Medium

**Mitigation**:
- Complete trace recording mandatory
- Liveness verification from state, not just trace
- Progress commitments in state

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can liveness be broken by ambiguous semantic mapping?

**Attack**: Map "progress" events to multiple interpretations, some not counting toward liveness.

**Mechanism**: `ProgressEvent` mapping ambiguous. Some executions of event count as progress, some don't.

**Preconditions**:
- Progress predicate ambiguous
- Multiple valid interpretations
- Constraint system uses non-progress interpretation

**Construction**:
1. Execute event `e` intended as progress
2. `μ(e)` maps to both `Progress` and `NoProgress`
3. Proof uses `NoProgress` interpretation
4. Liveness check fails despite progress made

**Observable Signal**: Same event type accepted/rejected as progress inconsistently

**Severity**: High

**Mitigation**:
- Unambiguous progress predicates
- Event type determinism
- Semantic mapping validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can liveness be broken by an upgrade?

**Attack**: Upgrade removes liveness requirement, making previous guarantees void.

**Mechanism**: Version 1 guarantees `Eventually(X)`. Version 2 removes this guarantee. Old proofs meaningless.

**Preconditions**:
- Liveness properties versioned
- Upgrade can weaken guarantees
- Old proofs not invalidated

**Construction**:
1. Prove `Eventually(X)` under version 1
2. Upgrade to version 2 removing `X` requirement
3. System no longer obligated to provide `X`
4. Previous liveness proof meaningless

**Observable Signal**: Liveness guarantees removed in upgrade changelog

**Severity**: High

**Mitigation**:
- Liveness invariants immutable
- Upgrade cannot weaken liveness
- Backward compatibility for liveness

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can liveness be broken by policy drift?

**Attack**: Gradually redefine "progress" to include non-progress events.

**Mechanism**: Policy updates expand "progress" definition until meaningless. Any activity counts as progress.

**Preconditions**:
- Progress defined in policy
- Policy update mechanism
- Progressive weakening acceptable

**Construction**:
1. Initial: `Progress = {StateChange, Completion}`
2. Update 1: Add `Attempt` (even if failed)
3. Update 2: Add `Receipt` (just receiving message)
4. Update 3: Add `Presence` (just existing)
5. Result: Everything is "progress", liveness meaningless

**Observable Signal**: Progress definition expanding over time

**Severity**: Medium

**Mitigation**:
- Progress invariants in protocol
- Policy cannot weaken liveness
- Strict progress criteria

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can liveness be broken while all tests pass?

**Attack**: Tests verify liveness on short traces; production has long traces where liveness fails.

**Mechanism**: Liveness requires `Eventually` over potentially infinite traces. Finite tests cannot verify.

**Preconditions**:
- Liveness not formally verified
- Tests finite, liveness infinite-horizon
- Long-running execution untested

**Construction**:
1. All tests: verify `Eventually(X)` within 10 steps (pass)
2. Production: 1000 steps without `X`
3. Liveness violated in practice, not in tests

**Observable Signal**: Liveness failures in long-running production systems

**Severity**: High

**Mitigation**:
- Model checking for liveness
- Bounded model checking with large bounds
- Formal liveness proofs

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can liveness be broken while local verification passes?

**Attack**: Local node shows progress, but global system blocked.

**Mechanism**: Local liveness check passes (node making progress), but global liveness requires cross-node coordination.

**Preconditions**:
- Distributed system
- Local vs global liveness distinction
- Coordination failures possible

**Construction**:
1. Node A: continuous progress, local liveness satisfied
2. Node B: blocked, no progress
3. Global liveness requires both A and B
4. Global liveness violated despite local satisfaction

**Observable Signal**: Local metrics healthy, global system stuck

**Severity**: Critical

**Mitigation**:
- Global liveness invariants
- Cross-node progress validation
- System-wide liveness monitoring

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can liveness be broken while the proof remains valid?

**Attack**: Proof system cannot express liveness, only safety. Liveness violations undetectable in proofs.

**Mechanism**: Constraint system encodes safety but not liveness. Proofs verify safety only.

**Preconditions**:
- Constraint system safety-only
- Liveness not encoded
- Verifier accepts safety-only proofs

**Construction**:
1. Execution violates liveness (deadlock)
2. Safety invariants hold (no bad state reached)
3. Proof verifies (safety only)
4. Liveness violated, proof valid

**Observable Signal**: Verifiable proofs for deadlocked executions

**Severity**: Critical

**Mitigation**:
- Liveness encoding in constraints
- Explicit liveness proof obligations
- Fairness constraints in specification

**Regression Test Required**: Yes

---

## 6. Authorization Invariants — Attack Matrix

**Definition**: Invariants constraining which entities may execute which actions under which conditions.

**VSEL Mapping**: `CanExecute(entity, action, context)`, access predicates, permission systems

### Attack Vector Analysis

#### V1: Bypass — Can authorization be bypassed?

**Attack**: Execute action without required authorization.

**Mechanism**: Exploit unchecked code path, privilege escalation vulnerability, or authorization check bypass.

**Preconditions**:
- Authorization check in some but not all paths
- Error handling bypasses checks
- Race condition in authorization

**Construction**:
1. Identify action requiring `Auth(role_X)`
2. Find execution path without check
3. Execute action without `role_X`
4. Action succeeds, authorization bypassed

**Observable Signal**: Unauthorized actions executed successfully

**Severity**: Critical

**Mitigation**:
- Mandatory access control (all paths checked)
- Authorization at entry point only
- Formal verification of authorization completeness

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can authorization be satisfied vacuously?

**Attack**: Define authorization such that all entities have all permissions.

**Mechanism**: `Auth(e, a) ≡ True` for all `e, a`. Authorization system present but meaningless.

**Preconditions**:
- Authorization policy allows all
- Default-allow configuration
- No explicit deny rules

**Construction**:
```haskell
Auth(entity, action) = True  -- Everyone can do everything
```

**Observable Signal**: Authorization checks always pass

**Severity**: Critical

**Mitigation**:
- Default-deny authorization
- Explicit permission grants only
- Authorization completeness review

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can authorization be weakened by configuration?

**Attack**: Governance grants broad permissions, weakening authorization.

**Mechanism**: Governance action adds `wildcard` permission to all entities.

**Preconditions**:
- Authorization configurable via governance
- No permission upper bounds
- Governance can grant arbitrary permissions

**Construction**:
1. Proposal: Grant `*` permission to `*` entities
2. Vote passes
3. All authorization checks pass trivially

**Observable Signal**: Governance proposals granting broad permissions

**Severity**: Critical

**Mitigation**:
- Authorization invariants immutable
- Governance cannot grant certain permissions
- Permission bounded by protocol

**Regression Test Required**: Yes

---

#### V4: Reordering — Can authorization be broken by reordering?

**Attack**: Reorder authorization grant and action execution.

**Mechanism**: Execute action before authorization grant takes effect.

**Preconditions**:
- Authorization changes have delay
- Actions can be front-run
- Grant not atomic with execution

**Construction**:
```
Block N:   Authorization grant submitted
Block N+1: Action executed (before grant processed)
Block N+2: Grant processed
Result: Action executed without authorization
```

**Observable Signal**: Actions preceding authorization in blockchain

**Severity**: High

**Mitigation**:
- Atomic authorization grants
- Grant effective immediately
- Execution ordering with respect to grants

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can authorization be broken by partial execution?

**Attack**: Partially execute action requiring multiple authorizations, bypassing checks.

**Mechanism**: Multi-sig action partially executes with subset of signatures.

**Preconditions**:
- Multi-stage authorization
- Partial execution possible
- Stage validation incomplete

**Construction**:
1. Action requires 3-of-5 signatures
2. Submit with 2 signatures
3. Partial execution proceeds with 2 (insufficient)
4. Authorization bypassed

**Observable Signal**: Multi-sig actions executing with insufficient signatures

**Severity**: Critical

**Mitigation**:
- Atomic authorization verification
- All-or-nothing signature checking
- Threshold enforcement in constraints

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can authorization be broken by concurrency?

**Attack**: Concurrent authorization checks see stale permissions.

**Mechanism**: Authorization revoked during concurrent execution.

**Preconditions**:
- Concurrent execution
- Authorization check separate from execution
- Time-of-check vs time-of-use gap

**Construction**:
```
Time 0:   Check authorization (authorized)
Time 1:   Revoke authorization
Time 2:   Execute action (now unauthorized)
Result: Authorization revoked, action still executes
```

**Observable Signal**: Actions executing after authorization revocation

**Severity**: Critical

**Mitigation**:
- Authorization binding to execution
- Atomic check-and-execute
- Constraint system authorization enforcement

**Regression Test Required**: Yes

---

#### V7: Rollback — Can authorization be broken by rollback?

**Attack**: Rollback revokes authorization grant, invalidating executed actions.

**Mechanism**: Authorization granted, actions executed, then rollback removes grant—actions now unauthorized but already executed.

**Preconditions**:
- Rollback mechanism
- Authorization state reversible
- Executed actions not validated against historical auth

**Construction**:
1. Grant authorization to entity E
2. E executes actions A1, A2, A3
3. Rollback to before grant
4. E no longer authorized, but actions executed

**Observable Signal**: Executed actions by now-unauthorized entities

**Severity**: High

**Mitigation**:
- Authorization monotonicity
- No rollback of authorization grants
- Historical authorization validation

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can authorization be broken by omitted traces?

**Attack**: Hide authorization check failure from trace.

**Mechanism**: Failed authorization not recorded, making it appear all actions authorized.

**Preconditions**:
- Authorization failures not traced
- Trace incomplete
- Verification trace-dependent

**Construction**:
1. Attempt unauthorized action
2. Authorization fails (not recorded)
3. Trace shows only authorized actions
4. Audit passes, unauthorized activity hidden

**Observable Signal**: Authorization failures absent from trace

**Severity**: High

**Mitigation**:
- Complete authorization logging
- Authorization result in trace
- Failed authorization attempts recorded

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can authorization be broken by ambiguous semantic mapping?

**Attack**: Ambiguous role mapping allows privilege escalation.

**Mechanism**: Entity has role `R` in one mapping, `R` maps to different permissions in different contexts.

**Preconditions**:
- Role semantics ambiguous
- Context-dependent role interpretation
- Proof uses permissive interpretation

**Construction**:
1. Entity granted `admin` role (limited scope)
2. `admin` maps to `{read, write}` in specification
3. `admin` maps to `{read, write, delete}` in implementation
4. Entity deletes data, "authorized" in implementation

**Observable Signal**: Same role with different permissions in different contexts

**Severity**: Critical

**Mitigation**:
- Unambiguous role definitions
- Canonical permission mapping
- Role semantics validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can authorization be broken by an upgrade?

**Attack**: Upgrade grants additional permissions retroactively.

**Mechanism**: Version 2 redefines role `user` to include `admin` permissions. All existing users now admins.

**Preconditions**:
- Role definitions versioned
- Upgrade changes role semantics
- Retroactive permission grants

**Construction**:
1. Version 1: `user = {read}`
2. Entity granted `user` role
3. Upgrade to Version 2: `user = {read, write, delete}`
4. Entity now has unauthorized permissions

**Observable Signal**: Role permissions expanding in upgrades

**Severity**: Critical

**Mitigation**:
- Immutable role definitions
- Upgrade cannot change authorization
- Explicit permission grants only

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can authorization be broken by policy drift?

**Attack**: Gradual expansion of role permissions through "clarifying" updates.

**Mechanism**: Series of "clarifications" each adding permissions, collectively transforming roles.

**Preconditions**:
- Authorization in policy
- Policy update mechanism
- Progressive expansion acceptable

**Construction**:
1. Initial: `user = {read}`
2. Update 1: Add `write_own` (reasonable)
3. Update 2: Add `write_group` (convenient)
4. Update 3: Add `delete_own` (cleanup)
5. Update 4: Add `admin_delegate` (temporary)
6. Result: `user` now has admin capabilities

**Observable Signal**: Role permissions growing over time

**Severity**: High

**Mitigation**:
- Authorization in protocol (immutable)
- Policy cannot override authorization
- Role permission bounds

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can authorization be broken while all tests pass?

**Attack**: Tests cover authorized paths; unauthorized paths exist in production.

**Mechanism**: Authorization checks in tests, but production has additional unchecked paths.

**Preconditions**:
- Test coverage incomplete
- Production code paths not in tests
- Authorization gaps in untested code

**Construction**:
1. Tests: verify all tested paths require authorization
2. Production: additional API endpoint without authorization check
3. Endpoint used, authorization bypassed
4. All tests pass

**Observable Signal**: Unauthorized access through untested endpoints

**Severity**: Critical

**Mitigation**:
- Comprehensive path coverage analysis
- Authorization completeness proof
- Mandatory authorization at entry points

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can authorization be broken while local verification passes?

**Attack**: Local authorization check passes, but global authorization fails.

**Mechanism**: Distributed system where local node authorizes, global policy violated.

**Preconditions**:
- Distributed authorization
- Local vs global authorization distinction
- Coordination failure

**Construction**:
1. Local node authorizes action A for entity E
2. Global policy: E prohibited from A in this context
3. Action executes locally, violates global policy
4. Local verification passes

**Observable Signal**: Local authorization inconsistent with global policy

**Severity**: Critical

**Mitigation**:
- Global authorization enforcement
- Distributed authorization consensus
- Policy consistency across nodes

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can authorization be broken while the proof remains valid?

**Attack**: Authorization not encoded in constraints, bypassed in execution.

**Mechanism**: Constraint system checks data validity, not authorization. Execution bypasses authorization.

**Preconditions**:
- Authorization not in constraint system
- Verifier doesn't check authorization
- Execution diverges from proof

**Construction**:
1. Entity not authorized for action
2. Construct proof with valid data (no auth check)
3. Execute action without authorization
4. Proof verifies, authorization violated

**Observable Signal**: Verifiable proofs for unauthorized actions

**Severity**: Catastrophic

**Mitigation**:
- Authorization encoding in constraints
- Proof includes authorization witness
- Authorization verification mandatory

**Regression Test Required**: Yes

---

## 7. Economic Invariants — Attack Matrix

**Definition**: Invariants preserving economic semantics—value conservation, fair pricing, anti-manipulation.

**VSEL Mapping**: E_cost, E_leverage, E_proportionality, G_econ_valid, TE_extraction, etc.

### Attack Vector Analysis

#### V1: Bypass — Can economic invariants be bypassed?

**Attack**: Zero-cost value extraction via fee rounding.

**Mechanism**: Fee calculation rounds down to zero for small amounts. Extract value via many small transactions.

**Preconditions**:
- Fee rounding to zero
- Small transaction allowed
- No minimum fee enforcement

**Construction**:
```
Transaction amount: 1 unit
Fee rate: 0.1%
Fee: 0.1 → rounds to 0
Net cost: 0
Result: Free transactions
```

**Observable Signal**: Zero-fee transactions in trace

**Severity**: Critical

**Mitigation**:
- Minimum fee enforcement
- Fee rounding always up (ceil)
- Economic cost > 0 for value-transfer

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can economic invariants be satisfied vacuously?

**Attack**: Define economic validity as always true.

**Mechanism**: `EconomicallyValid(s) ≡ True` makes all states economically valid, regardless of actual economics.

**Preconditions**:
- Economic validity not defined
- Default true in specification
- No economic constraints

**Construction**:
```haskell
EconomicallyValid(s) = True  -- All states valid
```

**Observable Signal**: Economic violations accepted as valid

**Severity**: Critical

**Mitigation**:
- Explicit economic validity predicates
- Economic invariant enforcement
- Economic domain expert review

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can economic invariants be weakened by configuration?

**Attack**: Increase slippage tolerance to 100%, removing price protection.

**Mechanism**: `MaxSlippage` parameter increased to 1.0 (100%), allowing any price movement.

**Preconditions**:
- `MaxSlippage` configurable
- No upper bound
- Governance control over parameters

**Construction**:
1. Current: `MaxSlippage = 0.01` (1%)
2. Governance: Set `MaxSlippage = 1.0` (100%)
3. Any price movement now "valid"
4. Price manipulation uncontrolled

**Observable Signal**: Slippage parameters increasing toward 100%

**Severity**: Critical

**Mitigation**:
- Hard bounds on economic parameters
- Economic invariants immutable
- Parameter change economic impact analysis

**Regression Test Required**: Yes

---

#### V4: Reordering — Can economic invariants be broken by reordering?

**Attack**: Reorder transactions to extract MEV.

**Mechanism**: Sandwich attack: front-run victim, back-run for profit. Individual transactions valid, sequence exploits.

**Preconditions**:
- Transaction ordering influenceable
- Price impact from ordering
- Profit from ordering manipulation

**Construction**:
```
Block N:   Attacker buys (raises price)
Block N+1: Victim buys (at higher price)
Block N+2: Attacker sells (at victim-inflated price)
Result: Attacker profits from price manipulation
```

**Observable Signal**: Systematic profit from transaction ordering

**Severity**: Critical

**Mitigation**:
- TE_sandwich invariant enforcement
- Commit-reveal schemes
- Batch execution with uniform pricing

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can economic invariants be broken by partial execution?

**Attack**: Partial liquidation leaves undercollateralized position.

**Mechanism**: Liquidation partially executes, insufficient to fully collateralize position.

**Preconditions**:
- Partial liquidation possible
- No completion requirement
- Undercollateralized state acceptable

**Construction**:
1. Position requires 100 units liquidation
2. Liquidation executes 50 units
3. Position still undercollateralized
4. `E_collateral` violated

**Observable Signal**: Partial liquidations leaving bad debt

**Severity**: Critical

**Mitigation**:
- Atomic liquidation semantics
- All-or-nothing collateral restoration
- Forced full liquidation

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can economic invariants be broken by concurrency?

**Attack**: Flash loan attack via atomic exploitation across multiple protocols.

**Mechanism**: Concurrent execution across systems exploits price discrepancies atomically.

**Preconditions**:
- Atomic cross-system execution
- Price discrepancies exist
- No cross-system economic coordination

**Construction**:
```
Atomic bundle:
  1. Borrow flash loan on System A
  2. Manipulate price on System B (concurrent)
  3. Exploit price on System C (concurrent)
  4. Repay flash loan
Result: Risk-free profit from concurrent manipulation
```

**Observable Signal**: Atomic transactions spanning multiple systems

**Severity**: Critical

**Mitigation**:
- TE_flash invariant enforcement
- Cross-system economic coordination
- Atomic execution economic bounds

**Regression Test Required**: Yes

---

#### V7: Rollback — Can economic invariants be broken by rollback?

**Attack**: Rollback after economic exploitation erases losses but keeps gains.

**Mechanism**: Exploit economic invariant, capture gains, rollback to before losses.

**Preconditions**:
- Rollback mechanism exists
- Economic state reversible
- Gain/loss asymmetry in rollback

**Preconditions**:
- Rollback to pre-exploitation state
- Attacker keeps extracted value
- System left with deficit

**Observable Signal**: Value extraction followed by state rollback

**Severity**: Catastrophic

**Mitigation**:
- No economic rollback
- Value transfer irreversibility
- Settlement finality

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can economic invariants be broken by omitted traces?

**Attack**: Hide economic manipulation in incomplete trace.

**Mechanism**: Manipulative transactions omitted from trace, making extraction appear legitimate.

**Preconditions**:
- Trace recording incomplete
- Economic verification trace-dependent
- Manipulation hidden

**Construction**:
1. Execute manipulation transactions (omitted from trace)
2. Execute extraction transactions (recorded in trace)
3. Trace shows only extraction, appears legitimate
4. Economic invariants pass on partial trace

**Observable Signal**: Economic activity inconsistent with recorded trace

**Severity**: Critical

**Mitigation**:
- Complete economic trace recording
- Economic state commitments
- Trace completeness verification

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can economic invariants be broken by ambiguous semantic mapping?

**Attack**: Ambiguous price mapping allows extraction at favorable rates.

**Mechanism**: `Price(Asset)` maps to different values in different contexts. Exploit favorable mapping.

**Preconditions**:
- Price oracle ambiguous
- Multiple valid price interpretations
- Constraint system uses stale price

**Construction**:
1. Price oracle provides price `P1`
2. Implementation uses stale price `P2 < P1`
3. Attacker buys at `P2`, sells elsewhere at `P1`
4. Economic extraction via price ambiguity

**Observable Signal**: Same asset with different prices in different contexts

**Severity**: Critical

**Mitigation**:
- Canonical price oracle
- Price freshness validation
- Price mapping unambiguity proof

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can economic invariants be broken by an upgrade?

**Attack**: Upgrade changes economic parameters retroactively, enabling extraction.

**Mechanism**: Version 2 changes fee structure, enabling value extraction from Version 1 commitments.

**Preconditions**:
- Economic parameters versioned
- Upgrade changes economics
- Retroactive economic impact

**Construction**:
1. Version 1: Commit to position with fee structure F1
2. Upgrade to Version 2: fee structure F2 (favorable to attacker)
3. Attacker's position now extractable under F2
4. Economic extraction enabled by upgrade

**Observable Signal**: Economic parameter changes in upgrades affecting existing positions

**Severity**: Critical

**Mitigation**:
- Economic invariants immutable across upgrades
- Position-specific economic terms locked
- Upgrade economic impact analysis required

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can economic invariants be broken by policy drift?

**Attack**: Gradual relaxation of economic constraints through policy updates.

**Mechanism**: Series of "minor" policy adjustments collectively undermine economic security.

**Preconditions**:
- Economic policy governable
- Incremental changes acceptable
- No cumulative analysis

**Construction**:
1. Initial: strict economic controls
2. Policy 1: Relax leverage limit (10x → 20x)
3. Policy 2: Relax collateral ratio (150% → 110%)
4. Policy 3: Relax liquidation threshold (80% → 95%)
5. Result: System economically fragile

**Observable Signal**: Progressive relaxation of economic constraints

**Severity**: High

**Mitigation**:
- Economic invariants in protocol (immutable)
- Policy cannot override economic constraints
- Economic bound enforcement

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can economic invariants be broken while all tests pass?

**Attack**: Economic edge cases not in test suite exploited in production.

**Mechanism**: Tests cover "normal" economics; production encounters edge case violating invariants.

**Preconditions**:
- Test economics simplified
- Edge cases untested
- Production complexity exceeds tests

**Construction**:
1. Tests: fixed prices, small amounts, simple positions
2. Production: volatile prices, large amounts, complex positions
3. Edge case: rounding error accumulates across large position
4. Economic invariant violated, tests pass

**Observable Signal**: Economic failures in production not in tests

**Severity**: Critical

**Mitigation**:
- Property-based economic testing
- Formal economic modeling
- Chaos engineering for economic edge cases

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can economic invariants be broken while local verification passes?

**Attack**: Local economic checks pass, but global economic state violated.

**Mechanism**: Pool-level economic valid, system-level economic invalid.

**Preconditions**:
- Local economic verification only
- Global economic dependencies
- Composition failures

**Construction**:
1. Pool A: economically valid (local check)
2. Pool B: economically valid (local check)
3. Combined A+B: systemic risk from correlation
4. Global economic invariant violated

**Observable Signal**: Local pools healthy, systemic economic failure

**Severity**: Critical

**Mitigation**:
- Global economic invariant verification
- Systemic risk analysis
- Cross-pool economic constraints

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can economic invariants be broken while the proof remains valid?

**Attack**: Underconstrained economic invariants allow extraction in valid proofs.

**Mechanism**: Constraint system doesn't encode economic invariants. Extraction valid in proof.

**Preconditions**:
- Economic invariants not in constraints
- Verifier doesn't check economics
- Underconstrained system

**Construction**:
1. Construct extraction transaction
2. Economic invariants violated (underconstrained)
3. Proof verifies (constraints satisfied)
4. Extraction valid in proof system

**Observable Signal**: Verifiable proofs for economically exploitative transactions

**Severity**: Catastrophic

**Mitigation**:
- Economic invariant encoding in constraints
- Economic constraint coverage analysis
- Formal economic verification

**Regression Test Required**: Yes

---

## 8. Governance Invariants — Attack Matrix

**Definition**: Invariants constraining protocol evolution, preventing capture, ensuring decentralization.

**VSEL Mapping**: Governance thresholds, proposal validity, execution constraints

### Attack Vector Analysis

#### V1: Bypass — Can governance be bypassed?

**Attack**: Execute governance action without proper approval.

**Mechanism**: Exploit emergency powers, admin keys, or governance implementation bugs.

**Preconditions**:
- Emergency mechanisms exist
- Admin privileges not revoked
- Governance check bypassable

**Construction**:
1. Identify emergency function `emergencyUpgrade()`
2. Call with compromised admin key
3. Upgrade executes without governance vote
4. Governance bypassed

**Observable Signal**: Governance actions without corresponding proposals/votes

**Severity**: Critical

**Mitigation**:
- No admin keys in production
- Emergency powers time-bounded
- Multi-sig emergency control

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can governance be satisfied vacuously?

**Attack**: Governance exists but has no real power.

**Mechanism**: Governance can vote on cosmetic parameters only; core protocol immutable by governance.

**Preconditions**:
- Governance scope limited
- Core protocol immutable
- Governance theater

**Construction**:
```
Governance powers: {color_scheme, logo_uri, marketing_text}
Core protocol: Immutable (even by governance)
Result: Governance exists but changes nothing meaningful
```

**Observable Signal**: Governance proposals limited to cosmetic changes

**Severity**: High

**Mitigation**:
- Clear governance scope
- Meaningful governance powers
- Governance effectiveness metrics

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can governance be weakened by configuration?

**Attack**: Reduce governance threshold to enable capture.

**Mechanism**: Lower quorum requirement until small coalition can control protocol.

**Preconditions**:
- Governance parameters configurable
- Threshold reduction possible
- No minimum threshold

**Construction**:
1. Initial: 66% quorum required
2. Proposal: Reduce to 10% quorum
3. Passes (with 11% participation)
4. Now 10% can control protocol

**Observable Signal**: Declining governance thresholds

**Severity**: Critical

**Mitigation**:
- Governance parameter bounds
- Threshold increases only via high threshold
- Governance invariants immutable

**Regression Test Required**: Yes

---

#### V4: Reordering — Can governance be broken by reordering?

**Attack**: Execute proposal before voting period ends.

**Mechanism**: Proposal supposed to wait 7 days, executed immediately via reordering.

**Preconditions**:
- Execution ordering manipulable
- Time constraints not enforced
- Race condition in governance

**Construction**:
```
Block N:   Proposal submitted
Block N+1: Proposal executed (before voting period)
Block N+2: Voting period would have ended
Result: Proposal executed without full voting period
```

**Observable Signal**: Proposal execution before timelock expiry

**Severity**: Critical

**Mitigation**:
- Enforced timelocks in protocol
- Execution delay in constraints
- Time-based governance enforcement

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can governance be broken by partial execution?

**Attack**: Partially execute governance proposal, applying some changes but not others.

**Mechanism**: Multi-part proposal partially executed, leaving system in inconsistent state.

**Preconditions**:
- Complex multi-part proposals
- Partial execution possible
- No atomic governance execution

**Construction**:
1. Proposal: [Change A, Change B, Change C]
2. Execute Change A
3. Execution fails on Change B
4. Changes A applied, B and C not
5. System in inconsistent state

**Observable Signal**: Partially applied governance proposals

**Severity**: Critical

**Mitigation**:
- Atomic governance execution
- All-or-nothing proposal application
- Rollback on partial failure

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can governance be broken by concurrency?

**Attack**: Concurrent governance proposals conflict, producing invalid state.

**Mechanism**: Two proposals both modify same parameter, concurrent execution produces undefined result.

**Preconditions**:
- Concurrent proposal execution
- Shared state modification
- No conflict detection

**Construction**:
```
Proposal 1: Set parameter X = 100
Proposal 2: Set parameter X = 200
Both pass, both execute concurrently
Result: X could be 100, 200, or undefined
```

**Observable Signal**: Inconsistent parameter values after concurrent proposals

**Severity**: Critical

**Mitigation**:
- Sequential proposal execution
- Conflict detection before execution
- Proposal dependency analysis

**Regression Test Required**: Yes

---

#### V7: Rollback — Can governance be broken by rollback?

**Attack**: Rollback revokes legitimate governance action.

**Mechanism**: Governance action executed, then rolled back, as if never happened.

**Preconditions**:
- Rollback mechanism
- Governance actions reversible
- State history mutable

**Construction**:
1. Governance action A executed (upgrade)
2. System operates under new rules
3. Rollback to before A
4. Upgrade undone, but effects remain
5. System inconsistent

**Observable Signal**: Governance actions disappearing from history

**Severity**: Critical

**Mitigation**:
- Governance actions immutable
- No rollback of governance
- Governance history append-only

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can governance be broken by omitted traces?

**Attack**: Hide governance actions from audit trail.

**Mechanism**: Governance actions executed but not recorded, hiding from accountability.

**Preconditions**:
- Governance logging incomplete
- Actions can be hidden
- Audit trace-dependent

**Construction**:
1. Execute governance action
2. Omit from governance log
3. System state changes
4. No record of decision process

**Observable Signal**: State changes without governance records

**Severity**: Critical

**Mitigation**:
- Complete governance logging
- Governance events in trace
- Audit trail completeness verification

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can governance be broken by ambiguous semantic mapping?

**Attack**: Ambiguous proposal text enables unintended execution.

**Mechanism**: Proposal text maps to multiple implementations; "safe" interpretation voted on, "dangerous" interpretation executed.

**Preconditions**:
- Proposal text ambiguous
- Multiple valid interpretations
- Execution differs from voter understanding

**Construction**:
1. Proposal: "Improve system efficiency"
2. Voters interpret: Optimize algorithms
3. Implementation: Remove security checks
4. Different interpretations, voters deceived

**Observable Signal**: Proposal execution diverging from voter expectations

**Severity**: Critical

**Mitigation**:
- Formal proposal specification
- Unambiguous execution semantics
- Proposal code review before voting

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can governance be broken by an upgrade?

**Attack**: Upgrade changes governance rules to enable capture.

**Mechanism**: Version 2 governance removes checks and balances from Version 1.

**Preconditions**:
- Governance rules versioned
- Upgrade can change governance
- Self-modifying governance possible

**Construction**:
1. Version 1: Multi-sig required for upgrades
2. Upgrade to Version 2: Remove multi-sig requirement
3. Version 2: Single party can upgrade
4. Governance capture enabled

**Observable Signal**: Governance constraints weakening in upgrades

**Severity**: Catastrophic

**Mitigation**:
- Immutable governance invariants
- Upgrade cannot weaken governance
- Governance ratification requirements

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can governance be broken by policy drift?

**Attack**: Gradual centralization via "temporary" governance adjustments.

**Mechanism**: Series of "temporary" measures accumulating permanent centralization.

**Preconditions**:
- Governance policy flexible
- Emergency measures possible
- No expiration on temporary powers

**Construction**:
1. Emergency 1: Grant admin powers (30 days)
2. Emergency 2: Extend admin powers (60 days)
3. Emergency 3: Make admin permanent
4. Result: Gradual centralization

**Observable Signal**: Accumulating "temporary" governance powers

**Severity**: High

**Mitigation**:
- Governance policy immutable
- Emergency powers time-bounded and non-extensible
- Decentralization metrics

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can governance be broken while all tests pass?

**Attack**: Tests cover governance logic; edge cases in governance execution bypassed.

**Mechanism**: Governance edge case not in test suite exploited.

**Preconditions**:
- Test coverage incomplete
- Governance edge cases untested
- Production governance different from tests

**Construction**:
1. Tests: Standard governance proposals pass/fail correctly
2. Edge case: Proposal with exactly threshold votes
3. Tie-breaking logic flawed
4. Production: Wrong proposal executes
5. Tests pass, production fails

**Observable Signal**: Governance failures in edge cases not in tests

**Severity**: Critical

**Mitigation**:
- Formal governance verification
- Edge case analysis
- Property-based governance testing

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can governance be broken while local verification passes?

**Attack**: Local governance check passes, global governance violated.

**Mechanism**: Local node approves action, global governance rejects, but action executes locally.

**Preconditions**:
- Distributed governance
- Local vs global governance distinction
- Split-brain possible

**Construction**:
1. Network partition: Group A and Group B separated
2. Group A votes YES on proposal (local majority)
3. Group B votes NO on proposal (local majority)
4. Global: Proposal rejected
5. Group A executes anyway (local approval)

**Observable Signal**: Divergent governance decisions across network partitions

**Severity**: Critical

**Mitigation**:
- Consensus required for governance
- Global governance enforcement
- Partition-resistant governance

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can governance be broken while the proof remains valid?

**Attack**: Governance not encoded in constraints; malicious governance in valid proof.

**Mechanism**: Constraint system doesn't verify governance. Malicious governance actions prove valid.

**Preconditions**:
- Governance not in constraint system
- Verifier doesn't check governance
- Underconstrained system

**Construction**:
1. Execute governance action without proper process
2. Constraint system doesn't verify governance process
3. Proof verifies (constraints satisfied)
4. Governance violated, proof valid

**Observable Signal**: Verifiable proofs for improperly authorized governance actions

**Severity**: Catastrophic

**Mitigation**:
- Governance encoding in constraints
- Proof includes governance witness
- Governance verification mandatory in proofs

**Regression Test Required**: Yes

---

## 9. State Transition Invariants — Attack Matrix

**Definition**: Invariants governing valid state transitions—determinism, totality, closure.

**VSEL Mapping**: L_valid, L_det, AX-1, AX-2, SAFE-3

### Attack Vector Analysis

#### V1: Bypass — Can state transitions be bypassed?

**Attack**: Mutate state without using `Apply` function.

**Mechanism**: Direct state modification bypassing transition logic.

**Preconditions**:
- State directly modifiable
- Transition logic bypassable
- Raw state access possible

**Construction**:
```
-- Intended: s' = Apply(s, σ)
-- Attack: s' = DirectModify(s, arbitrary_changes)
-- Transition logic completely bypassed
```

**Observable Signal**: State changes not corresponding to valid transitions

**Severity**: Catastrophic

**Mitigation**:
- Immutable state transitions (only via Apply)
- State modification encapsulation
- Transition verification in constraints

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can state transitions be satisfied vacuously?

**Attack**: Allow all state changes, making transition validity meaningless.

**Mechanism**: `ValidTransition(s, s') ≡ True` allows any state change.

**Preconditions**:
- Transition validity not defined
- Default allow
- No transition constraints

**Construction**:
```haskell
ValidTransition(s, s') = True  -- Any transition valid
```

**Observable Signal**: Arbitrary state modifications accepted

**Severity**: Catastrophic

**Mitigation**:
- Strict transition validity
- Whitelist of valid transitions
- Transition derivation from specification

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can state transitions be weakened by configuration?

**Attack**: Add "transition exceptions" via configuration.

**Mechanism**: Configurable exception list allows bypassing normal transition logic.

**Preconditions**:
- Transition exceptions configurable
- No exception limits
- Governance control over exceptions

**Construction**:
1. Normal: All transitions via `Apply`
2. Config: Add exception for "emergency transitions"
3. Emergency transitions bypass `Apply`
4. Transition validity weakened

**Observable Signal**: Configurable transition exceptions

**Severity**: Critical

**Mitigation**:
- No transition exceptions
- Immutable transition logic
- Configuration cannot affect transitions

**Regression Test Required**: Yes

---

#### V4: Reordering — Can state transitions be broken by reordering?

**Attack**: Transition composition non-associative, reordering produces different results.

**Mechanism**: `Apply(s, [σ1, σ2]) ≠ Apply(Apply(s, σ1), σ2)` due to reordering.

**Preconditions**:
- Transition composition order-dependent
- No associativity proof
- Batch processing differs from sequential

**Construction**:
```
Apply(s, [σ1, σ2]) = s_A
Apply(Apply(s, σ1), σ2) = s_B
s_A ≠ s_B  -- Non-associative, reordering matters
```

**Observable Signal**: Batch vs sequential execution producing different states

**Severity**: Critical

**Mitigation**:
- Transition associativity proof
- Batch/sequential equivalence verification
- Deterministic ordering enforcement

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can state transitions be broken by partial execution?

**Attack**: Partial transition leaves state in undefined intermediate form.

**Mechanism**: Multi-step transition partially executes, intermediate state invalid.

**Preconditions**:
- Transitions multi-step
- Intermediate states exposed
- No atomicity guarantee

**Construction**:
1. Transition T = [step1, step2, step3]
2. Execute step1 (state now intermediate)
3. Fail before step2
4. State exposed: neither s nor s', something else
5. Invalid state reachable

**Observable Signal**: Invalid intermediate states observable

**Severity**: Critical

**Mitigation**:
- Atomic transition semantics
- State changes only visible after completion
- Intermediate states invalid by construction

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can state transitions be broken by concurrency?

**Attack**: Concurrent transitions produce race condition, violating determinism.

**Mechanism**: `Apply(s, σ1)` and `Apply(s, σ2)` interleave producing non-deterministic result.

**Preconditions**:
- Concurrent execution
- Shared state access
- Race condition possible

**Construction**:
```
Thread 1: Read field X
Thread 2: Read field X
Thread 1: Write X+1
Thread 2: Write X+1 (based on stale read)
Result: X incremented once, should be twice
```

**Observable Signal**: Non-deterministic state under concurrent access

**Severity**: Critical

**Mitigation**:
- Sequential execution model
- State locking during transitions
- Deterministic ordering in constraints

**Regression Test Required**: Yes

---

#### V7: Rollback — Can state transitions be broken by rollback?

**Attack**: Rollback transition after execution, violating totality.

**Mechanism**: Transition executes, then rolled back, as if never happened.

**Preconditions**:
- Rollback mechanism
- Transitions reversible
- Execution history mutable

**Construction**:
1. Execute transition T: s → s'
2. Rollback to s
3. Transition "undone" but effects may persist
4. Transition system totality violated

**Observable Signal**: Transition history mutable

**Severity**: High

**Mitigation**:
- Append-only transition history
- No rollback of committed transitions
- Irreversibility in specification

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can state transitions be broken by omitted traces?

**Attack**: Hide transitions from trace, making system appear to have different behavior.

**Mechanism**: Transitions executed but not recorded, trace shows different transition sequence.

**Preconditions**:
- Trace recording incomplete
- Transitions can be hidden
- Verification trace-dependent

**Construction**:
1. Execute transition sequence T_actual
2. Record only T_subset in trace
3. Verify against T_subset (passes)
4. Actual behavior differs from verified behavior

**Observable Signal**: State inconsistent with recorded trace

**Severity**: Critical

**Mitigation**:
- Complete trace recording mandatory
- State commitment includes full trace
- Trace completeness proof

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can state transitions be broken by ambiguous semantic mapping?

**Attack**: Ambiguous mapping makes invalid transitions appear valid.

**Mechanism**: Transition T maps to multiple formal transitions; valid and invalid versions.

**Preconditions**:
- Transition mapping ambiguous
- Multiple valid interpretations
- Constraint system uses "valid" interpretation

**Construction**:
1. Concrete transition T_c has ambiguous encoding
2. Maps to T_valid (specification) and T_invalid (implementation)
3. Implementation executes T_invalid
4. Proof uses T_valid interpretation
5. Invalid transition in execution, valid in proof

**Observable Signal**: Same transition encoding validating differently

**Severity**: Critical

**Mitigation**:
- Injective transition mapping
- Canonical transition encoding
- Mapping validation in verification

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can state transitions be broken by an upgrade?

**Attack**: Upgrade changes transition semantics, breaking existing proofs.

**Mechanism**: Version 2 changes `Apply` function, proofs from Version 1 no longer valid.

**Preconditions**:
- Transition semantics versioned
- Upgrade changes semantics
- Old proofs accepted under new version

**Construction**:
1. Prove execution under Version 1 semantics
2. Upgrade to Version 2 with different semantics
3. Same concrete execution now invalid
4. Old proof still accepted

**Observable Signal**: Pre-upgrade proofs post-verifying under different semantics

**Severity**: High

**Mitigation**:
- Immutable transition semantics
- Version-specific verification
- Proof invalidation on breaking changes

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can state transitions be broken by policy drift?

**Attack**: Gradual transition rule relaxation through policy updates.

**Mechanism**: Series of "clarifications" expanding valid transition set.

**Preconditions**:
- Transition rules in policy
- Policy update mechanism
- Progressive relaxation acceptable

**Construction**:
1. Initial: Strict transition validation
2. Policy 1: Add exception for "legacy compatibility"
3. Policy 2: Add exception for "performance optimization"
4. Policy 3: Add exception for "emergency recovery"
5. Result: Many exceptions, weak validation

**Observable Signal**: Growing list of transition exceptions

**Severity**: High

**Mitigation**:
- Transition rules in protocol (immutable)
- Policy cannot affect transitions
- Strict transition validation

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can state transitions be broken while all tests pass?

**Attack**: Untested transition paths violate invariants.

**Mechanism**: Tests cover main paths; edge case paths violate transition invariants.

**Preconditions**:
- Test coverage incomplete
- Edge case transitions untested
- Production has additional paths

**Construction**:
1. Tests: Standard transitions pass validation
2. Production: Error recovery path bypasses validation
3. Error transition produces invalid state
4. Tests pass, production fails

**Observable Signal**: Transition failures in edge cases not in tests

**Severity**: Critical

**Mitigation**:
- Complete transition coverage
- Formal verification of all paths
- Mutation testing for transition logic

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can state transitions be broken while local verification passes?

**Attack**: Local transition valid, but global transition invalid.

**Mechanism**: Local node validates transition against local state, but global state makes transition invalid.

**Preconditions**:
- Distributed state
- Local vs global state distinction
- Split-brain possible

**Construction**:
1. Local state S_local valid for transition T
2. Global state S_global (different) makes T invalid
3. Local node executes T
4. Global invariant violated

**Observable Signal**: Locally valid transitions violating global invariants

**Severity**: Critical

**Mitigation**:
- Global state validation
- Consensus before transition execution
- Cross-node transition verification

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can state transitions be broken while the proof remains valid?

**Attack**: Invalid transition accepted by underconstrained constraint system.

**Mechanism**: Constraint system doesn't fully encode transition validity.

**Preconditions**:
- Transition underconstrained
- Verifier accepts invalid transitions
- Constraint system incomplete

**Construction**:
1. Construct invalid transition T_invalid
2. Find witness satisfying constraints (underconstrained)
3. Proof verifies
4. Invalid transition in valid proof

**Observable Signal**: Verifiable proofs for invalid transitions

**Severity**: Catastrophic

**Mitigation**:
- Complete transition constraints
- Transition validity encoding
- Constraint coverage analysis

**Regression Test Required**: Yes

---

## 10. Temporal Invariants — Attack Matrix

**Definition**: Invariants over time and sequences—monotonicity, causality, eventual consistency.

**VSEL Mapping**: T_no_revert, T_causal, T_cons, G_mono

### Attack Vector Analysis

#### V1: Bypass — Can temporal invariants be bypassed?

**Attack**: Directly modify timestamp to violate monotonicity.

**Mechanism**: Set `τ_current < τ_previous` via timestamp manipulation.

**Preconditions**:
- Timestamp modifiable
- No monotonicity enforcement
- Time validation weak

**Construction**:
```
Block N:   timestamp = 1000
Block N+1: timestamp = 999 (set backwards)
Result: Monotonicity violated
```

**Observable Signal**: Non-monotonic timestamps

**Severity**: Critical

**Mitigation**:
- Monotonic timestamp enforcement
- Time validation in constraints
- Timestamp integrity proofs

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can temporal invariants be satisfied vacuously?

**Attack**: Define temporal properties over empty trace.

**Mechanism**: `Temporal(τ) ≡ True` for empty trace; no temporal properties actually checked.

**Preconditions**:
- Temporal invariants not defined
- Default true
- Trace can be empty

**Construction**:
```haskell
Temporal(τ) = True  -- All traces temporally valid
```

**Observable Signal**: No temporal validation performed

**Severity**: High

**Mitigation**:
- Explicit temporal invariants
- Temporal property enforcement
- Non-trivial temporal requirements

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can temporal invariants be weakened by configuration?

**Attack**: Extend temporal windows to infinity, removing temporal constraints.

**Mechanism**: `T_max` for eventual consistency increased to unbounded.

**Preconditions**:
- Temporal parameters configurable
- No upper bounds
- Governance control over time

**Construction**:
1. Initial: Eventual consistency within 100 blocks
2. Config: Set to 2^64 blocks (infinite)
3. No temporal constraint actually enforced

**Observable Signal**: Temporal parameters set to extreme values

**Severity**: High

**Mitigation**:
- Hard temporal bounds
- Temporal invariants immutable
- Maximum timeout enforcement

**Regression Test Required**: Yes

---

#### V4: Reordering — Can temporal invariants be broken by reordering?

**Attack**: Reorder events to violate causality.

**Mechanism**: Effect appears before cause in trace.

**Preconditions**:
- Event ordering influenceable
- Causality not enforced
- Reordering possible

**Construction**:
```
Intended: [Cause, Effect]
Attack:   [Effect, Cause]
Result: Effect observed before cause
```

**Observable Signal**: Effects preceding causes in trace

**Severity**: Critical

**Mitigation**:
- Causality enforcement
- Happens-before validation
- Causal ordering in constraints

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can temporal invariants be broken by partial execution?

**Attack**: Partial trace shows violated temporal property, full trace doesn't.

**Mechanism**: Temporal property holds on full trace but not on partial prefix.

**Preconditions**:
- Temporal properties prefix-sensitive
- Partial traces analyzed
- Prefix/suffix distinction

**Construction**:
1. Full trace: [A, B, C] satisfies temporal property
2. Partial trace: [A, B] violates temporal property
3. Analysis on partial trace shows violation
4. Full trace actually valid

**Observable Signal**: Temporal violations in partial traces

**Severity**: Medium

**Mitigation**:
- Temporal properties over complete traces
- Prefix invariance where appropriate
- Complete trace analysis

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can temporal invariants be broken by concurrency?

**Attack**: Concurrent events violate happens-before ordering.

**Mechanism**: Concurrent execution produces interleaving violating causality.

**Preconditions**:
- Concurrent event execution
- No total order enforcement
- Race condition in ordering

**Construction**:
```
Thread 1: Event A (cause)
Thread 2: Event B (effect of A)
Interleaving: B observed before A (causality violation)
```

**Observable Signal**: Causality violations in concurrent execution

**Severity**: Critical

**Mitigation**:
- Sequential execution model
- Happens-before enforcement
- Causal consistency in constraints

**Regression Test Required**: Yes

---

#### V7: Rollback — Can temporal invariants be broken by rollback?

**Attack**: Rollback creates duplicate states, violating `T_no_revert`.

**Mechanism**: State reappearance after rollback violates temporal monotonicity.

**Preconditions**:
- Rollback mechanism
- State can reappear
- Temporal invariants not enforced

**Construction**:
1. State S at time T1
2. Progress to S' at T2
3. Rollback to S at T3
4. S appears at both T1 and T3
5. `T_no_revert` violated

**Observable Signal**: Duplicate states at different times

**Severity**: High

**Mitigation**:
- No state rollback
- Append-only state history
- Temporal monotonicity enforcement

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can temporal invariants be broken by omitted traces?

**Attack**: Hide events from trace, breaking temporal chain.

**Mechanism**: Omitted events make temporal property appear satisfied when violated.

**Preconditions**:
- Trace recording incomplete
- Temporal verification trace-dependent
- Events can be hidden

**Construction**:
1. Trace with event A: [A, B] violates temporal property
2. Omit A from trace: [B] appears to satisfy property
3. Temporal violation hidden

**Observable Signal**: Temporal properties satisfied on incomplete traces

**Severity**: Critical

**Mitigation**:
- Complete trace recording
- Temporal verification over full traces
- Event completeness proofs

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can temporal invariants be broken by ambiguous semantic mapping?

**Attack**: Ambiguous timestamp mapping makes ordering unclear.

**Mechanism**: Same concrete timestamp maps to multiple formal times.

**Preconditions**:
- Timestamp mapping ambiguous
- Multiple valid orderings
- Constraint system uses favorable ordering

**Construction**:
1. Concrete timestamps: T1 = T2 (same value)
2. Formal interpretation: T1 < T2 (one ordering)
3. Alternative interpretation: T2 < T1 (another ordering)
4. Causality depends on interpretation

**Observable Signal**: Same timestamps with different orderings

**Severity**: High

**Mitigation**:
- Injective timestamp mapping
- Canonical ordering for ties
- Timestamp unambiguity proof

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can temporal invariants be broken by an upgrade?

**Attack**: Upgrade changes temporal semantics, invalidating historical guarantees.

**Mechanism**: Version 2 defines time differently from Version 1.

**Preconditions**:
- Temporal semantics versioned
- Upgrade changes time
- Historical proofs affected

**Construction**:
1. Version 1: Monotonic time
2. Upgrade to Version 2: Time can go backwards
3. Old proofs assume monotonicity
4. Monotonicity no longer guaranteed

**Observable Signal**: Temporal property changes in upgrades

**Severity**: High

**Mitigation**:
- Immutable temporal invariants
- Time semantics version-independent
- Backward compatibility for time

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can temporal invariants be broken by policy drift?

**Attack**: Gradual temporal constraint relaxation.

**Mechanism**: Series of "adjustments" to timing parameters.

**Preconditions**:
- Temporal policy governable
- Incremental changes acceptable
- No cumulative analysis

**Construction**:
1. Initial: Strict temporal ordering
2. Policy 1: Allow small time reversals
3. Policy 2: Extend tolerance
4. Policy 3: Remove ordering requirements
5. Result: Temporal constraints meaningless

**Observable Signal**: Progressive temporal relaxation

**Severity**: Medium

**Mitigation**:
- Temporal invariants in protocol
- Policy cannot affect time
- Strict temporal enforcement

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can temporal invariants be broken while all tests pass?

**Attack**: Tests use short traces; long traces violate temporal properties.

**Mechanism**: Temporal property fails on long traces not tested.

**Preconditions**:
- Test traces short
- Temporal properties long-horizon
- Edge cases untested

**Construction**:
1. Tests: Traces of length 10, temporal properties hold
2. Production: Traces of length 10000
3. Rounding error accumulates, temporal property fails
4. Tests pass, production fails

**Observable Signal**: Temporal failures in long-running systems

**Severity**: High

**Mitigation**:
- Model checking for temporal properties
- Bounded model checking with large bounds
- Formal temporal verification

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can temporal invariants be broken while local verification passes?

**Attack**: Local temporal ordering valid, global ordering invalid.

**Mechanism**: Local node sees events in order, global view shows different order.

**Preconditions**:
- Distributed time
- Local vs global ordering distinction
- Clock skew possible

**Construction**:
1. Node A: sees [E1, E2] in order
2. Node B: sees [E2, E1] (clock skew)
3. Global: E2 before E1 (causality violation)
4. Local verification passes

**Observable Signal**: Clock skew causing ordering inconsistencies

**Severity**: Critical

**Mitigation**:
- Synchronized clocks
- Logical clocks (Lamport/Vector)
- Global ordering consensus

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can temporal invariants be broken while the proof remains valid?

**Attack**: Temporal properties not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode temporal invariants.

**Preconditions**:
- Temporal invariants not constrained
- Verifier doesn't check time
- Underconstrained system

**Construction**:
1. Execution violates temporal property (non-monotonic)
2. Constraints don't check monotonicity
3. Proof verifies
4. Temporal violation in valid proof

**Observable Signal**: Verifiable proofs with temporal violations

**Severity**: Catastrophic

**Mitigation**:
- Temporal invariants in constraints
- Time validation in proofs
- Temporal constraint coverage

**Regression Test Required**: Yes

---

## 11. Ordering Invariants — Attack Matrix

**Definition**: Invariants constraining execution order—causality, sequencing, dependencies.

**VSEL Mapping**: T_causal, Order preservation, dependency constraints

### Attack Vector Analysis

#### V1: Bypass — Can ordering be bypassed?

**Attack**: Execute dependent operation before prerequisite.

**Mechanism**: Operation B requires A, but B executed first.

**Preconditions**:
- Dependency check bypassable
- Prerequisite validation weak
- Ordering not enforced

**Construction**:
```
Operation: Transfer without prior balance check
Result: Transfer succeeds (overdraft)
```

**Observable Signal**: Operations executing without prerequisites

**Severity**: Critical

**Mitigation**:
- Dependency enforcement in protocol
- Prerequisite validation mandatory
- Ordering constraints in constraints

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can ordering be satisfied vacuously?

**Attack**: No ordering requirements, any order "valid."

**Mechanism**: `Ordered(τ) ≡ True` for all traces.

**Preconditions**:
- Ordering not defined
- Default allow
- No sequencing constraints

**Construction**:
```haskell
Ordered(τ) = True  -- Any order valid
```

**Observable Signal**: No ordering validation

**Severity**: High

**Mitigation**:
- Explicit ordering requirements
- Dependency graph validation
- Sequencing constraints

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can ordering be weakened by configuration?

**Attack**: Relax ordering requirements through configuration.

**Mechanism**: Dependency checks disabled via configuration.

**Preconditions**:
- Ordering configurable
- Checks can be disabled
- Governance control over ordering

**Construction**:
1. Config: `strict_ordering = true`
2. Governance: Set `strict_ordering = false`
3. Dependencies no longer enforced

**Observable Signal**: Ordering checks disabled in configuration

**Severity**: Critical

**Mitigation**:
- Ordering invariants immutable
- No configuration of ordering
- Strict dependency enforcement

**Regression Test Required**: Yes

---

#### V4: Reordering — Can ordering be broken by reordering?

**Attack**: Transaction reordering exploits price impact.

**Mechanism**: Sandwich attack via ordering manipulation.

**Preconditions**:
- Ordering influenceable
- Price impact from order
- Profit from reordering

**Construction**:
```
Attacker transaction (buy)
Victim transaction (buy, at higher price)
Attacker transaction (sell, at inflated price)
Result: Profit from ordering
```

**Observable Signal**: Systematic profit from transaction ordering

**Severity**: Critical

**Mitigation**:
- Ordering invariants
- Batch execution with uniform pricing
- Commit-reveal schemes

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can ordering be broken by partial execution?

**Attack**: Partial dependency satisfaction allows premature execution.

**Mechanism**: Operation requires [A, B, C], but executes after only [A].

**Preconditions**:
- Partial dependency check
- Incomplete validation
- Dependencies checkable separately

**Construction**:
1. Operation requires prerequisites A, B, C
2. Check A (passes)
3. Execute operation (before B, C checked)
4. Operation succeeds with incomplete prerequisites

**Observable Signal**: Operations executing with partial prerequisites

**Severity**: Critical

**Mitigation**:
- All-or-nothing dependency checking
- Complete prerequisite validation
- Atomic dependency satisfaction

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can ordering be broken by concurrency?

**Attack**: Concurrent execution produces race condition in ordering.

**Mechanism**: Operations A and B concurrent, ordering undefined.

**Preconditions**:
- Concurrent execution
- No ordering between concurrent ops
- Race condition exploitable

**Construction**:
```
Thread 1: Operation A starts
Thread 2: Operation B starts
Both complete, but ordering undefined
Dependency: A must precede B, but order uncertain
```

**Observable Signal**: Undefined ordering in concurrent execution

**Severity**: Critical

**Mitigation**:
- Sequential execution
- Deterministic ordering
- Concurrency control

**Regression Test Required**: Yes

---

#### V7: Rollback — Can ordering be broken by rollback?

**Attack**: Rollback removes completed operations, reordering effective sequence.

**Mechanism**: Operations A, B, C executed. Rollback removes B. Effective order: A, C.

**Preconditions**:
- Rollback mechanism
- Operations reversible
- Ordering mutable

**Construction**:
1. Execute A, B, C in order
2. Rollback B
3. Trace shows A, C (B removed)
4. Effective ordering changed

**Observable Signal**: Operations disappearing from ordering

**Severity**: High

**Mitigation**:
- No rollback of committed operations
- Append-only operation history
- Ordering immutability

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can ordering be broken by omitted traces?

**Attack**: Hide operations from trace, changing apparent ordering.

**Mechanism**: Omitted operations make ordering appear different.

**Preconditions**:
- Trace recording incomplete
- Ordering verification trace-dependent
- Operations can be hidden

**Construction**:
1. Actual: [A, B, C, D]
2. Recorded: [A, C, D] (B omitted)
3. Verification: C follows A directly (B dependency violated)
4. Ordering appears valid

**Observable Signal**: Ordering inconsistent with actual execution

**Severity**: Critical

**Mitigation**:
- Complete trace recording
- Ordering verification over full traces
- Operation completeness

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can ordering be broken by ambiguous semantic mapping?

**Attack**: Ambiguous dependency specification allows reordering.

**Mechanism**: Dependency "A before B" ambiguous—does B require A or just prefer A?

**Preconditions**:
- Dependency semantics ambiguous
- Multiple interpretations
- Constraint system uses weak interpretation

**Construction**:
1. Specification: "A should precede B"
2. Interpretation A: B requires A (strict)
3. Interpretation B: B prefers A but can proceed without (weak)
4. Implementation uses B, allowing B without A

**Observable Signal**: Dependencies treated as preferences not requirements

**Severity**: High

**Mitigation**:
- Unambiguous dependency specification
- Strict dependency semantics
- Dependency validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can ordering be broken by an upgrade?

**Attack**: Upgrade changes dependency requirements.

**Mechanism**: Version 2 removes dependency that Version 1 required.

**Preconditions**:
- Dependencies versioned
- Upgrade changes dependencies
- Old dependencies not enforced

**Construction**:
1. Version 1: B requires A
2. Upgrade to Version 2: B doesn't require A
3. Execute B without A
4. Old dependency violated

**Observable Signal**: Dependency changes in upgrades

**Severity**: High

**Mitigation**:
- Immutable dependency invariants
- Upgrade cannot remove dependencies
- Dependency backward compatibility

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can ordering be broken by policy drift?

**Attack**: Gradual dependency relaxation through policy updates.

**Mechanism**: Series of "optimizations" removing dependencies.

**Preconditions**:
- Dependencies in policy
- Policy update mechanism
- Progressive weakening acceptable

**Construction**:
1. Initial: Strict dependency graph
2. Policy 1: Remove "unnecessary" dependency
3. Policy 2: Add "shortcut" bypassing dependency
4. Policy 3: Dependencies now optional
5. Result: Weak ordering

**Observable Signal**: Dependency graph simplifying over time

**Severity**: High

**Mitigation**:
- Dependencies in protocol (immutable)
- Policy cannot affect ordering
- Strict dependency enforcement

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can ordering be broken while all tests pass?

**Attack**: Ordering edge cases not in test suite.

**Mechanism**: Tests use simple ordering; complex ordering scenarios untested.

**Preconditions**:
- Test ordering simple
- Complex dependencies untested
- Edge cases uncovered

**Construction**:
1. Tests: Linear ordering A→B→C
2. Production: Complex DAG dependencies
3. Circular dependency in DAG
4. Tests pass, production ordering fails

**Observable Signal**: Ordering failures in complex scenarios

**Severity**: Critical

**Mitigation**:
- Dependency graph analysis
- Topological sorting verification
- Ordering completeness testing

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can ordering be broken while local verification passes?

**Attack**: Local ordering valid, global ordering invalid.

**Mechanism**: Local node validates ordering locally, but global ordering violated.

**Preconditions**:
- Distributed ordering
- Local vs global ordering distinction
- Ordering inconsistency possible

**Construction**:
1. Node A: validates local ordering (passes)
2. Global: ordering requires cross-node coordination
3. Coordination fails
4. Global ordering violated, local passes

**Observable Signal**: Local ordering consistent, global inconsistent

**Severity**: Critical

**Mitigation**:
- Global ordering validation
- Distributed ordering consensus
- Cross-node ordering verification

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can ordering be broken while the proof remains valid?

**Attack**: Ordering not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode ordering requirements.

**Preconditions**:
- Ordering not constrained
- Verifier doesn't check ordering
- Underconstrained system

**Construction**:
1. Execution: B before A (violates dependency)
2. Constraints: Don't check ordering
3. Proof verifies
4. Ordering violated in valid proof

**Observable Signal**: Verifiable proofs with ordering violations

**Severity**: Catastrophic

**Mitigation**:
- Ordering invariants in constraints
- Dependency encoding in proofs
- Ordering constraint coverage

**Regression Test Required**: Yes

---

## 12. Conservation Invariants — Attack Matrix

**Definition**: Invariants preserving quantities—value conservation, resource accounting, mass preservation.

**VSEL Mapping**: L_cons, T_cons, Resource conservation, accounting invariants

### Attack Vector Analysis

#### V1: Bypass — Can conservation be bypassed?

**Attack**: Create value from nothing via accounting bug.

**Mechanism**: Double-credit or missing debit creates unbacked value.

**Preconditions**:
- Accounting bug
- Debit/credit imbalance
- Conservation check bypassable

**Construction**:
```
Credit A: +100 (correct)
Credit B: +100 (duplicate, should not happen)
No corresponding debit
Result: 200 created from 100
```

**Observable Signal**: Unbacked value creation

**Severity**: Catastrophic

**Mitigation**:
- Double-entry accounting
- Conservation validation mandatory
- Accounting invariants in constraints

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can conservation be satisfied vacuously?

**Attack**: Define conservation trivially true.

**Mechanism**: `Conserved(s, s') ≡ True` allows any value changes.

**Preconditions**:
- Conservation not defined
- Default true
- No accounting requirements

**Construction**:
```haskell
Conserved(s, s') = True  -- Any value change valid
```

**Observable Signal**: Value creation without accounting

**Severity**: Catastrophic

**Mitigation**:
- Explicit conservation requirements
- Accounting equation enforcement
- Resource conservation proofs

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can conservation be weakened by configuration?

**Attack**: Add "conservation exceptions" via configuration.

**Mechanism**: Configurable list of operations exempt from conservation.

**Preconditions**:
- Conservation configurable
- Exceptions allowed
- Governance control over conservation

**Construction**:
1. Normal: All operations conserve value
2. Config: Add "minting" exception
3. Minting creates value without conservation

**Observable Signal**: Conservation exceptions in configuration

**Severity**: Critical

**Mitigation**:
- Immutable conservation invariants
- No exceptions to conservation
- Protocol-level conservation

**Regression Test Required**: Yes

---

#### V4: Reordering — Can conservation be broken by reordering?

**Attack**: Reordering produces rounding error accumulation.

**Mechanism**: Order of operations affects rounding, conservation violated in aggregate.

**Preconditions**:
- Rounding in operations
- Order-dependent rounding
- Conservation only per-operation

**Construction**:
```
Order A: [(100+1)/2, (100+1)/2] = [50, 50] = 100
Order B: [100/2, (100+1)/2+1/2] = [50, 51] = 101
Result: Conservation depends on order
```

**Observable Signal**: Conservation violations dependent on operation order

**Severity**: Critical

**Mitigation**:
- Conservation over full trace, not individual operations
- Rounding invariant to conservation
- Order-independent conservation

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can conservation be broken by partial execution?

**Attack**: Partial transaction leaves conservation violated.

**Mechanism**: Debit without corresponding credit (or vice versa) due to partial execution.

**Preconditions**:
- Partial execution possible
- Atomicity not guaranteed
- Conservation only checks complete transactions

**Construction**:
1. Transaction: Debit A, Credit B (should conserve)
2. Execute Debit A
3. Fail before Credit B
4. A debited, B not credited
5. Conservation violated

**Observable Signal**: Unbalanced partial transactions

**Severity**: Critical

**Mitigation**:
- Atomic transaction semantics
- All-or-nothing execution
- Conservation validation per atomic unit

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can conservation be broken by concurrency?

**Attack**: Race condition in accounting allows double-spend.

**Mechanism**: Concurrent debits from same balance both succeed.

**Preconditions**:
- Concurrent balance access
- Check-then-act race
- No isolation

**Construction**:
```
Balance: 100
Thread 1: Check 100 ≥ 50, Debit 50
Thread 2: Check 100 ≥ 60, Debit 60
Both succeed: Total debited 110, balance was 100
Result: Conservation violated
```

**Observable Signal**: Overdrafts in concurrent execution

**Severity**: Catastrophic

**Mitigation**:
- Sequential execution
- Atomic check-and-debit
- Conservation in constraints

**Regression Test Required**: Yes

---

#### V7: Rollback — Can conservation be broken by rollback?

**Attack**: Rollback removes debit but not credit.

**Mechanism**: Asymmetric rollback—credits kept, debits rolled back.

**Preconditions**:
- Rollback mechanism
- Asymmetric rollback possible
- Conservation not rollback-aware

**Construction**:
1. Transaction: Debit A, Credit B
2. Execute: A debited, B credited
3. Rollback A's debit (A restored)
4. B keeps credit
5. Value created from nothing

**Observable Signal**: Asymmetric rollbacks creating value

**Severity**: Catastrophic

**Mitigation**:
- No asymmetric rollback
- Atomic rollback (all or nothing)
- Conservation over full history

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can conservation be broken by omitted traces?

**Attack**: Hide value-creating transactions from trace.

**Mechanism**: Unrecorded transactions create value not in accounting.

**Preconditions**:
- Trace recording incomplete
- Conservation verification trace-dependent
- Transactions can be hidden

**Construction**:
1. Execute hidden mint transaction (not recorded)
2. Execute legitimate transactions (recorded)
3. Conservation checks on recorded trace (passes)
4. Actual conservation violated (hidden mint)

**Observable Signal**: Value not accounted for in trace

**Severity**: Critical

**Mitigation**:
- Complete transaction recording
- Conservation over full trace
- Transaction completeness proofs

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can conservation be broken by ambiguous semantic mapping?

**Attack**: Ambiguous value representation allows conservation bypass.

**Mechanism**: Same value represented multiple ways, conservation across representations fails.

**Preconditions**:
- Value representation ambiguous
- Multiple encodings for same value
- Conservation doesn't normalize

**Construction**:
```
Representation A: 100
Representation B: 1e2 (same value, different encoding)
Credit: +100 (Representation A)
Debit: -1e2 (Representation B)
System: Different encodings, conservation check fails to equate
Result: Conservation violated (same value added and removed)
```

**Observable Signal**: Conservation failures across different representations

**Severity**: Critical

**Mitigation**:
- Canonical value representation
- Normalization before conservation check
- Representation invariance

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can conservation be broken by an upgrade?

**Attack**: Upgrade changes accounting rules, enabling conservation violation.

**Mechanism**: Version 2 introduces new accounting that doesn't conserve with Version 1.

**Preconditions**:
- Accounting rules versioned
- Upgrade changes conservation
- Cross-version conservation not checked

**Construction**:
1. Version 1: Value V1 created
2. Upgrade to Version 2: New accounting
3. V1 value in Version 2 accounting doesn't conserve
4. Conservation violated across versions

**Observable Signal**: Conservation violations across protocol versions

**Severity**: Critical

**Mitigation**:
- Immutable conservation invariants
- Upgrade cannot change accounting
- Cross-version conservation validation

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can conservation be broken by policy drift?

**Attack**: Gradual accounting rule relaxation.

**Mechanism**: Series of "adjustments" to accounting rules.

**Preconditions**:
- Accounting in policy
- Policy update mechanism
- Progressive relaxation acceptable

**Construction**:
1. Initial: Strict double-entry accounting
2. Policy 1: Allow "estimated" values
3. Policy 2: Add "adjustment" entries
4. Policy 3: Permit "temporary" imbalances
5. Result: Conservation weakened

**Observable Signal**: Accounting rules relaxing over time

**Severity**: Critical

**Mitigation**:
- Conservation in protocol (immutable)
- Policy cannot affect accounting
- Strict conservation enforcement

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can conservation be broken while all tests pass?

**Attack**: Tests use integers; production uses floats with rounding errors.

**Mechanism**: Conservation holds with integer arithmetic, fails with floating point.

**Preconditions**:
- Tests use different arithmetic
- Production has rounding
- Conservation not tested with real arithmetic

**Construction**:
1. Tests: Integer arithmetic, conservation exact
2. Production: Floating point, rounding errors
3. Rounding accumulation violates conservation
4. Tests pass, production fails

**Observable Signal**: Conservation failures only in production

**Severity**: Critical

**Mitigation**:
- Production-equivalent testing
- Rounding invariant testing
- Formal conservation proofs

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can conservation be broken while local verification passes?

**Attack**: Local conservation valid, global conservation invalid.

**Mechanism**: Conservation holds locally per-pool, fails globally across pools.

**Preconditions**:
- Local conservation only
- Global conservation not checked
- Cross-pool interactions

**Construction**:
1. Pool A: conservation holds
2. Pool B: conservation holds
3. Cross-pool transfer: A loses 100, B gains 101
4. Local conservation passes, global fails

**Observable Signal**: Pool-level conservation, system-level violation

**Severity**: Critical

**Mitigation**:
- Global conservation invariants
- Cross-pool conservation validation
- System-level accounting

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can conservation be broken while the proof remains valid?

**Attack**: Conservation not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode conservation laws.

**Preconditions**:
- Conservation not constrained
- Verifier doesn't check conservation
- Underconstrained system

**Construction**:
1. Execution: Value created without source
2. Constraints: Don't verify conservation
3. Proof verifies
4. Conservation violated in valid proof

**Observable Signal**: Verifiable proofs with conservation violations

**Severity**: Catastrophic

**Mitigation**:
- Conservation invariants in constraints
- Accounting equation encoding
- Conservation constraint coverage

**Regression Test Required**: Yes

---

## 13. Access Control Invariants — Attack Matrix

**Definition**: Invariants constraining resource access—read/write permissions, ownership, delegation.

**VSEL Mapping**: Read permissions, write permissions, ownership invariants

### Attack Vector Analysis

#### V1: Bypass — Can access control be bypassed?

**Attack**: Access resource without required permissions.

**Mechanism**: Permission check bypass via implementation flaw.

**Preconditions**:
- Permission check in some paths
- Bypass path exists
- Access control incomplete

**Construction**:
1. Resource requires `Read` permission
2. Normal path checks permission
3. Alternative path (e.g., cache read) doesn't check
4. Read without permission via alternative path

**Observable Signal**: Unauthorized resource access

**Severity**: Critical

**Mitigation**:
- Mandatory access control (all paths)
- Permission checks at entry points
- Access control completeness proof

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can access control be satisfied vacuously?

**Attack**: All entities have all permissions.

**Mechanism**: `CanAccess(entity, resource) ≡ True` for all.

**Preconditions**:
- Access control not configured
- Default allow
- No permission restrictions

**Construction**:
```haskell
CanAccess(entity, resource) = True  -- Everyone can access everything
```

**Observable Signal**: No access control enforcement

**Severity**: Critical

**Mitigation**:
- Default-deny access control
- Explicit permission grants
- Access control policy definition

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can access control be weakened by configuration?

**Attack**: Governance grants broad access permissions.

**Mechanism**: Governance action gives `*` access to `*` resources.

**Preconditions**:
- Access permissions configurable
- No permission bounds
- Governance control over access

**Construction**:
1. Proposal: Grant universal read access
2. Passes governance
3. All resources now readable by all

**Observable Signal**: Broad permission grants via governance

**Severity**: Critical

**Mitigation**:
- Access control invariants immutable
- Governance cannot grant certain permissions
- Permission upper bounds

**Regression Test Required**: Yes

---

#### V4: Reordering — Can access control be broken by reordering?

**Attack**: Access resource before permission revocation.

**Mechanism**: Use resource, permission revoked, use again (should fail but order matters).

**Preconditions**:
- Permission changes have delay
- Resource usage front-runnable
- Revocation not immediate

**Construction**:
```
Block N:   Permission revocation submitted
Block N+1: Access resource (revocation not yet effective)
Block N+2: Revocation effective
Result: Accessed after revocation submitted
```

**Observable Signal**: Resource access after revocation

**Severity**: High

**Mitigation**:
- Immediate revocation
- Atomic permission changes
- Access time validation

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can access control be broken by partial execution?

**Attack**: Partial permission check allows unauthorized access.

**Mechanism**: Multi-factor permission check partially executed.

**Preconditions**:
- Multi-factor access control
- Partial check possible
- Completion not required

**Construction**:
1. Access requires factors A, B, C
2. Check A (passes)
3. Fail before B, C
4. Access granted (partial check only)

**Observable Signal**: Access with partial permission verification

**Severity**: Critical

**Mitigation**:
- Atomic permission checking
- All factors required
- Partial check rejection

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can access control be broken by concurrency?

**Attack**: Race condition in permission check allows escalation.

**Mechanism**: Check permission, permission revoked, use resource with stale permission.

**Preconditions**:
- Check-then-act race
- Permission mutable
- No synchronization

**Construction**:
```
Time 0: Check permission (has access)
Time 1: Permission revoked
Time 2: Access resource (based on stale check)
Result: Access after revocation
```

**Observable Signal**: Access using stale permissions

**Severity**: Critical

**Mitigation**:
- Atomic permission validation
- Time-of-use permission check
- Access binding to permission

**Regression Test Required**: Yes

---

#### V7: Rollback — Can access control be broken by rollback?

**Attack**: Rollback restores old permissions.

**Mechanism**: Permission revoked, then rollback restores old (permissive) permissions.

**Preconditions**:
- Rollback mechanism
- Permissions reversible
- Access control state mutable

**Construction**:
1. Entity has permission P
2. Permission P revoked
3. Entity attempts access (fails)
4. Rollback to before revocation
5. Permission P restored
6. Entity accesses resource

**Observable Signal**: Permission restoration via rollback

**Severity**: High

**Mitigation**:
- Permission changes immutable
- No rollback of permissions
- Permission history append-only

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can access control be broken by omitted traces?

**Attack**: Hide unauthorized access from audit trail.

**Mechanism**: Access resource, access not recorded, appears authorized.

**Preconditions**:
- Access logging incomplete
- Audit trail-dependent verification
- Access can be hidden

**Construction**:
1. Entity accesses resource (unauthorized)
2. Access not logged
3. Audit shows no unauthorized access
4. Violation hidden

**Observable Signal**: Missing access records

**Severity**: Critical

**Mitigation**:
- Complete access logging
- Access events in trace
- Audit trail completeness

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can access control be broken by ambiguous semantic mapping?

**Attack**: Ambiguous permission semantics allow unintended access.

**Mechanism**: Permission "read" maps to multiple interpretations—some include write.

**Preconditions**:
- Permission semantics ambiguous
- Multiple valid interpretations
- System uses permissive interpretation

**Construction**:
1. Grant "read" permission
2. Granter intends: read-only
3. System interprets: read + metadata write
4. Entity writes metadata (unintended)

**Observable Signal**: Permissions exceeding grantor intent

**Severity**: High

**Mitigation**:
- Unambiguous permission definitions
- Permission minimization
- Permission semantics validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can access control be broken by an upgrade?

**Attack**: Upgrade expands permissions retroactively.

**Mechanism**: Version 2 redefines permission `read` to include `write`.

**Preconditions**:
- Permission semantics versioned
- Upgrade changes permissions
- Retroactive permission expansion

**Construction**:
1. Version 1: `read` = read-only
2. Entities granted `read` permission
3. Upgrade to Version 2: `read` = read + write
4. Entities now have write access

**Observable Signal**: Permission expansion in upgrades

**Severity**: Critical

**Mitigation**:
- Immutable permission semantics
- Upgrade cannot change permissions
- Permission compatibility

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can access control be broken by policy drift?

**Attack**: Gradual permission expansion through policy updates.

**Mechanism**: Series of "convenience" permissions accumulating.

**Preconditions**:
- Access control policy governable
- Incremental changes acceptable
- No cumulative analysis

**Construction**:
1. Initial: Minimal permissions
2. Policy 1: Add "temporary" admin access
3. Policy 2: Extend "emergency" permissions
4. Policy 3: Broaden "maintenance" access
5. Result: Permissive access control

**Observable Signal**: Expanding access control policies

**Severity**: High

**Mitigation**:
- Access control in protocol (immutable)
- Policy cannot override permissions
- Strict permission minimization

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can access control be broken while all tests pass?

**Attack**: Tests cover main paths; edge cases bypass access control.

**Mechanism**: Access control in tested paths, bypass in untested paths.

**Preconditions**:
- Test coverage incomplete
- Edge paths untested
- Bypass exists in untested code

**Construction**:
1. Tests: All tested paths check permissions
2. Production: Cache read path doesn't check
3. Access via cache bypasses control
4. Tests pass, production vulnerable

**Observable Signal**: Access control bypass in production only

**Severity**: Critical

**Mitigation**:
- Complete path coverage
- Access control completeness proof
- Mandatory access control

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can access control be broken while local verification passes?

**Attack**: Local access control passes, global policy violated.

**Mechanism**: Local node grants access, global policy restricts.

**Preconditions**:
- Distributed access control
- Local vs global policy distinction
- Policy inconsistency possible

**Construction**:
1. Local policy: Access allowed
2. Global policy: Access prohibited
3. Local node grants access
4. Global policy violated

**Observable Signal**: Local/global access policy inconsistency

**Severity**: Critical

**Mitigation**:
- Global access control enforcement
- Policy consistency verification
- Centralized access control

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can access control be broken while the proof remains valid?

**Attack**: Access control not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode access control.

**Preconditions**:
- Access control not constrained
- Verifier doesn't check permissions
- Underconstrained system

**Construction**:
1. Unauthorized access in execution
2. Constraints don't verify access control
3. Proof verifies
4. Access violation in valid proof

**Observable Signal**: Verifiable proofs with access violations

**Severity**: Catastrophic

**Mitigation**:
- Access control in constraints
- Permission encoding in proofs
- Access control constraint coverage

**Regression Test Required**: Yes

---

## 14. Upgrade Invariants — Attack Matrix

**Definition**: Invariants preserving correctness across protocol changes—backward compatibility, state migration, semantic preservation.

**VSEL Mapping**: Version compatibility, state migration, upgrade safety

### Attack Vector Analysis

#### V1: Bypass — Can upgrade invariants be bypassed?

**Attack**: Execute upgrade without proper validation.

**Mechanism**: Emergency upgrade path bypasses safety checks.

**Preconditions**:
- Emergency upgrade mechanism
- Safety checks bypassable
- Upgrade validation incomplete

**Construction**:
1. Normal upgrade requires validation
2. Emergency path skips validation
3. Execute emergency upgrade
4. Safety checks bypassed

**Observable Signal**: Upgrades without validation

**Severity**: Critical

**Mitigation**:
- Mandatory upgrade validation
- No emergency bypass
- Upgrade safety proofs

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can upgrade invariants be satisfied vacuously?

**Attack**: All upgrades "valid" by definition.

**Mechanism**: `ValidUpgrade(v1, v2) ≡ True` for all versions.

**Preconditions**:
- Upgrade validity not defined
- Default allow
- No upgrade constraints

**Construction**:
```haskell
ValidUpgrade(old, new) = True  -- Any upgrade valid
```

**Observable Signal**: Arbitrary upgrades accepted

**Severity**: Catastrophic

**Mitigation**:
- Strict upgrade validation
- Compatibility requirements
- Upgrade safety proofs

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can upgrade invariants be weakened by configuration?

**Attack**: Relax upgrade requirements through configuration.

**Mechanism**: Governance reduces upgrade validation requirements.

**Preconditions**:
- Upgrade requirements configurable
- Requirements reducible
- Governance control

**Construction**:
1. Initial: Strict validation required
2. Config: Reduce validation to signature only
3. Upgrades now less validated

**Observable Signal**: Declining upgrade validation

**Severity**: Critical

**Mitigation**:
- Immutable upgrade requirements
- No configuration of upgrade safety
- Protocol-level upgrade invariants

**Regression Test Required**: Yes

---

#### V4: Reordering — Can upgrade invariants be broken by reordering?

**Attack**: Upgrade before prerequisite migrations.

**Mechanism**: State migration should precede logic upgrade, but reversed.

**Preconditions**:
- Upgrade has multiple components
- Ordering not enforced
- Migration and logic separable

**Construction**:
1. Upgrade requires: [MigrateState, UpdateLogic]
2. Execute: UpdateLogic first
3. Logic operates on unmigrated state
4. Invariant violation

**Observable Signal**: Logic/state version mismatch

**Severity**: Critical

**Mitigation**:
- Atomic upgrade execution
- Component ordering enforcement
- Upgrade step dependencies

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can upgrade invariants be broken by partial execution?

**Attack**: Partial upgrade leaves system inconsistent.

**Mechanism**: Multi-step upgrade partially executes.

**Preconditions**:
- Multi-step upgrade
- Partial execution possible
- No rollback on failure

**Construction**:
1. Upgrade: [Step1, Step2, Step3]
2. Execute Step1
3. Step2 fails
4. System partially upgraded, inconsistent

**Observable Signal**: Partial upgrade state

**Severity**: Critical

**Mitigation**:
- Atomic upgrade semantics
- All-or-nothing upgrade
- Upgrade rollback capability

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can upgrade invariants be broken by concurrency?

**Attack**: Concurrent upgrades produce inconsistent state.

**Mechanism**: Two upgrades execute concurrently, interfering.

**Preconditions**:
- Concurrent upgrade execution
- No mutual exclusion
- Upgrade interference possible

**Construction**:
```
Upgrade A: Modifies state X
Upgrade B: Modifies state X (concurrently)
Result: State X inconsistent, partially A, partially B
```

**Observable Signal**: Concurrent upgrade conflicts

**Severity**: Critical

**Mitigation**:
- Sequential upgrade execution
- Upgrade locking
- Single upgrade at a time

**Regression Test Required**: Yes

---

#### V7: Rollback — Can upgrade invariants be broken by rollback?

**Attack**: Rollback after upgrade, reverting to vulnerable version.

**Mechanism**: Upgrade applied, then rolled back.

**Preconditions**:
- Upgrade reversible
- Rollback mechanism
- Version reversion possible

**Construction**:
1. Upgrade from V1 to V2 (security fix)
2. System operates on V2
3. Rollback to V1
4. Security vulnerability restored

**Observable Signal**: Version rollback after upgrade

**Severity**: Critical

**Mitigation**:
- Upgrades irreversible
- No rollback to old versions
- Upgrade finality

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can upgrade invariants be broken by omitted traces?

**Attack**: Hide upgrade from audit trail.

**Mechanism**: Upgrade executed but not recorded.

**Preconditions**:
- Upgrade logging incomplete
- Audit trail-dependent verification
- Upgrade can be hidden

**Construction**:
1. Execute upgrade
2. Omit from upgrade log
3. System behavior changes
4. No record of upgrade

**Observable Signal**: Behavioral changes without upgrade records

**Severity**: Critical

**Mitigation**:
- Complete upgrade logging
- Upgrade events in trace
- Upgrade audit trail

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can upgrade invariants be broken by ambiguous semantic mapping?

**Attack**: Ambiguous state migration creates semantic divergence.

**Mechanism**: Old state maps to multiple new states; migration chooses incorrectly.

**Preconditions**:
- State mapping ambiguous
- Multiple valid migrations
- Migration uses incorrect mapping

**Construction**:
1. State S in V1 has ambiguous encoding
2. Migration to V2: S could map to S' or S''
3. Migration chooses S' (incorrect for intent)
4. Semantic divergence

**Observable Signal**: State migration producing unexpected results

**Severity**: Critical

**Mitigation**:
- Unambiguous state mapping
- Migration validation
- Semantic preservation proofs

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can upgrade invariants be broken by an upgrade?

**Attack**: Meta-upgrade breaks upgrade invariants.

**Mechanism**: Upgrade mechanism itself upgraded to remove safety checks.

**Preconditions**:
- Upgrade mechanism versioned
- Self-modifying upgrades
- Safety checks removable

**Construction**:
1. Version 1: Safe upgrade mechanism
2. Upgrade mechanism to Version 2 (removes safety checks)
3. All future upgrades unsafe
4. Upgrade invariants violated

**Observable Signal**: Upgrade mechanism changes removing safety

**Severity**: Catastrophic

**Mitigation**:
- Immutable upgrade invariants
- Self-upgrade restrictions
- Upgrade mechanism verification

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can upgrade invariants be broken by policy drift?

**Attack**: Gradual relaxation of upgrade requirements.

**Mechanism**: Series of "streamlining" upgrades reducing safety.

**Preconditions**:
- Upgrade policy governable
- Incremental changes acceptable
- No cumulative analysis

**Construction**:
1. Initial: Strict upgrade process
2. Policy 1: Reduce review time
3. Policy 2: Reduce signatories
4. Policy 3: Allow "emergency" bypass
5. Result: Weak upgrade safety

**Observable Signal**: Upgrade process weakening over time

**Severity**: Critical

**Mitigation**:
- Upgrade invariants in protocol (immutable)
- Policy cannot affect upgrade safety
- Strict upgrade requirements

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can upgrade invariants be broken while all tests pass?

**Attack**: Tests use simple upgrades; production has complex edge cases.

**Mechanism**: Upgrade edge cases not in test suite.

**Preconditions**:
- Test upgrades simple
- Production upgrades complex
- Edge cases untested

**Construction**:
1. Tests: Simple state migration
2. Production: Complex multi-state migration
3. Edge case: State dependency cycle
4. Tests pass, production fails

**Observable Signal**: Upgrade failures in production edge cases

**Severity**: Critical

**Mitigation**:
- Comprehensive upgrade testing
- Property-based upgrade testing
- Formal upgrade verification

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can upgrade invariants be broken while local verification passes?

**Attack**: Local upgrade valid, global upgrade invalid.

**Mechanism**: Local node validates upgrade locally, but global compatibility fails.

**Preconditions**:
- Distributed upgrade
- Local vs global validation
- Inconsistency possible

**Construction**:
1. Local node: upgrade valid
2. Global: upgrade incompatible with other nodes
3. Local node upgrades
4. Global consistency violated

**Observable Signal**: Divergent versions across network

**Severity**: Critical

**Mitigation**:
- Global upgrade consensus
- Cross-node upgrade validation
- Coordinated upgrades

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can upgrade invariants be broken while the proof remains valid?

**Attack**: Upgrade invariants not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode upgrade safety.

**Preconditions**:
- Upgrade invariants not constrained
- Verifier doesn't check upgrades
- Underconstrained system

**Construction**:
1. Unsafe upgrade in execution
2. Constraints don't verify upgrade safety
3. Proof verifies
4. Upgrade violation in valid proof

**Observable Signal**: Verifiable proofs for unsafe upgrades

**Severity**: Catastrophic

**Mitigation**:
- Upgrade invariants in constraints
- Upgrade safety encoding
- Upgrade constraint coverage

**Regression Test Required**: Yes

---

## 15. Trace Integrity Invariants — Attack Matrix

**Definition**: Invariants ensuring complete, accurate, tamper-proof execution history.

**VSEL Mapping**: T_complete, Trace validity, commitment consistency

### Attack Vector Analysis

#### V1: Bypass — Can trace integrity be bypassed?

**Attack**: Mutate state without recording trace.

**Mechanism**: Direct state modification not reflected in trace.

**Preconditions**:
- State modifiable outside trace
- Trace recording incomplete
- State/trace decoupled

**Construction**:
```
-- Normal: State change → Trace entry
-- Attack: Direct state modification
State = arbitrary_value  -- No trace entry
Result: State changed, trace unaware
```

**Observable Signal**: State/trace mismatch

**Severity**: Catastrophic

**Mitigation**:
- State changes only via traced transitions
- Complete trace recording
- State-trace coupling

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can trace integrity be satisfied vacuously?

**Attack**: Empty trace considered "complete."

**Mechanism**: `Complete(τ) ≡ True` even for empty traces.

**Preconditions**:
- Completeness not defined
- Default true
- No trace requirements

**Construction**:
```haskell
Complete(τ) = True  -- Any trace "complete"
```

**Observable Signal**: Incomplete traces accepted as complete

**Severity**: Critical

**Mitigation**:
- Explicit completeness requirements
- Trace validation
- Completeness proofs

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can trace integrity be weakened by configuration?

**Attack**: Reduce trace recording through configuration.

**Mechanism**: Governance disables certain trace entries.

**Preconditions**:
- Trace recording configurable
- Entries can be disabled
- Governance control over tracing

**Construction**:
1. Full trace recording initially
2. Config: Disable "verbose" trace entries
3. Important entries now omitted

**Observable Signal**: Trace entries disabled via configuration

**Severity**: Critical

**Mitigation**:
- Immutable trace requirements
- No configuration of trace recording
- Complete trace mandatory

**Regression Test Required**: Yes

---

#### V4: Reordering — Can trace integrity be broken by reordering?

**Attack**: Reorder trace entries to change apparent history.

**Mechanism**: Trace entries reordered, causality violated.

**Preconditions**:
- Trace ordering manipulable
- No integrity protection
- Reordering possible

**Construction**:
```
Actual:   [A causes B, B happens]
Recorded: [B happens, A causes B]  -- Reordered, causality violated
```

**Observable Signal**: Trace entries out of causal order

**Severity**: Critical

**Mitigation**:
- Cryptographic trace chaining
- Tamper-evident traces
- Causal ordering in traces

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can trace integrity be broken by partial execution?

**Attack**: Partial trace recorded, execution incomplete.

**Mechanism**: Trace entry written, execution fails, trace remains.

**Preconditions**:
- Trace written before execution
- No atomic trace/execution
- Partial recording possible

**Construction**:
1. Write trace entry for operation
2. Attempt operation (fails)
3. Trace shows operation, but not completed
4. Trace inconsistent with state

**Observable Signal**: Trace entries for failed operations

**Severity**: Critical

**Mitigation**:
- Atomic trace/execution
- Execution before trace finalization
- Rollback on execution failure

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can trace integrity be broken by concurrency?

**Attack**: Concurrent trace writes produce inconsistent ordering.

**Mechanism**: Multiple concurrent operations, trace ordering ambiguous.

**Preconditions**:
- Concurrent trace writing
- No total order enforcement
- Ordering non-deterministic

**Construction**:
```
Thread 1: Operation A, write trace entry
Thread 2: Operation B, write trace entry
Result: Trace order may not match execution order
```

**Observable Signal**: Trace order inconsistent with execution

**Severity**: Critical

**Mitigation**:
- Sequential trace writing
- Deterministic trace ordering
- Total order in traces

**Regression Test Required**: Yes

---

#### V7: Rollback — Can trace integrity be broken by rollback?

**Attack**: Rollback removes trace entries, rewriting history.

**Mechanism**: Trace rolled back, history altered.

**Preconditions**:
- Trace rollback mechanism
- History mutable
- Entries removable

**Construction**:
1. Execute operations, record in trace
2. Rollback to earlier point
3. Trace entries after rollback point removed
4. History rewritten

**Observable Signal**: Trace entries disappearing

**Severity**: Critical

**Mitigation**:
- Append-only traces
- No trace rollback
- Immutable trace history

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can trace integrity be broken by omitted traces?

**Attack**: Systematically omit certain traces.

**Mechanism**: Selective trace omission hides behavior.

**Preconditions**:
- Trace omission possible
- Selective recording
- Verification incomplete

**Construction**:
1. Define "omittable" operations
2. Execute omittable operations (not recorded)
3. Execute normal operations (recorded)
4. Trace shows only normal operations

**Observable Signal**: Systematic trace gaps

**Severity**: Critical

**Mitigation**:
- No omittable operations
- Complete trace recording
- Omission detection

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can trace integrity be broken by ambiguous semantic mapping?

**Attack**: Ambiguous trace encoding makes interpretation subjective.

**Mechanism**: Same trace entry maps to multiple interpretations.

**Preconditions**:
- Trace encoding ambiguous
- Multiple valid interpretations
- Verification uses favorable interpretation

**Construction**:
1. Trace entry T with ambiguous encoding
2. Interpretation A: Normal operation
3. Interpretation B: Malicious operation
4. Actual: Interpretation B
5. Verification uses A

**Observable Signal**: Same trace entry interpreted differently

**Severity**: Critical

**Mitigation**:
- Unambiguous trace encoding
- Canonical trace format
- Trace encoding validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can trace integrity be broken by an upgrade?

**Attack**: Upgrade changes trace format, breaking integrity.

**Mechanism**: Version 2 uses different trace format, old traces incompatible.

**Preconditions**:
- Trace format versioned
- Upgrade changes format
- Old traces not preserved

**Construction**:
1. Version 1: Trace format F1
2. Upgrade to Version 2: Format F2
3. Old traces in F1 not valid in F2
4. Trace integrity lost for old traces

**Observable Signal**: Trace format changes breaking historical validation

**Severity**: High

**Mitigation**:
- Backward-compatible trace formats
- Trace format migration
- Historical trace preservation

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can trace integrity be broken by policy drift?

**Attack**: Gradual trace relaxation through policy.

**Mechanism**: Series of "optimizations" reducing trace completeness.

**Preconditions**:
- Trace policy governable
- Incremental relaxation acceptable
- No cumulative analysis

**Construction**:
1. Initial: Complete trace
2. Policy 1: Omit "redundant" entries
3. Policy 2: Compress "similar" entries
4. Policy 3: Sample instead of recording all
5. Result: Incomplete trace

**Observable Signal**: Progressive trace reduction

**Severity**: Critical

**Mitigation**:
- Trace requirements in protocol (immutable)
- Policy cannot affect tracing
- Complete trace mandatory

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can trace integrity be broken while all tests pass?

**Attack**: Tests use simplified traces; production has full complexity.

**Mechanism**: Trace edge cases not in test suite.

**Preconditions**:
- Test traces simplified
- Production traces complex
- Edge cases untested

**Construction**):
1. Tests: Linear traces, simple operations
2. Production: Complex branching traces
3. Edge case: Circular trace reference
4. Tests pass, production trace invalid

**Observable Signal**: Trace failures in complex scenarios

**Severity**: Critical

**Mitigation**:
- Comprehensive trace testing
- Property-based trace generation
- Formal trace verification

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can trace integrity be broken while local verification passes?

**Attack**: Local trace valid, global trace invalid.

**Mechanism**: Local node has complete trace, global trace incomplete.

**Preconditions**:
- Distributed trace
- Local vs global trace distinction
- Inconsistency possible

**Construction**:
1. Node A: Complete local trace
2. Global: Aggregated trace missing entries
3. Global trace validation fails
4. Local validation passes

**Observable Signal**: Local trace complete, global incomplete

**Severity**: Critical

**Mitigation**:
- Global trace validation
- Cross-node trace consistency
- Distributed trace consensus

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can trace integrity be broken while the proof remains valid?

**Attack**: Trace integrity not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't verify trace completeness.

**Preconditions**:
- Trace integrity not constrained
- Verifier doesn't check traces
- Underconstrained system

**Construction**:
1. Incomplete trace in execution
2. Constraints don't verify completeness
3. Proof verifies
4. Trace violation in valid proof

**Observable Signal**: Verifiable proofs with incomplete traces

**Severity**: Catastrophic

**Mitigation**:
- Trace integrity in constraints
- Completeness encoding in proofs
- Trace constraint coverage

**Regression Test Required**: Yes

---

## 16. Policy Consistency Invariants — Attack Matrix

**Definition**: Invariants ensuring policy intent is preserved and consistently applied.

**VSEL Mapping**: Policy commitment, intent preservation, semantic stability

### Attack Vector Analysis

#### V1: Bypass — Can policy consistency be bypassed?

**Attack**: Execute action violating policy intent via technicality.

**Mechanism**: Exploit policy wording to violate intent while satisfying letter.

**Preconditions**:
- Policy wording incomplete
- Intent not fully specified
- Technical bypass possible

**Construction**:
1. Policy: "No transfers over 1000 units"
2. Attack: 10 transfers of 100 units each
3. Letter satisfied (each ≤ 1000)
4. Intent violated (total 1000)

**Observable Signal**: Actions satisfying policy letter but violating intent

**Severity**: High

**Mitigation**:
- Policy intent explicit
- Intent-based validation
- Policy completeness

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can policy consistency be satisfied vacuously?

**Attack**: Policy exists but has no requirements.

**Mechanism**: `Policy(p) ≡ True` for all actions.

**Preconditions**:
- Policy not defined
- Default allow
- No policy constraints

**Construction**:
```haskell
Policy(action) = True  -- All actions policy-compliant
```

**Observable Signal**: No policy enforcement

**Severity**: Critical

**Mitigation**:
- Explicit policy requirements
- Policy enforcement
- Policy completeness

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can policy consistency be weakened by configuration?

**Attack**: Policy interpreted permissively via configuration.

**Mechanism**: Policy parser configured for lenient interpretation.

**Preconditions**:
- Policy interpretation configurable
- Strictness reducible
- Governance control over interpretation

**Construction**):
1. Policy: "Reasonable fees"
2. Config: Define "reasonable" as 100%
3. Policy effectively meaningless

**Observable Signal**: Policy interpretation drifting via configuration

**Severity**: High

**Mitigation**:
- Policy interpretation fixed
- No configuration of policy semantics
- Objective policy criteria

**Regression Test Required**: Yes

---

#### V4: Reordering — Can policy consistency be broken by reordering?

**Attack**: Reorder policy changes to violate intent.

**Mechanism**: Policy A enacted, then Policy B enacted, then A reverted.

**Preconditions**:
- Policy changes reversible
- Ordering affects outcome
- No cumulative policy enforcement

**Construction**:
```
Order 1: Enact Policy A, Enact Policy B → A + B effective
Order 2: Enact Policy A, Revert A, Enact Policy B → Only B effective
Result: Same actions, different policies effective
```

**Observable Signal**: Policy effective set dependent on change order

**Severity**: High

**Mitigation**:
- Policy accumulation (additive only)
- No policy reversion
- Policy ordering invariants

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can policy consistency be broken by partial execution?

**Attack**: Partial policy application leaves inconsistent policy state.

**Mechanism**: Multi-part policy partially applied.

**Preconditions**:
- Complex multi-part policies
- Partial application possible
- No atomicity

**Construction**:
1. Policy: [Requirement A, Requirement B, Requirement C]
2. Apply Requirement A
3. Fail before B and C
4. Partial policy in effect

**Observable Signal**: Partially applied policies

**Severity**: High

**Mitigation**:
- Atomic policy application
- All-or-nothing policy changes
- Policy rollback on partial failure

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can policy consistency be broken by concurrency?

**Attack**: Concurrent policy changes conflict.

**Mechanism**: Two policy changes modify same area, produce inconsistent result.

**Preconditions**:
- Concurrent policy changes
- No conflict resolution
- Changes interfere

**Construction**:
```
Policy Change A: Increase fee to 5%
Policy Change B: Decrease fee to 1%
Both applied concurrently
Result: Fee undefined or inconsistent
```

**Observable Signal**: Conflicting policy changes

**Severity**: High

**Mitigation**:
- Sequential policy changes
- Policy conflict detection
- Policy change serialization

**Regression Test Required**: Yes

---

#### V7: Rollback — Can policy consistency be broken by rollback?

**Attack**: Rollback removes policy commitment.

**Mechanism**: Policy enacted, then rolled back, commitment broken.

**Preconditions**:
- Policy rollback possible
- Commitments reversible
- No policy permanence

**Construction**:
1. Policy P enacted (public commitment)
2. Users rely on P
3. Rollback removes P
4. Commitment broken

**Observable Signal**: Policy rollbacks breaking commitments

**Severity**: Critical

**Mitigation**:
- Immutable policy commitments
- No policy rollback
- Policy permanence guarantees

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can policy consistency be broken by omitted traces?

**Attack**: Policy changes not recorded, intent unclear.

**Mechanism**: Policy changes executed but not traced.

**Preconditions**:
- Policy logging incomplete
- Changes can be hidden
- Verification trace-dependent

**Construction**:
1. Policy change enacted (not recorded)
2. System behavior changes
3. No record of policy basis
4. Consistency unverifiable

**Observable Signal**: Behavioral changes without policy records

**Severity**: High

**Mitigation**:
- Complete policy logging
- Policy changes in trace
- Policy audit trail

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can policy consistency be broken by ambiguous semantic mapping?

**Attack**: Policy interpreted differently by different components.

**Mechanism**: Same policy text, different implementations.

**Preconditions**:
- Policy semantics ambiguous
- Multiple interpretations
- Component divergence

**Construction**:
1. Policy: "Fair distribution"
2. Component A: Interpret as equal distribution
3. Component B: Interpret as proportional distribution
4. Same policy, inconsistent application

**Observable Signal**: Same policy applied differently across components

**Severity**: Critical

**Mitigation**:
- Unambiguous policy specification
- Formal policy semantics
- Policy interpretation validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can policy consistency be broken by an upgrade?

**Attack**: Upgrade changes policy semantics retroactively.

**Mechanism**: Version 2 reinterprets Version 1 policies.

**Preconditions**:
- Policy semantics versioned
- Upgrade changes interpretation
- Retroactive reinterpretation

**Construction**:
1. Version 1: Policy P interpreted as X
2. Users rely on X
3. Upgrade to Version 2: P interpreted as Y (incompatible)
4. User expectations violated

**Observable Signal**: Policy reinterpretation across versions

**Severity**: Critical

**Mitigation**:
- Immutable policy semantics
- Policy compatibility across versions
- Version-specific policy validation

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can policy consistency be broken by policy drift?

**Attack**: Gradual policy change erodes original intent.

**Mechanism**: Series of small policy "clarifications" shifting meaning.

**Preconditions**):
- Policy updatable
- Incremental changes acceptable
- No cumulative analysis

**Construction**:
1. Initial: Strict policy
2. Update 1: "Clarify" exception A
3. Update 2: "Clarify" exception B
4. Update 3: "Clarify" exception C
5. Result: Policy substantially changed

**Observable Signal**: Policy meaning shifting over time

**Severity**: High

**Mitigation**:
- Policy intent preservation
- Policy drift detection
- Cumulative impact analysis

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can policy consistency be broken while all tests pass?

**Attack**: Tests use clear policies; production has ambiguous policies.

**Mechanism**: Policy edge cases not in test suite.

**Preconditions**:
- Test policies simple
- Production policies complex
- Edge cases untested

**Construction**:
1. Tests: Clear, unambiguous policies
2. Production: Ambiguous policy edge case
3. Edge case: Policy admits contradictory actions
4. Tests pass, production inconsistent

**Observable Signal**: Policy inconsistencies in edge cases

**Severity**: High

**Mitigation**:
- Comprehensive policy testing
- Edge case analysis
- Policy completeness verification

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can policy consistency be broken while local verification passes?

**Attack**: Local policy interpretation consistent, global inconsistent.

**Mechanism**: Different nodes interpret same policy differently.

**Preconditions**:
- Distributed policy interpretation
- Local vs global consistency
- Interpretation divergence

**Construction**:
1. Node A: Interprets policy as P_A
2. Node B: Interprets policy as P_B (incompatible)
3. Local consistency: Each node consistent internally
4. Global inconsistency: P_A ≠ P_B

**Observable Signal**: Policy interpretation divergence across nodes

**Severity**: Critical

**Mitigation**:
- Global policy consistency
- Canonical policy interpretation
- Cross-node policy validation

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can policy consistency be broken while the proof remains valid?

**Attack**: Policy not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode policy requirements.

**Preconditions**:
- Policy not constrained
- Verifier doesn't check policy
- Underconstrained system

**Construction**:
1. Policy violation in execution
2. Constraints don't verify policy
3. Proof verifies
4. Policy violation in valid proof

**Observable Signal**: Verifiable proofs violating policy

**Severity**: Catastrophic

**Mitigation**):
- Policy encoding in constraints
- Policy witness in proofs
- Policy constraint coverage

**Regression Test Required**: Yes

---

## 17. Cryptographic Binding Invariants — Attack Matrix

**Definition**: Invariants ensuring cryptographic integrity of commitments, proofs, and bindings.

**VSEL Mapping**: G_commit, Commitment consistency, proof binding

### Attack Vector Analysis

#### V1: Bypass — Can cryptographic binding be bypassed?

**Attack**: Modify committed value without detection.

**Mechanism**: Collision attack or preimage attack on commitment.

**Preconditions**:
- Weak cryptographic primitive
- Collision possible
- Binding not enforced

**Construction**:
```
Commit(v1) = c
Find v2 such that Commit(v2) = c (collision)
Replace v1 with v2, commitment unchanged
Result: Binding broken
```

**Observable Signal**: Different values with same commitment

**Severity**: Catastrophic

**Mitigation**:
- Collision-resistant hash functions
- Binding enforcement
- Cryptographic primitive verification

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can cryptographic binding be satisfied vacuously?

**Attack**: Trivial commitment scheme allows any binding.

**Mechanism**: `Commit(v) = constant` for all v.

**Preconditions**):
- Commitment not properly defined
- Default weak binding
- No cryptographic requirements

**Construction**:
```haskell
Commit(v) = 0x00...00  -- Same commitment for all values
```

**Observable Signal**: All values have same commitment

**Severity**: Catastrophic

**Mitigation**:
- Proper commitment scheme
- Cryptographic binding requirements
- Commitment uniqueness

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can cryptographic binding be weakened by configuration?

**Attack**: Reduce security level via configuration.

**Mechanism**: Governance reduces hash length or changes primitive.

**Preconditions**:
- Cryptographic parameters configurable
- Security reducible
- Governance control over cryptography

**Construction**:
1. Initial: 256-bit commitments
2. Config: Reduce to 128-bit
3. Collision resistance weakened

**Observable Signal**: Declining cryptographic security parameters

**Severity**: Critical

**Mitigation**:
- Immutable cryptographic parameters
- Minimum security levels
- No configuration of cryptography

**Regression Test Required**: Yes

---

#### V4: Reordering — Can cryptographic binding be broken by reordering?

**Attack**: Reorder commitment and value, breaking binding.

**Mechanism**: Value committed out of order with respect to binding.

**Preconditions**):
- Commitment/value ordering manipulable
- Binding order-dependent
- Reordering possible

**Construction**:
```
Intended: [Commit(v), Use(v)]
Attack:   [Use(v), Commit(v)] -- Use before commit
Result: Binding violated (used before committed)
```

**Observable Signal**: Values used before commitment

**Severity**: Critical

**Mitigation**:
- Commit-before-use enforcement
- Ordering constraints
- Binding sequence validation

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can cryptographic binding be broken by partial execution?

**Attack**: Partial commitment process leaves binding incomplete.

**Mechanism**: Multi-step commitment partially executed.

**Preconditions**:
- Commitment multi-step
- Partial execution possible
- No atomicity

**Construction**:
1. Commitment requires: [Hash, Sign, Publish]
2. Execute Hash
3. Fail before Sign
4. Binding incomplete

**Observable Signal**: Incomplete commitment processes

**Severity**: Critical

**Mitigation**:
- Atomic commitment operations
- All-or-nothing commitment
- Rollback on partial failure

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can cryptographic binding be broken by concurrency?

**Attack**: Race condition in commitment allows double-spend.

**Mechanism**: Commitment check and use race.

**Preconditions**:
- Check-then-act race
- Commitment mutable
- No synchronization

**Construction**:
```
Time 0: Check commitment (valid)
Time 1: Commitment revoked
Time 2: Use commitment (based on stale check)
Result: Use after revocation
```

**Observable Signal**: Race conditions in commitment usage

**Severity**: Critical

**Mitigation**:
- Atomic commitment validation
- Time-of-use commitment check
- Commitment locking

**Regression Test Required**: Yes

---

#### V7: Rollback — Can cryptographic binding be broken by rollback?

**Attack**: Rollback removes commitment, breaking binding.

**Mechanism**: Commitment made, then rolled back.

**Preconditions**):
- Commitment rollback possible
- Binding reversible
- No permanence

**Construction**:
1. Make commitment C for value v
2. Use commitment (relying on binding)
3. Rollback commitment C
4. Binding broken (commitment gone)

**Observable Signal**: Commitment rollback after use

**Severity**: Critical

**Mitigation**:
- Immutable commitments
- No commitment rollback
- Binding permanence

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can cryptographic binding be broken by omitted traces?

**Attack**: Hide commitment from trace, breaking auditability.

**Mechanism**: Commitment made but not recorded.

**Preconditions**):
- Commitment logging incomplete
- Verification trace-dependent
- Commitments can be hidden

**Construction**:
1. Make commitment C
2. Omit C from trace
3. Later: Claim no commitment made
4. Binding unverifiable

**Observable Signal**: Missing commitment records

**Severity**: Critical

**Mitigation**:
- Complete commitment logging
- Commitments in trace
- Binding audit trail

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can cryptographic binding be broken by ambiguous semantic mapping?

**Attack**: Ambiguous commitment encoding allows multiple interpretations.

**Mechanism**: Same commitment binds multiple values depending on interpretation.

**Preconditions**):
- Commitment encoding ambiguous
- Multiple valid interpretations
- System uses favorable interpretation

**Construction**:
1. Commitment C encodes value v
2. Interpretation A: C binds v
3. Interpretation B: C binds v' (different value)
4. System uses interpretation B

**Observable Signal**: Same commitment binding different values

**Severity**: Catastrophic

**Mitigation**:
- Unambiguous commitment encoding
- Canonical commitment format
- Binding interpretation validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can cryptographic binding be broken by an upgrade?

**Attack**: Upgrade changes cryptographic primitive, breaking old bindings.

**Mechanism**: Version 2 uses different commitment scheme.

**Preconditions**):
- Cryptographic primitives versioned
- Upgrade changes primitives
- Old bindings not preserved

**Construction**:
1. Version 1: Commitments using Scheme A
2. Upgrade to Version 2: Scheme B
3. Old commitments in Scheme A not valid in Scheme B
4. Historical bindings broken

**Observable Signal**: Commitment scheme changes breaking historical bindings

**Severity**: Critical

**Mitigation**:
- Backward-compatible primitives
- Commitment scheme migration
- Historical binding preservation

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can cryptographic binding be broken by policy drift?

**Attack**: Gradual weakening of cryptographic requirements.

**Mechanism**: Series of "modernization" changes reducing security.

**Preconditions**):
- Cryptographic policy governable
- Incremental weakening acceptable
- No cumulative analysis

**Construction**:
1. Initial: Strong primitives (SHA-3, Ed25519)
2. Policy 1: Add legacy support (SHA-1)
3. Policy 2: Reduce key lengths (performance)
4. Policy 3: Deprecate strong primitives
5. Result: Weak cryptography

**Observable Signal**: Declining cryptographic standards

**Severity**: Catastrophic

**Mitigation**:
- Immutable cryptographic requirements
- Policy cannot affect cryptography
- Minimum security standards

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can cryptographic binding be broken while all tests pass?

**Attack**: Tests use strong cryptography; production has weak configuration.

**Mechanism**: Production configuration different from tests.

**Preconditions**):
- Test/production configuration divergence
- Weak cryptography in production
- Configuration not tested

**Construction**:
1. Tests: Strong cryptography configured
2. Production: Weak cryptography configured
3. Attack: Collision on weak primitive
4. Tests pass, production vulnerable

**Observable Signal**: Production/test cryptographic configuration divergence

**Severity**: Catastrophic

**Mitigation**):
- Production-equivalent testing
- Cryptographic configuration validation
- Minimum security enforcement

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can cryptographic binding be broken while local verification passes?

**Attack**: Local binding valid, global binding invalid.

**Mechanism**: Local node verifies commitment, global verification fails.

**Preconditions**):
- Distributed commitment verification
- Local vs global distinction
- Inconsistency possible

**Construction**:
1. Local commitment C verified
2. Global: C not in global commitment set
3. Local accepts, global rejects
4. Binding inconsistency

**Observable Signal**: Local/global commitment verification divergence

**Severity**: Critical

**Mitigation**:
- Global commitment validation
- Cross-node binding verification
- Distributed commitment consensus

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can cryptographic binding be broken while the proof remains valid?

**Attack**: Cryptographic binding not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't verify commitments.

**Preconditions**):
- Binding not constrained
- Verifier doesn't check commitments
- Underconstrained system

**Construction**:
1. Invalid commitment in execution
2. Constraints don't verify binding
3. Proof verifies
4. Binding violation in valid proof

**Observable Signal**: Verifiable proofs with invalid commitments

**Severity**: Catastrophic

**Mitigation**):
- Cryptographic binding in constraints
- Commitment verification in proofs
- Binding constraint coverage

**Regression Test Required**: Yes

---

## 18. Cross-Domain Invariants — Attack Matrix

**Definition**: Invariants across system boundaries—composition safety, interface contracts, cross-system consistency.

**VSEL Mapping**: C_shared, CE_arbitrage, CE_contagion, Cross-system constraints

### Attack Vector Analysis

#### V1: Bypass — Can cross-domain invariants be bypassed?

**Attack**: Exploit cross-system interface to bypass checks.

**Mechanism**: System A's checks bypassed via System B.

**Preconditions**):
- Cross-system interface
- Checks bypassable via composition
- Interface validation weak

**Construction**:
```
System A: Requires check X for action
System B: No check X required
Attack: Action via System B, bypass System A's check
Result: Check X bypassed
```

**Observable Signal**: Actions via cross-system interfaces bypassing checks

**Severity**: Critical

**Mitigation**):
- Cross-system check propagation
- Interface validation
- Composition safety

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can cross-domain invariants be satisfied vacuously?

**Attack**: No cross-system interactions, making cross-domain invariants vacuously true.

**Mechanism**: Isolated systems have no cross-domain constraints.

**Preconditions**):
- No cross-system composition
- Invariants over empty set
- Composition not used

**Construction**:
```haskell
CrossDomain(τ) = True  -- No cross-domain interactions
```

**Observable Signal**: Cross-domain invariants not tested (no composition)

**Severity**: High

**Mitigation**):
- Composition testing
- Cross-system validation
- Non-vacuous cross-domain requirements

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can cross-domain invariants be weakened by configuration?

**Attack**: Relax cross-system constraints via configuration.

**Mechanism**: Governance reduces cross-system validation.

**Preconditions**):
- Cross-system constraints configurable
- Constraints reducible
- Governance control

**Construction**):
1. Initial: Strict cross-system validation
2. Config: Reduce validation for "performance"
3. Cross-system safety weakened

**Observable Signal**: Declining cross-system validation

**Severity**: Critical

**Mitigation**):
- Immutable cross-system constraints
- No configuration of composition safety
- Protocol-level cross-domain invariants

**Regression Test Required**: Yes

---

#### V4: Reordering — Can cross-domain invariants be broken by reordering?

**Attack**: Reorder cross-system operations to violate atomicity.

**Mechanism**: Cross-system transaction order affects consistency.

**Preconditions**):
- Cross-system operations order-dependent
- Atomicity not guaranteed
- Reordering possible

**Construction**):
```
Intended: [SystemA.commit, SystemB.commit] (atomic)
Attack:   [SystemA.commit, SystemB.abort] (partial)
Result: Cross-system inconsistency
```

**Observable Signal**: Cross-system atomicity violations

**Severity**: Critical

**Mitigation**):
- Cross-system atomicity
- Two-phase commit
- Distributed transaction coordination

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can cross-domain invariants be broken by partial execution?

**Attack**: Partial cross-system execution leaves inconsistency.

**Mechanism**: Multi-system operation partially executes.

**Preconditions**):
- Cross-system operations multi-step
- Partial execution possible
- No distributed atomicity

**Construction**):
1. Operation: [SystemA.update, SystemB.update]
2. Execute SystemA.update
3. Fail before SystemB.update
4. Systems inconsistent

**Observable Signal**: Cross-system state divergence

**Severity**: Critical

**Mitigation**):
- Distributed atomic operations
- All-or-nothing cross-system execution
- Compensating transactions

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can cross-domain invariants be broken by concurrency?

**Attack**: Concurrent cross-system operations cause inconsistency.

**Mechanism**: Race condition across system boundaries.

**Preconditions**):
- Concurrent cross-system access
- No distributed locking
- Race condition possible

**Construction**):
```
System A: Check balance X
System B: Check balance X (concurrently)
Both: Debit based on same balance
Result: Double-spend across systems
```

**Observable Signal**: Cross-system race conditions

**Severity**: Critical

**Mitigation**):
- Distributed locking
- Cross-system serialization
- Consensus before action

**Regression Test Required**: Yes

---

#### V7: Rollback — Can cross-domain invariants be broken by rollback?

**Attack**: Asymmetric rollback across systems.

**Mechanism**: One system rolls back, other doesn't.

**Preconditions**):
- Independent rollback mechanisms
- No coordinated rollback
- Asymmetric recovery

**Construction**):
1. Cross-system transaction commits on A and B
2. A rolls back (failure)
3. B doesn't roll back
4. Cross-system inconsistency

**Observable Signal**: Asymmetric rollback across systems

**Severity**: Critical

**Mitigation**):
- Coordinated rollback
- Distributed transaction integrity
- Cross-system recovery

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can cross-domain invariants be broken by omitted traces?

**Attack**: Hide cross-system interactions from trace.

**Mechanism**: Cross-system calls not recorded in either system's trace.

**Preconditions**):
- Cross-system tracing incomplete
- Interactions can be hidden
- Verification per-system only

**Construction**):
1. System A calls System B
2. Neither system records the call
3. Cross-system dependency invisible
4. Cross-domain invariant unverifiable

**Observable Signal**: Missing cross-system interaction records

**Severity**: Critical

**Mitigation**):
- Complete cross-system tracing
- Distributed trace recording
- Cross-system audit trail

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can cross-domain invariants be broken by ambiguous semantic mapping?

**Attack**: Same concept mapped differently across systems.

**Mechanism**: "Value" means different things in System A and System B.

**Preconditions**):
- Semantic mapping ambiguous
- Cross-system interpretation divergence
- Integration uses inconsistent mappings

**Construction**):
```
System A: "Value" = nominal value
System B: "Value" = real value (adjusted for inflation)
Transfer: A sends nominal 100, B receives real 100
Result: Semantic mismatch, value discrepancy
```

**Observable Signal**: Cross-system semantic mismatches

**Severity**: Critical

**Mitigation**):
- Unambiguous cross-system semantics
- Canonical interface definitions
- Semantic mapping validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can cross-domain invariants be broken by an upgrade?

**Attack**: One system upgrades, breaking cross-system compatibility.

**Mechanism**: System A upgrades, System B still on old version.

**Preconditions**):
- Independent upgrade schedules
- Version mismatch possible
- Cross-version compatibility not guaranteed

**Construction**):
1. System A on Version 1
2. System B on Version 1
3. System A upgrades to Version 2 (breaking changes)
4. Cross-system interface broken

**Observable Signal**: Cross-system failures after single-system upgrade

**Severity**: Critical

**Mitigation**):
- Coordinated upgrades
- Cross-system version compatibility
- Upgrade synchronization

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can cross-domain invariants be broken by policy drift?

**Attack**: Divergent policies across systems.

**Mechanism**: Systems' policies drift apart over time.

**Preconditions**):
- Independent policy governance
- Policy divergence possible
- No cross-system policy coordination

**Construction**):
1. Initial: Systems A and B have compatible policies
2. Policy drift: A becomes more restrictive, B more permissive
3. Cross-system operations inconsistent
4. Cross-domain invariants violated

**Observable Signal**: Policy divergence across systems

**Severity**: High

**Mitigation**):
- Cross-system policy coordination
- Policy compatibility requirements
- Distributed policy governance

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can cross-domain invariants be broken while all tests pass?

**Attack**: Tests use isolated systems; production uses composition.

**Mechanism**: Cross-system edge cases not in test suite.

**Preconditions**):
- Tests per-system only
- Composition not tested
- Cross-system edge cases uncovered

**Construction**):
1. Tests: System A passes, System B passes (isolated)
2. Production: A and B composed
3. Edge case: Cross-system interaction bug
4. Tests pass, production fails

**Observable Signal**: Cross-system failures only in production

**Severity**: Critical

**Mitigation**):
- Cross-system integration testing
- Composition testing
- End-to-end validation

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can cross-domain invariants be broken while local verification passes?

**Attack**: Local system valid, cross-system invalid.

**Mechanism**: Each system valid locally, but cross-system invariant violated.

**Preconditions**):
- Local verification only
- Cross-system validation absent
- Composition invariants not checked

**Construction**):
1. System A: Valid locally
2. System B: Valid locally
3. Cross-system: Shared state inconsistent
4. Local verification passes, cross-system fails

**Observable Signal**: Local validity, cross-system invalidity

**Severity**: Critical

**Mitigation**):
- Cross-system validation
- Composition invariant checking
- Distributed verification

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can cross-domain invariants be broken while the proof remains valid?

**Attack**: Cross-domain invariants not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't encode cross-system requirements.

**Preconditions**):
- Cross-domain invariants not constrained
- Verifier per-system only
- Underconstrained composition

**Construction**):
1. Cross-system violation in execution
2. Constraints don't verify cross-system properties
3. Proof verifies
4. Cross-domain violation in valid proof

**Observable Signal**: Verifiable proofs with cross-system violations

**Severity**: Catastrophic

**Mitigation**):
- Cross-domain invariants in constraints
- Composition encoding in proofs
- Cross-system constraint coverage

**Regression Test Required**: Yes

---

## 19. Semantic Equivalence Invariants — Attack Matrix

**Definition**: Invariants ensuring meaning preservation across layers—specification, implementation, and proof alignment.

**VSEL Mapping**: X_exec, X_constraint, X_proof, Semantic preservation

### Attack Vector Analysis

#### V1: Bypass — Can semantic equivalence be bypassed?

**Attack**: Direct implementation bypassing specification semantics.

**Mechanism**: Implementation executes behavior not in specification.

**Preconditions**):
- Implementation/specification divergence
- Specification not enforced
- Bypass path exists

**Construction**):
```
Specification: Apply(s, σ) = specific_behavior
Implementation: Apply(s, σ) = different_behavior
Result: Semantic equivalence bypassed
```

**Observable Signal**: Implementation behavior diverging from specification

**Severity**: Catastrophic

**Mitigation**):
- Implementation verification against specification
- Semantic equivalence proofs
- Specification conformance testing

**Regression Test Required**: Yes

---

#### V2: Vacuous Satisfaction — Can semantic equivalence be satisfied vacuously?

**Attack**: Specification so vague any implementation satisfies it.

**Mechanism**: `Spec(s, σ, s') ≡ True` for all transitions.

**Preconditions**):
- Specification not defined
- Default allow
- No semantic requirements

**Construction**):
```haskell
Spec(s, σ, s') = True  -- Any behavior satisfies specification
```

**Observable Signal**: Vague or missing specification

**Severity**: Catastrophic

**Mitigation**):
- Precise formal specification
- Explicit semantic requirements
- Specification completeness

**Regression Test Required**: Yes

---

#### V3: Configuration Weakening — Can semantic equivalence be weakened by configuration?

**Attack**: Relax specification conformance via configuration.

**Mechanism**: Governance allows deviations from specification.

**Preconditions**):
- Specification conformance configurable
- Deviations allowed
- Governance control over semantics

**Construction**):
1. Initial: Strict specification conformance
2. Config: Allow "optimization" deviations
3. Semantic equivalence weakened

**Observable Signal**: Specification deviations via configuration

**Severity**: Critical

**Mitigation**):
- Immutable specification conformance
- No configuration of semantics
- Strict semantic equivalence

**Regression Test Required**: Yes

---

#### V4: Reordering — Can semantic equivalence be broken by reordering?

**Attack**: Reorder specification and implementation validation.

**Mechanism**: Implementation deployed before specification validated.

**Preconditions**):
- Implementation/specification ordering flexible
- Validation after deployment
- Reordering possible

**Construction**):
```
Intended: [Specify, Validate, Implement]
Attack:   [Implement, Specify, Validate] -- Implementation first
Result: Implementation may not match specification
```

**Observable Signal**: Implementation preceding specification

**Severity**: Critical

**Mitigation**):
- Specification-first development
- Validation before implementation
- Semantic equivalence before deployment

**Regression Test Required**: Yes

---

#### V5: Partial Execution — Can semantic equivalence be broken by partial execution?

**Attack**: Partial semantic preservation leaves equivalence incomplete.

**Mechanism**: Some operations preserve semantics, others don't.

**Preconditions**):
- Semantic preservation partial
- Some paths not covered
- Equivalence incomplete

**Construction**):
1. Most operations: Preserve semantics
2. Edge case operations: Don't preserve semantics
3. General equivalence claimed
4. Edge cases violate equivalence

**Observable Signal**: Semantic preservation failures in edge cases

**Severity**: Critical

**Mitigation**):
- Complete semantic preservation
- All paths verified
- Exhaustive equivalence checking

**Regression Test Required**: Yes

---

#### V6: Concurrency — Can semantic equivalence be broken by concurrency?

**Attack**: Concurrent implementation/specification divergence.

**Mechanism**: Implementation and specification interpreted concurrently, divergent results.

**Preconditions**):
- Concurrent interpretation
- No synchronization
- Race condition possible

**Construction**):
```
Thread 1: Interpret specification (result A)
Thread 2: Execute implementation (result B)
Results: A ≠ B, semantic divergence
```

**Observable Signal**: Specification/implementation divergence under concurrency

**Severity**: Critical

**Mitigation**):
- Deterministic interpretation
- Synchronized execution
- Semantic locking

**Regression Test Required**: Yes

---

#### V7: Rollback — Can semantic equivalence be broken by rollback?

**Attack**: Rollback to version with different semantics.

**Mechanism**: Specification rolled back, implementation not (or vice versa).

**Preconditions**):
- Specification versioned
- Rollback possible
- Version mismatch

**Construction**):
1. Specification V1, Implementation V1 (equivalent)
2. Upgrade both to V2 (still equivalent)
3. Rollback specification to V1
4. Implementation still V2
5. Semantic divergence

**Observable Signal**: Specification/implementation version mismatch

**Severity**: Critical

**Mitigation**):
- Synchronized versioning
- Coordinated rollback
- Version equivalence enforcement

**Regression Test Required**: Yes

---

#### V8: Omitted Traces — Can semantic equivalence be broken by omitted traces?

**Attack**: Hide semantic divergence from trace.

**Mechanism**: Divergent execution not recorded, appears equivalent.

**Preconditions**):
- Trace recording incomplete
- Divergence can be hidden
- Verification trace-dependent

**Construction**):
1. Implementation diverges from specification
2. Divergence not recorded in trace
3. Trace shows apparent equivalence
4. Actual divergence hidden

**Observable Signal**: Semantic divergence not reflected in trace

**Severity**: Critical

**Mitigation**):
- Complete semantic trace recording
- Divergence detection
- Trace completeness

**Regression Test Required**: Yes

---

#### V9: Ambiguous Semantic Mapping — Can semantic equivalence be broken by ambiguous semantic mapping?

**Attack**: Core issue for semantic equivalence—ambiguous mapping makes equivalence undefined.

**Mechanism**: Mapping `μ: Impl → Spec` ambiguous, equivalence not well-defined.

**Preconditions**):
- Semantic mapping ambiguous
- Multiple valid interpretations
- Equivalence unclear

**Construction**):
```
Implementation state S maps to {Spec_A, Spec_B}
Spec_A: Behavior valid
Spec_B: Behavior invalid
Implementation behavior: Invalid
Claim: Equivalent to Spec_A (favorable interpretation)
```

**Observable Signal**: Same implementation mapped to different specifications

**Severity**: Catastrophic

**Mitigation**):
- Unambiguous semantic mapping (THM-1)
- Injective mapping
- Semantic mapping validation

**Regression Test Required**: Yes

---

#### V10: Upgrade Exploitation — Can semantic equivalence be broken by an upgrade?

**Attack**: Upgrade changes semantics, breaking equivalence with old proofs.

**Mechanism**: New version has different semantics, old proofs no longer valid.

**Preconditions**):
- Semantics versioned
- Upgrade changes semantics
- Old equivalence broken

**Construction**):
1. Version 1: Spec A, Impl A, Proof of equivalence
2. Upgrade to Version 2: Spec B, Impl B
3. Old proofs claim equivalence to Spec A
4. Spec A ≠ Spec B, old proofs invalid

**Observable Signal**: Semantic changes breaking historical equivalence

**Severity**: Critical

**Mitigation**):
- Immutable core semantics
- Upgrade semantic compatibility
- Equivalence preservation across versions

**Regression Test Required**: Yes

---

#### V11: Policy Drift — Can semantic equivalence be broken by policy drift?

**Attack**: Gradual semantic drift through "clarifications."

**Mechanism**: Series of semantic "adjustments" diverging from original.

**Preconditions**):
- Semantics governable
- Incremental changes acceptable
- No cumulative analysis

**Construction**):
1. Initial: Precise semantics
2. Policy 1: "Clarify" edge case (actually change)
3. Policy 2: "Simplify" complex case (remove detail)
4. Policy 3: "Optimize" common case (change behavior)
5. Result: Semantics substantially changed

**Observable Signal**: Semantic drift through policy updates

**Severity**: Critical

**Mitigation**):
- Immutable semantics
- Policy cannot change meaning
- Semantic stability guarantees

**Regression Test Required**: Yes

---

#### V12: Test Passage — Can semantic equivalence be broken while all tests pass?

**Attack**: Tests check syntactic equivalence, miss semantic divergence.

**Mechanism**: Implementation and specification produce same outputs for tested inputs, different semantics for untested.

**Preconditions**):
- Test coverage incomplete
- Semantic equivalence not fully tested
- Edge cases uncovered

**Construction**):
1. Tests: Input/Output equivalence verified
2. Production: Untested input produces different semantics
3. Implementation and specification diverge semantically
4. Tests pass, semantics diverge

**Observable Signal**: Syntactic equivalence, semantic divergence

**Severity**: Critical

**Mitigation**):
- Semantic equivalence testing
- Exhaustive input coverage
- Formal equivalence proofs

**Regression Test Required**: Yes

---

#### V13: Local Verification Passage — Can semantic equivalence be broken while local verification passes?

**Attack**: Local semantic equivalence valid, global invalid.

**Mechanism**: Component semantics locally equivalent, system semantics diverge.

**Preconditions**):
- Local equivalence only
- Global composition not checked
- Composition failures

**Construction**):
1. Component A: Locally equivalent to spec
2. Component B: Locally equivalent to spec
3. Composition A+B: Not equivalent to composed spec
4. Local verification passes, global fails

**Observable Signal**: Local equivalence, global divergence

**Severity**: Critical

**Mitigation**):
- Global semantic equivalence
- Composition verification
- End-to-end equivalence checking

**Regression Test Required**: Yes

---

#### V14: Proof Validity Preservation — Can semantic equivalence be broken while the proof remains valid?

**Attack**: Semantic equivalence not in constraints; violated in valid proof.

**Mechanism**: Constraint system doesn't verify semantic preservation.

**Preconditions**):
- Semantic equivalence not constrained
- Verifier checks only constraints, not semantics
- Underconstrained system

**Construction**):
1. Implementation diverges from specification
2. Constraints satisfied (syntactically)
3. Proof verifies
4. Semantic equivalence violated in valid proof

**Observable Signal**: Verifiable proofs with semantic divergence

**Severity**: Catastrophic

**Mitigation**):
- Semantic equivalence in constraints
- Semantic preservation encoding
- Equivalence constraint coverage

**Regression Test Required**: Yes

---

## 20. Cross-Cutting Attack Patterns

### Pattern A: Multi-Layer Invariant Collapse

**Description**: Multiple invariants collapse simultaneously when a single assumption is violated at a lower layer.

**Example**: Cryptographic binding failure (`V14`) cascades to:
- Trace integrity failure (no commitment to verify trace)
- Safety failure (invalid states committed as valid)
- Economic failure (value extraction via forged commitments)
- Governance failure (invalid governance actions committed)

**Mitigation**: Defense in depth; each layer assumes lower layers may fail.

**Regression Test Required**: Yes

---

### Pattern B: Temporal Accumulation Attacks

**Description**: Small per-step violations accumulate over time to violate global invariants.

**Example**: Rounding error `0.0001` per transaction, `10^6` transactions = `100` units extracted.

**Detection**: Requires long-trace analysis, not per-step verification.

**Mitigation**: Bounded accumulation, cumulative error tracking.

**Regression Test Required**: Yes

---

### Pattern C: Proof-Validity Blindness

**Description**: System accepts proof as guarantee, ignoring that proof verifies wrong property.

**Root Cause**: Specification/proof/execution misalignment. Proof proves `Property A`, system needs `Property B`.

**Mitigation**: Specification-first proofs, property verification, semantic preservation validation.

**Regression Test Required**: Yes

---

### Pattern D: Configuration Cascade

**Description**: Single configuration change cascades through multiple invariants, weakening them all.

**Example**: Governance reduces security parameter, affecting:
- Cryptographic binding (weaker commitments)
- Access control (fewer checks required)
- Economic invariants (larger bounds)
- Safety invariants (weaker validation)

**Mitigation**: Configuration impact analysis, invariant preservation under config changes.

**Regression Test Required**: Yes

---

## 21. Severity Assessment Summary

### Catastrophic (System Compromise)

**Invariants**: Safety (V14), Economic (V14), Cryptographic Binding (V1, V2, V14), Semantic Equivalence (V9, V14), Conservation (V1, V6, V14), Access Control (V14), Trace Integrity (V14), Cross-Domain (V14)

**Common Vectors**: Proof validity preservation (V14) is catastrophic across all invariant classes when the constraint system is underconstrained.

---

### Critical (Major Functionality Compromise)

**Invariants**: Safety (V1, V4, V5, V6, V13), Liveness (V1, V4, V6, V13, V14), Authorization (V1, V3, V5, V6, V9, V10, V14), Economic (V1, V3, V4, V5, V9, V10, V13, V14), Governance (V1, V3, V4, V5, V6, V9, V10, V14), State Transition (V1, V4, V5, V6, V9, V10, V13, V14), Temporal (V1, V4, V6, V9, V14), Ordering (V1, V4, V5, V6, V13, V14), Conservation (V3, V4, V5, V7, V9, V10, V11, V13), Access Control (V1, V3, V5, V6, V10, V12, V13, V14), Upgrade (V1, V3, V4, V5, V6, V10, V14), Trace Integrity (V1, V3, V5, V7, V9, V12), Policy Consistency (V1, V3, V7, V9, V10, V13, V14), Cross-Domain (V1, V3, V4, V5, V6, V10, V12, V13)

---

### High (Significant Risk)

**Invariants**: Safety (V2, V3, V7, V8, V11, V12), Liveness (V2, V3, V7, V8, V10, V11, V12), Authorization (V2, V4, V7, V8, V11), Economic (V7, V8, V11, V12), Governance (V2, V7, V8, V11, V12), State Transition (V2, V3, V7, V8, V11, V12), Temporal (V2, V3, V7, V10, V11, V12, V13), Ordering (V2, V3, V7, V8, V10, V11), Conservation (V2, V8, V12), Access Control (V2, V4, V7, V8, V11), Upgrade (V2, V7, V8, V11, V12, V13), Trace Integrity (V2, V4, V10, V11), Policy Consistency (V2, V4, V5, V6, V8, V11, V12), Cryptographic Binding (V3, V4, V5, V7, V11, V12), Cross-Domain (V2, V7, V8, V9, V11), Semantic Equivalence (V2, V4, V5, V7, V8, V10, V11, V12, V13)

---

### Medium (Moderate Risk)

**Invariants**: Liveness (V5, V8, V9), Authorization (V12), Economic (V6), Temporal (V5, V8, V9), Ordering (V8, V9), Trace Integrity (V5), Policy Consistency (V9)

---

## 22. Mitigation Hierarchy

### Level 1: Specification Correctness

Invariants must be:
- Precisely defined
- Complete (no gaps)
- Unambiguous

Without correct specification, no implementation or proof can be correct.

---

### Level 2: Implementation Fidelity

Implementation must:
- Conform to specification
- Have no bypass paths
- Be exhaustively tested

Implementation bugs are the most common source of invariant violations.

---

### Level 3: Constraint Completeness

Constraints must:
- Encode all invariants
- Be sound (no false positives)
- Be complete (no false negatives)

Underconstrained systems admit valid proofs for invalid executions.

---

### Level 4: Verification Rigor

Verification must:
- Check the right properties
- Not rely on proof validity alone
- Include semantic validation

Proof of wrong property is worse than no proof.

---

### Level 5: Operational Integrity

Operations must:
- Preserve invariants under configuration changes
- Resist policy drift
- Maintain cross-version compatibility

Invariants must survive deployment, not just design.

---

## 23. Validation Requirements

For each invariant class, the following must be validated:

1. **Existence**: Invariant is formally defined
2. **Testability**: Invariant can be tested (adversarially)
3. **Constraint Encoding**: Invariant is encoded in constraints
4. **Proof Integration**: Invariant is verified in proofs
5. **Operational Enforcement**: Invariant holds in operation

If any requirement is missing, the invariant is illusory.

---

## 24. Regression Test Suite Requirements

For each attack vector in each invariant class, a regression test must exist:

**Test Structure**:
```rust
#[test]
fn test_SAFETY_V14_underconstraint_exploit() {
    // Attempt to violate safety while proof remains valid
    let invalid_execution = construct_invalid_execution();
    let proof = generate_proof(&invalid_execution);
    
    // This SHOULD fail - proof should not verify for invalid execution
    assert!(!verify(proof), "Underconstrained system accepted invalid execution");
}
```

**Coverage Requirement**: All 224 attack vectors (16 classes × 14 vectors) must have regression tests.

---

## 25. Closing Statement

This invariant attack matrix is not merely documentation of potential failures. It is a systematic enumeration of every way VSEL could be wrong while appearing to be right.

The adversary assumed in this matrix is not external. It is the system itself—its complexity, its assumptions, its blind spots. Every invariant class tested against every attack vector represents a commitment: we have asked this question, and we have an answer.

If an entry in this matrix is empty—if we cannot say how an invariant resists a given attack vector—then we do not know whether the invariant holds. Unknown is not safe. Unknown is vulnerable.

The goal of VSEL is not to have many invariants. It is to have invariants that survive adversarial scrutiny. This matrix is the scrutiny.

If your invariant cannot withstand these attacks, it is not an invariant. It is a hope.

---

*Document Version*: 1.0  
*Stage*: 4 (Invariant Adversarial Testing)  
*Classification*: Security Critical  
*Distribution*: Internal Audit Team, Core Protocol Engineers