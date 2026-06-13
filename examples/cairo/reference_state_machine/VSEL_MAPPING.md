# VSEL to Cairo Mapping

This document defines the mapping boundary for the Cairo reference state machine. It is intentionally concrete: every VSEL concept listed here maps either to executable Cairo state, a transition guard, an emitted observable, a generated compiler artifact, or a documented non-goal.

## Semantic Intent

The intended behavior is a bounded monotonic counter state machine with explicit transition ordering and finalization.

```text
Intent:
  accept only ordered transitions;
  require caller-provided expected_version to match current version;
  allow only bounded positive deltas before finalization;
  reject all Apply transitions after Seal;
  expose enough observable data for an external VSEL trace to bind before/after state.
```

Machine-readable locus:

- `semantic_core/src/lib.cairo`, function `apply_transition`
- `semantic_core/src/lib.cairo`, function `seal`
- `semantic_core/src/lib.cairo`, function `invariant_holds`
- `src/reference_contract.cairo`, Starknet persistence wrapper
- `executable/src/lib.cairo`, executable/provable entrypoint
- Starknet events `TransitionApplied` and `MachineSealed`

## State

```text
counter: u64
version: u64
last_transition_id: u64
sealed: bool
last_observable: felt252
```

VSEL state root binding for this example must include all five fields. Omitting `sealed` or `last_transition_id` is unsound because it permits replay or post-finalization ambiguity.

## Inputs

`Apply` input:

```text
(transition_id: u64, expected_version: u64, delta: u64, actor: felt252)
```

`Seal` input:

```text
(transition_id: u64, expected_version: u64, actor: felt252)
```

`actor` is semantic metadata supplied to the contract and event stream. It is not treated as Starknet account authentication. A production adapter must separately bind Starknet caller/account identity if authorization is part of the claim.

## Transitions

Accepted `Apply` transition relation:

```text
Pre:
  sealed = false
  0 < delta <= 1000
  expected_version = version
  transition_id = last_transition_id + 1
  counter + delta <= 1000000

Post:
  counter' = counter + delta
  version' = version + 1
  last_transition_id' = transition_id
  sealed' = false
  last_observable' = C("APPLY", transition_id, expected_version, counter, delta, counter', actor)
```

Accepted `Seal` transition relation:

```text
Pre:
  sealed = false
  expected_version = version
  transition_id = last_transition_id + 1

Post:
  counter' = counter
  version' = version + 1
  last_transition_id' = transition_id
  sealed' = true
  last_observable' = C("SEAL", transition_id, expected_version, counter, 0, counter, actor)
```

All other executions are violation states and must be rejected by the Cairo runtime or by any VSEL trace verifier interpreting this contract.

## Observables

The observable event schema is:

```text
TransitionApplied(
  transition_id,
  actor,
  previous_version,
  next_version,
  previous_counter,
  delta,
  next_counter,
  observable_commitment
)

MachineSealed(
  transition_id,
  actor,
  previous_version,
  next_version,
  counter,
  observable_commitment
)
```

The observable commitment is:

```text
C(kind, transition_id, expected_version, previous_counter, delta, next_counter, actor)
  = "VSEL_REF_SM_V1"
  + kind
  + actor
  + 3  * transition_id
  + 5  * expected_version
  + 7  * previous_counter
  + 11 * delta
  + 13 * next_counter
```

This commitment is intentionally not advertised as collision-resistant. It is a deterministic executable binding point for the example trace. A real Cairo/STARK backend must bind the native Cairo trace, public inputs, program hash, and proof transcript.

## Invariants

| ID | Invariant | Enforcement |
| --- | --- | --- |
| I1 | `counter <= 1000000` | `apply_transition` post-state guard and `invariant_holds()` |
| I2 | `version = last_transition_id` | ordered transition rule on both transitions |
| I3 | `sealed => Apply rejected` | `apply_transition` sealed guard |
| I4 | `transition_id = previous(last_transition_id) + 1` | transition guard |
| I5 | `last_observable = C(latest accepted transition)` | transition assignment and tests |

## VSEL Binding Requirements

A VSEL trace verifier for this example must bind:

1. semantic core source hash;
2. Starknet contract source hash;
3. Sierra contract class hash or artifact hash;
4. CASM compiled class hash or artifact hash;
5. executable entrypoint source hash;
6. executable compiled artifact hash if the Scarb/Stwo proof path is used;
7. ordered calldata for each accepted transition;
8. before/after values of all five state variables;
9. emitted event payloads;
10. rejection evidence for invalid transitions if a failed execution is part of the trace;
11. exact Scarb/Cairo/Sierra/SNForge versions;
12. executable proof artifact hash if the Scarb/Stwo proof path is used.

Binding only the event count, only the final counter, or only proof acceptance is insufficient.

The Starknet contract target and the Scarb executable target are not the same
compiled object. A VSEL adapter that uses the executable proof path must also
bind the shared `semantic_core` hash and prove, check, or explicitly attest
that the executable entrypoint exercises the same transition functions and
invariant predicates exposed by the contract wrapper. A native proof over the
executable target must not be reinterpreted as a proof over the deployed
contract CASM without this equivalence binding.

## Non-Goals

This example does not provide:

- a VCAI/v1 proof package;
- a Stone/Stwo/SHARP adapter certificate bound to verifier version/hash,
  Cairo source hash, Sierra hash, CASM hash, executable program hash, Cairo
  trace hash, public input hash, constraint commitment, statement hash, proof
  hash, and transcript hash;
- account authorization semantics;
- gas-cost policy;
- cross-contract composition;
- reorg/finality handling;
- cryptographic replay protection outside the contract execution environment.
