# VSEL Cairo Reference State Machine

This directory contains a minimal Starknet/Cairo execution target for VSEL semantic binding tests. It is deliberately small enough to audit line-by-line, but it is real Scarb code, not pseudocode.

The layout separates incompatible Cairo target modes:

- `semantic_core/`: pure Cairo transition system used by every target.
- root package: Starknet contract target that emits Sierra and CASM.
- `executable/`: executable target used by `scarb execute`, `scarb prove`, and `scarb verify`.

## Toolchain

The package is pinned to the toolchain available during creation:

- `scarb 2.16.0`
- `cairo 2.16.0`
- `sierra 1.7.0`
- `snforge 0.57.0`

The expected local commands for the contract target are:

```sh
scarb build
snforge test
```

The expected local commands for the executable/proof target are:

```sh
cd executable
scarb execute --arguments-file inputs/valid_transition.json --print-program-output
scarb prove --execute --arguments-file inputs/valid_transition.json
scarb verify --execution-id <execution-id-produced-by-prove>
```

`scarb build` in the root package produces Sierra and CASM artifacts under `target/dev/`. `scarb prove` in `executable/` produces a Stwo proof under `executable/target/execute/.../proof/proof.json`. The generated `artifacts/HASHES.md` records the concrete artifact hashes produced locally; this session verified `execution6`.

## State Machine

The contract state is:

```text
S = (counter, version, last_transition_id, sealed, last_observable)
```

The admissible transitions are partial functions:

```text
Apply(transition_id, expected_version, delta, actor)
Seal(transition_id, expected_version, actor)
```

`Apply` is defined only when:

```text
sealed = false
delta != 0
delta <= MAX_DELTA
expected_version = version
transition_id = last_transition_id + 1
counter + delta <= MAX_COUNTER
```

It produces:

```text
counter' = counter + delta
version' = version + 1
last_transition_id' = transition_id
sealed' = false
last_observable' = C("APPLY", transition_id, expected_version, counter, delta, counter', actor)
```

`Seal` is defined only when:

```text
sealed = false
expected_version = version
transition_id = last_transition_id + 1
```

It produces:

```text
counter' = counter
version' = version + 1
last_transition_id' = transition_id
sealed' = true
last_observable' = C("SEAL", transition_id, expected_version, counter, 0, counter, actor)
```

`C(...)` is a deterministic Cairo-field observable commitment used for trace binding in this example. It is not a cryptographic hash, not a proof, and not a substitute for a Cairo/STARK verifier.

## Executable Invariants

The contract exposes `invariant_holds()` and enforces the following invariants through transition guards:

```text
I1: counter <= MAX_COUNTER
I2: version = last_transition_id
I3: sealed = true => Apply is rejected
I4: each accepted transition_id equals the previous last_transition_id + 1
I5: last_observable equals the deterministic commitment of the latest accepted transition
```

The tests cover successful ordered execution, sealing, zero delta rejection, version mismatch rejection, transition-order rejection, delta-bound rejection, and rejection after sealing.

## Proof Status

This example generated and verified a local Stwo proof through Scarb 2.16.0:

```sh
cd executable
scarb prove --execute --arguments-file inputs/valid_transition.json
scarb verify --execution-id <execution-id-produced-by-prove>
```

This is not VSEL final acceptance. The Scarb/Stwo proof is a native Cairo proof artifact, but it is not packaged as VCAI/v1 and is not bound to VSEL witness, constraint, public-input, Lean-certificate, and adapter-certificate commitments. VSEL final acceptance still requires `CairoStarkBackend` plus a pinned Stone/Stwo command adapter that emits a verifier certificate bound to verifier version/hash, Cairo source hash, Sierra hash, CASM hash, executable program hash, Cairo trace hash, public input hash, constraint commitment, statement hash, proof hash, and verifier transcript hash.

The proof target and deployment target are deliberately separated: `executable/`
is the Scarb executable used for local proving, while the root package emits the
Starknet contract Sierra/CASM. A VSEL adapter must bind their common
`semantic_core` source hash and the executable artifact hash before treating an
executable proof as evidence for the contract transition semantics.

The purpose of this directory is explicit:

1. provide a real Cairo/Starknet execution target;
2. produce reproducible Sierra/CASM artifacts;
3. record concrete hashes for the Cairo source and compiled artifacts;
4. generate a local Scarb/Stwo proof fixture;
5. define a precise VSEL-to-Cairo semantic mapping that a native Cairo/STARK adapter must bind.

Any claim that Scarb proof verification alone proves VSEL semantic correctness would be false.

## Files

- `semantic_core/src/lib.cairo`: pure transition system and invariants.
- `Scarb.toml`: pinned Scarb/Starknet/Foundry contract package definition.
- `src/reference_contract.cairo`: Starknet contract wrapper over the pure transition system.
- `executable/Scarb.toml`: executable/provable package using the same semantic core.
- `executable/src/lib.cairo`: `#[executable]` entrypoint.
- `tests/test_reference_state_machine.cairo`: Starknet Foundry tests.
- `VSEL_MAPPING.md`: semantic mapping from VSEL concepts to Cairo artifacts.
- `artifacts/HASHES.md`: generated local hash manifest after clean build/prove/verify.
