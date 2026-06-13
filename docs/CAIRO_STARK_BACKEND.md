# Cairo/STARK Native Backend Feature

The `vsel-proof` feature `cairo-stark-backend` exposes fail-closed constructors
for Stone/Stwo/Scarb command adapters and a checked-in VSEL-aware native wrapper
binary:

```bash
cargo test -p vsel-proof --features cairo-stark-backend
cargo build -p vsel-proof --features cairo-stark-backend --bin vsel-cairo-native-wrapper
```

This feature does not vendor Stone, Stwo, SHARP, Scarb, Cairo, or a verifier
binary. It enables the Rust API that constructs a pinned native command adapter
after external commands have been pinned by version and SHA3-256 digest. The
`vsel-cairo-native-wrapper` binary is the VSEL command adapter: it consumes the
native proof artifact, recomputes configured program and trace hashes, invokes
the configured native verifier, packages canonical VCAI/v1 bytes, and emits a
complete verifier certificate only after native acceptance.

Absence of a command, digest mismatch, ambiguous adapter identity, missing
program or trace artifact paths, malformed VCAI/v1 proof bytes, verifier-version
drift, verifier-binary drift, program-hash drift, trace-hash drift, missing
native context attestation, native context mismatch, or native verifier rejection
is verification failure.

## Environment Contract

Stone:

```text
VSEL_STONE_CAIRO_VERSION=<version-id>
VSEL_STONE_CAIRO_PROVER=<absolute-path-to-vsel-stone-prover-adapter>
VSEL_STONE_CAIRO_PROVER_SHA3_256=<64-hex-sha3-256>
VSEL_STONE_CAIRO_VERIFIER=<absolute-path-to-vsel-stone-verifier-adapter>
VSEL_STONE_CAIRO_VERIFIER_SHA3_256=<64-hex-sha3-256>
```

Stwo:

```text
VSEL_STWO_CAIRO_VERSION=<version-id>
VSEL_STWO_CAIRO_PROVER=<absolute-path-to-vsel-stwo-prover-adapter>
VSEL_STWO_CAIRO_PROVER_SHA3_256=<64-hex-sha3-256>
VSEL_STWO_CAIRO_VERIFIER=<absolute-path-to-vsel-stwo-verifier-adapter>
VSEL_STWO_CAIRO_VERIFIER_SHA3_256=<64-hex-sha3-256>
```

Scarb:

```text
VSEL_SCARB_CAIRO_VERSION=<version-id>
VSEL_SCARB_CAIRO_PROVER=<absolute-path-to-vsel-cairo-native-wrapper>
VSEL_SCARB_CAIRO_PROVER_SHA3_256=<64-hex-sha3-256>
VSEL_SCARB_CAIRO_VERIFIER=<absolute-path-to-vsel-cairo-native-wrapper>
VSEL_SCARB_CAIRO_VERIFIER_SHA3_256=<64-hex-sha3-256>
```

Configured positive E2E tests also require the program commitment environment:

```text
VSEL_CAIRO_PROGRAM_HASH=<64-hex-sha3-256>
VSEL_CAIRO_SIERRA_PROGRAM_HASH=<64-hex-sha3-256>
VSEL_CAIRO_CASM_PROGRAM_HASH=<64-hex-sha3-256>
VSEL_CAIRO_EXECUTABLE_PROGRAM_HASH=<64-hex-sha3-256>
```

The configured commands must speak the VSEL command protocol implemented by
`CommandCairoAdapter`. A raw native binary is acceptable only if it implements
that stdin/stdout contract directly. Otherwise the configured path must point
to a thin adapter wrapper that invokes the native Stone/Stwo prover or verifier
and emits VSEL output only after native acceptance.

The checked-in wrapper binary is:

```text
protocol/crates/vsel-proof/src/bin/vsel-cairo-native-wrapper.rs
```

It is configured through these environment variables:

```text
VSEL_CAIRO_NATIVE_VERIFY_COMMAND=<shell command that invokes scarb/stone/stwo verification>
VSEL_CAIRO_NATIVE_WORKDIR=<optional working directory for the native command>
VSEL_CAIRO_NATIVE_PROOF_PATH=<path to native proof artifact used for packaging>
VSEL_CAIRO_NATIVE_TRACE_PATH=<path to Cairo trace/prover-input artifact>
VSEL_CAIRO_PROGRAM_PATH=<path to canonical Cairo source-manifest artifact>
VSEL_CAIRO_SIERRA_PROGRAM_PATH=<path to Sierra artifact>
VSEL_CAIRO_CASM_PROGRAM_PATH=<path to CASM/compiled-contract artifact>
VSEL_CAIRO_EXECUTABLE_PROGRAM_PATH=<path to executable proof-target artifact>
VSEL_CAIRO_SEMANTIC_BINDING_PATH=<path to canonical Cairo semantic-binding report>
```

The native verify command receives deterministic environment variables such as
`VSEL_CAIRO_REQUEST_PROOF_PATH`, `VSEL_CAIRO_REQUEST_STATEMENT_HASH`,
`VSEL_CAIRO_REQUEST_PROOF_HASH`, `VSEL_CAIRO_REQUEST_CAIRO_TRACE_HASH`,
`VSEL_CAIRO_REQUEST_SEMANTIC_BINDING_HASH`,
`VSEL_CAIRO_REQUEST_PUBLIC_INPUT_HASH`, and
`VSEL_CAIRO_REQUEST_CONSTRAINT_COMMITMENT`. A raw `scarb verify` invocation is
not sufficient because it does not consume the VSEL statement fields. The
configured command must run the native verifier and then emit the native context
attestation below, after checking that the accepted native proof corresponds to
the same VSEL statement. The wrapper also checks that the configured native
proof path bytes match the embedded VCAI proof bytes during verification.
For the reference Scarb path, `cairo_program_hash` is the SHA3-256 digest of a
canonical `VSEL_CAIRO_SOURCE_MANIFEST_V1` file that enumerates the semantic
core, Starknet wrapper, executable entrypoint, input fixture, and Scarb lock
artifacts. The Lean semantic certificate carries this same digest as
`cairo_source_manifest_hash` and requires the `cairo:source_manifest_binding`
obligation, so final acceptance cannot silently reinterpret the Cairo program
commitment as an untyped blob.
For the reference Scarb path, `semantic_binding_hash` is the SHA3-256 digest of
a canonical `VSEL_CAIRO_SEMANTIC_BINDING_V1` report that records the shared
semantic-core source hash, contract-wrapper source hash, executable-entrypoint
source hash, and the booleans proving that the contract/executable delegate to
the shared semantic core. The Lean semantic certificate requires
`cairo_semantic_binding_hash` and the
`cairo:semantic_binding_report_binding` obligation.
The checked-in wrapper validates this manifest before VCAI/v1 packaging: the
header must match `VSEL_CAIRO_SOURCE_MANIFEST_V1`, every entry must be
`relative/path 64-hex-sha3-256`, duplicate/absolute/parent-directory paths are
rejected, and the manifest must bind at least semantic-core sources, executable
proof-target sources, and Scarb lockfile dependency resolution.
It also validates the semantic-binding report before VCAI/v1 packaging: the
header must match `VSEL_CAIRO_SEMANTIC_BINDING_V1`, all path/digest fields must
be present and well-formed, and all semantic delegation booleans must be `true`.

```text
VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1
backend_id=cairo-stark/<adapter-id>
cairo_program_hash=<64-hex-sha3-256>
sierra_program_hash=<64-hex-sha3-256>
casm_program_hash=<64-hex-sha3-256>
executable_program_hash=<64-hex-sha3-256>
semantic_binding_hash=<64-hex-sha3-256>
cairo_trace_hash=<64-hex-sha3-256>
public_input_hash=<64-hex-sha3-256>
constraint_commitment=<64-hex-sha3-256>
statement_hash=<64-hex-sha3-256>
proof_hash=<64-hex-sha3-256>
accepted=true
END
```

Every attested field is compared against the statement reconstructed internally
by the wrapper. Missing attestation, duplicate fields, malformed hashes, and any
field mismatch fail closed before VCAI/v1 bytes or a verifier certificate can be
emitted.

## Adapter Identity

The constructed adapter id is:

```text
<stone|stwo|scarb>-<version>-prover-<prover_sha3_256>-verifier-<verifier_sha3_256>
```

`CairoStarkBackend` uses this as:

```text
cairo-stark/<adapter-id>
```

The backend id is then bound into proof metadata, VCAI/v1 artifact fields, and
the native verifier certificate. The certificate also carries the verifier
version and verifier binary SHA3-256 digest, and the pinned native adapter
rejects certificates whose self-reported version or digest does not match the
validated command configuration. This prevents relabeling a proof across
adapter families, versions, or verifier binaries.

## Verifier Certificate Contract

The verifier command must emit:

```text
VSEL_CAIRO_VERIFIER_CERTIFICATE_V1
adapter_id=<adapter-id>
verifier_version=<version-id>
verifier_binary_hash=<64-hex-sha3-256>
backend_id=cairo-stark/<adapter-id>
cairo_program_hash=<64-hex-sha3-256>
sierra_program_hash=<64-hex-sha3-256>
casm_program_hash=<64-hex-sha3-256>
executable_program_hash=<64-hex-sha3-256>
semantic_binding_hash=<64-hex-sha3-256>
cairo_trace_hash=<64-hex-sha3-256>
public_input_hash=<64-hex-sha3-256>
constraint_commitment=<64-hex-sha3-256>
statement_hash=<64-hex-sha3-256>
proof_hash=<64-hex-sha3-256>
transcript_hash=<64-hex-sha3-256>
accepted=true
```

The VCAI/v1 artifact is rejected unless the certificate fields match the
artifact fields exactly. `accepted=true` is not sufficient: every explicit
program, executable, semantic-binding, trace, public-input, constraint,
statement, proof, transcript, adapter, version, and verifier-binary binding is
checked before the backend can report cryptographic consistency.

## Non-Goals

The feature does not prove that a Cairo reference program is semantically
correct. It only provides the fail-closed operational bridge required for a
real native Cairo/STARK proof artifact to enter the existing VSEL verification
pipeline. Final acceptance still requires:

* `BackendProver<CairoStarkBackend<_>>`
* `BackendCryptographicVerifier<CairoStarkBackend<_>>`
* canonical VCAI/v1 proof bytes
* exact program, public-input, trace, constraint, statement, proof, verifier
  version/hash, and transcript binding
* `verify_strict_trace`
* executable Lean semantic-certificate checking with Cairo obligations

## Current Cairo Example

The repository includes a reproducible Cairo reference example at:

```text
examples/cairo/reference_state_machine/
```

It contains a pure semantic core, a Starknet contract target that emits Sierra
and CASM, a separate executable target, Starknet Foundry tests, and a local
Scarb/Stwo proof path:

```sh
cd examples/cairo/reference_state_machine
scarb build
snforge test

cd executable
scarb prove --execute --arguments-file inputs/valid_transition.json
scarb verify --execution-id <execution-id-produced-by-prove>
```

The example records artifact hashes in `artifacts/HASHES.md`.

The checked-in pre-production gate regenerates and verifies this path:

```sh
bash scripts/preproduction_acceptance.sh
```

The gate builds the Lean checker, builds and tests the Cairo reference target,
generates a fresh Scarb/Stwo proof, verifies it natively, packages it as VCAI/v1,
verifies it through `BackendCryptographicVerifier<CairoStarkBackend<_>>`, runs
`verify_strict_trace`, executes the Lean semantic-certificate checker, and runs
adversarial proof-tampering tests. It writes
`target/preproduction/acceptance-report.json` with the toolchain versions, Scarb
execution id, SHA3-256/SHA-256 hashes of the canonical
`VSEL_CAIRO_SOURCE_MANIFEST_V1`, SHA3-256/SHA-256 hashes of
`VSEL_CAIRO_SEMANTIC_BINDING_V1`, and SHA-256 hashes of the generated
`proof.json` and `prover_input.json`. The semantic-binding report records the
semantic-core, contract-wrapper, and executable-entrypoint hashes and fails the
gate if the contract/executable stop delegating to the shared semantic core. The
The same manifest and semantic-binding paths are passed into
`tests/cairo_acceptance_drill.rs`, which checks them byte-for-byte before using
them as VCAI Cairo program commitments.
The Scarb execution id is passed into
`tests/cairo_acceptance_drill.rs` with `VSEL_REQUIRE_REAL_SCARB_ACCEPTANCE=1`, so
a missing native proof fixture is a failure rather than a skipped positive test.

The executable proof target and Starknet contract target are distinct compiler
outputs. A production VCAI wrapper must bind the executable artifact hash and
the shared semantic-core source hash, then check or attest that the executable
entrypoint invokes the same transition and invariant functions used by the
contract wrapper. A native proof over the executable target is not, by itself,
a proof over the deployed contract CASM.

## Checked-in Native Wrapper Status

The repository now includes the wrapper needed by the native command adapter
contract. `vsel-cairo-native-wrapper` implements both VSEL command modes:

```text
VSEL_CAIRO_PROVE_REQUEST_V1  -> proof_hex=<canonical VCAI/v1 bytes>
VSEL_CAIRO_VERIFY_REQUEST_V1 -> VSEL_CAIRO_VERIFIER_CERTIFICATE_V1
```

The wrapper's acceptance invariant is:

```text
emit(VCAI/v1 or certificate)
  => configured program artifacts hash to the expected program commitments
  && configured trace artifact hashes to cairo_trace_hash
  && native proof bytes are present and non-empty
  && configured native verifier exits successfully
  && native verifier emits a VSEL context attestation for the same statement
  && adapter id, version, verifier hash, statement hash, proof hash, and transcript hash are bound
```

This closes the adapter-wrapper gap. It does not remove the higher-level VSEL
requirements: the resulting VCAI/v1 artifact is cryptographic evidence only
until `verify_strict_trace` also checks witness, constraints, deterministic
trace replay, and executable/mechanized semantic evidence.
