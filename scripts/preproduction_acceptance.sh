#!/usr/bin/env bash
# VSEL pre-production acceptance gate.
#
# This gate is intentionally stricter than the default developer test script.
# It fails closed on missing native Cairo tooling, missing Lean checker support,
# wrapper/adaptor regression, and a skipped real Scarb/Stwo acceptance drill.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTOCOL_DIR="$PROJECT_ROOT/protocol"
CAIRO_REFERENCE_DIR="$PROJECT_ROOT/examples/cairo/reference_state_machine"
CAIRO_EXECUTABLE_DIR="$CAIRO_REFERENCE_DIR/executable"
REPORT_DIR="$PROJECT_ROOT/target/preproduction"
REPORT_FILE="$REPORT_DIR/acceptance-report.json"
SOURCE_MANIFEST_FILE="$REPORT_DIR/cairo-source-manifest.txt"
SEMANTIC_BINDING_FILE="$REPORT_DIR/cairo-semantic-binding.txt"

STATUS="failed"
REPORT_WRITTEN=0
EXECUTION_ID=""
NATIVE_EXECUTION_DIR=""
NATIVE_PROOF_JSON=""
NATIVE_PROVER_INPUT_JSON=""
NATIVE_PROOF_SHA256=""
NATIVE_PROVER_INPUT_SHA256=""
SOURCE_MANIFEST_SHA3_256=""
SOURCE_MANIFEST_SHA256=""
SEMANTIC_BINDING_SHA3_256=""
SEMANTIC_BINDING_SHA256=""
CARGO_VERSION=""
LAKE_VERSION=""
SCARB_VERSION=""
SNFORGE_VERSION=""

log() {
  printf '[VSEL preprod] %s\n' "$*"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[VSEL preprod] missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

json_escape() {
  printf '%s' "$1" | awk 'BEGIN { ORS = "" } {
    gsub(/\\/, "\\\\")
    gsub(/"/, "\\\"")
    gsub(/\t/, "\\t")
    gsub(/\r/, "\\r")
    if (NR > 1) {
      printf "\\n"
    }
    printf "%s", $0
  }'
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_sha3_256() {
  openssl dgst -sha3-256 "$1" | awk '{print $NF}'
}

require_file_contains() {
  local path="$1"
  local pattern="$2"
  local reason="$3"
  if ! grep -Fq "$pattern" "$path"; then
    log "Cairo semantic binding check failed for $path: $reason"
    log "missing pattern: $pattern"
    exit 1
  fi
}

write_cairo_source_manifest() {
  mkdir -p "$REPORT_DIR"
  local files=(
    "Scarb.toml"
    "Scarb.lock"
    "semantic_core/Scarb.toml"
    "semantic_core/Scarb.lock"
    "semantic_core/src/lib.cairo"
    "src/lib.cairo"
    "src/reference_contract.cairo"
    "executable/Scarb.toml"
    "executable/Scarb.lock"
    "executable/src/lib.cairo"
    "executable/inputs/valid_transition.json"
  )

  printf 'VSEL_CAIRO_SOURCE_MANIFEST_V1\n' >"$SOURCE_MANIFEST_FILE"
  local file
  for file in "${files[@]}"; do
    if [ ! -s "$CAIRO_REFERENCE_DIR/$file" ]; then
      log "Cairo source manifest input missing or empty: $CAIRO_REFERENCE_DIR/$file"
      exit 1
    fi
    printf '%s %s\n' "$file" "$(file_sha3_256 "$CAIRO_REFERENCE_DIR/$file")" \
      >>"$SOURCE_MANIFEST_FILE"
  done
  SOURCE_MANIFEST_SHA3_256="$(file_sha3_256 "$SOURCE_MANIFEST_FILE")"
  SOURCE_MANIFEST_SHA256="$(file_sha256 "$SOURCE_MANIFEST_FILE")"
}

write_cairo_semantic_binding_report() {
  mkdir -p "$REPORT_DIR"
  local core="$CAIRO_REFERENCE_DIR/semantic_core/src/lib.cairo"
  local contract="$CAIRO_REFERENCE_DIR/src/reference_contract.cairo"
  local executable="$CAIRO_REFERENCE_DIR/executable/src/lib.cairo"

  for file in "$core" "$contract" "$executable"; do
    if [ ! -s "$file" ]; then
      log "Cairo semantic binding input missing or empty: $file"
      exit 1
    fi
  done

  require_file_contains "$core" "pub fn apply_transition(" \
    "semantic core must expose the apply transition relation"
  require_file_contains "$core" "pub fn seal(" \
    "semantic core must expose the finalization transition relation"
  require_file_contains "$core" "pub fn invariant_holds(state: MachineState) -> bool" \
    "semantic core must expose invariant predicate"
  require_file_contains "$core" "assert(invariant_holds(next), 'VSEL_INV');" \
    "semantic core transitions must enforce invariant predicate"

  require_file_contains "$contract" "use vsel_reference_state_machine_core::{" \
    "contract wrapper must import the shared semantic core"
  require_file_contains "$contract" "apply_transition as apply_pure" \
    "contract apply entrypoint must be backed by semantic-core apply_transition"
  require_file_contains "$contract" "seal as seal_pure" \
    "contract seal entrypoint must be backed by semantic-core seal"
  require_file_contains "$contract" "let (after, observable) = apply_pure(before, input);" \
    "contract apply entrypoint must call semantic-core apply relation"
  require_file_contains "$contract" "let (after, observable) = seal_pure(before, transition_id, expected_version, actor);" \
    "contract seal entrypoint must call semantic-core seal relation"
  require_file_contains "$contract" "invariant_holds(read_state(self))" \
    "contract invariant query must delegate to semantic core"

  require_file_contains "$executable" "use vsel_reference_state_machine_core::{TransitionInput, apply_transition, initial_state};" \
    "executable proof target must import the same semantic-core transition"
  require_file_contains "$executable" "let (next, observable) = apply_transition(initial_state(), input);" \
    "executable proof target must call semantic-core apply relation"

  cat >"$SEMANTIC_BINDING_FILE" <<BINDING
VSEL_CAIRO_SEMANTIC_BINDING_V1
semantic_core=semantic_core/src/lib.cairo $(file_sha3_256 "$core")
contract_wrapper=src/reference_contract.cairo $(file_sha3_256 "$contract")
executable_entrypoint=executable/src/lib.cairo $(file_sha3_256 "$executable")
core_apply_transition=true
core_seal_transition=true
core_invariant_predicate=true
contract_uses_core_apply=true
contract_uses_core_seal=true
contract_uses_core_invariant=true
executable_uses_core_apply=true
BINDING

  SEMANTIC_BINDING_SHA3_256="$(file_sha3_256 "$SEMANTIC_BINDING_FILE")"
  SEMANTIC_BINDING_SHA256="$(file_sha256 "$SEMANTIC_BINDING_FILE")"
}

write_report() {
  local status="$1"
  local exit_code="$2"
  mkdir -p "$REPORT_DIR"
  cat >"$REPORT_FILE" <<JSON
{
  "schema": "vsel.preproduction_acceptance.v1",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "$(json_escape "$status")",
  "exit_code": $exit_code,
  "toolchain": {
    "cargo": "$(json_escape "$CARGO_VERSION")",
    "lake": "$(json_escape "$LAKE_VERSION")",
    "scarb": "$(json_escape "$SCARB_VERSION")",
    "snforge": "$(json_escape "$SNFORGE_VERSION")"
  },
  "native_cairo": {
    "package_dir": "$(json_escape "$CAIRO_EXECUTABLE_DIR")",
    "source_manifest": "$(json_escape "$SOURCE_MANIFEST_FILE")",
    "source_manifest_sha3_256": "$(json_escape "$SOURCE_MANIFEST_SHA3_256")",
    "source_manifest_sha256": "$(json_escape "$SOURCE_MANIFEST_SHA256")",
    "semantic_binding": "$(json_escape "$SEMANTIC_BINDING_FILE")",
    "semantic_binding_sha3_256": "$(json_escape "$SEMANTIC_BINDING_SHA3_256")",
    "semantic_binding_sha256": "$(json_escape "$SEMANTIC_BINDING_SHA256")",
    "execution_id": "$(json_escape "$EXECUTION_ID")",
    "execution_dir": "$(json_escape "$NATIVE_EXECUTION_DIR")",
    "proof_json": "$(json_escape "$NATIVE_PROOF_JSON")",
    "proof_json_sha256": "$(json_escape "$NATIVE_PROOF_SHA256")",
    "prover_input_json": "$(json_escape "$NATIVE_PROVER_INPUT_JSON")",
    "prover_input_json_sha256": "$(json_escape "$NATIVE_PROVER_INPUT_SHA256")"
  },
  "acceptance_path": {
    "native_verifier": "scarb verify",
    "vcai_backend": "vsel-proof/cairo-stark-backend",
    "strict_trace": "VerificationPipeline::verify_strict_trace",
    "lean_checker": "lake build vselCheck"
  }
}
JSON
}

on_exit() {
  local exit_code=$?
  if [ "$REPORT_WRITTEN" -eq 0 ]; then
    write_report "$STATUS" "$exit_code" || true
  fi
}

trap on_exit EXIT

require_command cargo
require_command lake
require_command scarb
require_command snforge
require_command openssl

log "toolchain"
CARGO_VERSION="$(cargo --version)"
LAKE_VERSION="$(lake --version)"
SCARB_VERSION="$(scarb --version)"
SNFORGE_VERSION="$(snforge --version)"
printf '%s\n' "$CARGO_VERSION"
printf '%s\n' "$LAKE_VERSION"
printf '%s\n' "$SCARB_VERSION"
printf '%s\n' "$SNFORGE_VERSION"

log "Rust formatting"
(cd "$PROTOCOL_DIR" && cargo fmt --all --check)

log "Lean semantic checker build"
(cd "$PROJECT_ROOT/formal" && lake build && lake build vselCheck)

log "Cairo reference contract build and tests"
(cd "$CAIRO_REFERENCE_DIR" && scarb build && snforge test)
write_cairo_source_manifest
log "Cairo source manifest: $SOURCE_MANIFEST_FILE"
write_cairo_semantic_binding_report
log "Cairo semantic binding: $SEMANTIC_BINDING_FILE"

log "Cairo executable proof generation"
(cd "$CAIRO_EXECUTABLE_DIR" && scarb build)
(cd "$CAIRO_EXECUTABLE_DIR" && scarb prove --execute --arguments-file inputs/valid_transition.json)

EXECUTION_ID="$(
  find "$CAIRO_EXECUTABLE_DIR/target/execute/vsel_reference_state_machine_exec" \
    -maxdepth 1 -type d -name 'execution*' -print \
    | sed 's|.*/execution||' \
    | sort -n \
    | tail -1
)"

if [ -z "$EXECUTION_ID" ]; then
  log "failed to locate generated Scarb execution id"
  exit 1
fi

NATIVE_EXECUTION_DIR="$CAIRO_EXECUTABLE_DIR/target/execute/vsel_reference_state_machine_exec/execution${EXECUTION_ID}"
NATIVE_PROOF_JSON="$NATIVE_EXECUTION_DIR/proof/proof.json"
NATIVE_PROVER_INPUT_JSON="$NATIVE_EXECUTION_DIR/prover_input.json"

if [ ! -s "$NATIVE_PROOF_JSON" ]; then
  log "generated execution is missing proof.json: $NATIVE_PROOF_JSON"
  exit 1
fi

if [ ! -s "$NATIVE_PROVER_INPUT_JSON" ]; then
  log "generated execution is missing prover_input.json: $NATIVE_PROVER_INPUT_JSON"
  exit 1
fi

NATIVE_PROOF_SHA256="$(file_sha256 "$NATIVE_PROOF_JSON")"
NATIVE_PROVER_INPUT_SHA256="$(file_sha256 "$NATIVE_PROVER_INPUT_JSON")"

log "Cairo executable native verification: execution${EXECUTION_ID}"
(cd "$CAIRO_EXECUTABLE_DIR" && scarb verify --execution-id "$EXECUTION_ID")

log "Wrapper and acceptance drills"
(
  cd "$PROTOCOL_DIR"
  cargo test -p vsel-proof --features cairo-stark-backend --test cairo_native_wrapper -- --nocapture
  VSEL_REQUIRE_REAL_SCARB_ACCEPTANCE=1 \
  VSEL_SCARB_EXECUTION_ID="$EXECUTION_ID" \
  VSEL_CAIRO_SOURCE_MANIFEST_PATH="$SOURCE_MANIFEST_FILE" \
  VSEL_CAIRO_SEMANTIC_BINDING_PATH="$SEMANTIC_BINDING_FILE" \
    cargo test -p vsel-proof --features cairo-stark-backend --test cairo_acceptance_drill -- --nocapture
)

log "Core verifier and adversarial proof tampering tests"
(
  cd "$PROTOCOL_DIR"
  cargo test -p vsel-proof lean_certificate_checker_is_part_of_strict_trace_acceptance --lib -- --nocapture
  cargo test -p vsel-proof strict_stark_policy_rejects_hash_backend_proof_relabelled_as_cairo_stark --lib -- --nocapture
  cargo test -p vsel-proof --test adversarial_proof_tampering -- --nocapture
)

STATUS="passed"
write_report "$STATUS" 0
REPORT_WRITTEN=1
log "pre-production report: $REPORT_FILE"
log "pre-production acceptance gate passed"
