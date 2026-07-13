#!/usr/bin/env bash
# Run the extended VSEL fuzzing campaign and emit a machine-readable report.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTOCOL_DIR="$PROJECT_ROOT/protocol"
REPORT_DIR="$PROJECT_ROOT/target/fuzzing"
REPORT_FILE="$REPORT_DIR/extended-fuzz-report.json"
FUZZ_DURATION_SECONDS="${FUZZ_DURATION_SECONDS:-3600}"

TARGETS=(
  fuzz_goldilocks_arith
  fuzz_poseidon_permute
  fuzz_poseidon_hash_bytes
  fuzz_proof_deser
  fuzz_constraint_eval
  fuzz_witness_construct
  fuzz_sir_deser
)

json_escape() {
  printf '%s' "$1" | awk 'BEGIN { ORS = "" } {
    gsub(/\\/, "\\\\")
    gsub(/"/, "\\\"")
    gsub(/\t/, "\\t")
    gsub(/\r/, "\\r")
    if (NR > 1) { printf "\\n" }
    printf "%s", $0
  }'
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[extended-fuzz] missing required command: $1" >&2
    exit 1
  fi
}

require_command cargo
require_command cargo-fuzz

mkdir -p "$REPORT_DIR"

status="passed"
results=()
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for target in "${TARGETS[@]}"; do
  log_file="$REPORT_DIR/${target}.log"
  echo "[extended-fuzz] target=$target duration=${FUZZ_DURATION_SECONDS}s"
  mkdir -p "$PROTOCOL_DIR/fuzz/corpus/$target"

  set +e
  (
    cd "$PROTOCOL_DIR"
    cargo fuzz run "$target" -- \
      -max_total_time="$FUZZ_DURATION_SECONDS" \
      -print_final_stats=1
  ) 2>&1 | tee "$log_file"
  exit_code="${PIPESTATUS[0]}"
  set -e

  artifact_dir="$PROTOCOL_DIR/fuzz/artifacts/$target"
  crashes=0
  if [ -d "$artifact_dir" ]; then
    crashes="$(find "$artifact_dir" -type f | wc -l | tr -d ' ')"
  fi

  if [ "$exit_code" -ne 0 ] || [ "$crashes" -ne 0 ]; then
    status="failed"
  fi

  results+=("{\"target\":\"$(json_escape "$target")\",\"exit_code\":$exit_code,\"crashes\":$crashes,\"log\":\"$(json_escape "$log_file")\"}")
done

{
  printf '{\n'
  printf '  "schema": "vsel.extended_fuzz.v1",\n'
  printf '  "started_at_utc": "%s",\n' "$started_at"
  printf '  "finished_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "duration_seconds_per_target": %s,\n' "$FUZZ_DURATION_SECONDS"
  printf '  "status": "%s",\n' "$status"
  printf '  "targets": [\n'
  for i in "${!results[@]}"; do
    suffix=","
    if [ "$i" -eq "$((${#results[@]} - 1))" ]; then
      suffix=""
    fi
    printf '    %s%s\n' "${results[$i]}" "$suffix"
  done
  printf '  ]\n'
  printf '}\n'
} >"$REPORT_FILE"

echo "[extended-fuzz] report: $REPORT_FILE"

if [ "$status" != "passed" ]; then
  echo "[extended-fuzz] campaign failed" >&2
  exit 1
fi
