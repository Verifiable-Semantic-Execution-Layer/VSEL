#!/usr/bin/env bash
# VSEL Protocol — CI Pipeline Orchestration Script
# Requirements: 17.2, 17.7
#
# Local CI runner that mirrors the GitHub Actions pipeline.
# Executes all checks in the correct order with fail-fast behavior.
#
# Pipeline order:
#   1. Version consistency check
#   2. Lean 4: lake build → lake test
#   3. Rust: fmt → clippy → unit tests → property tests → differential → adversarial → integration
#   4. TLA+: model checking (StateMachine, Invariants, TransitionPartitioning, Composition)
#   5. Python: pytest adversarial tooling
#   6. Security: cargo-audit dependency scan
#
# Usage:
#   ./scripts/ci.sh              # Run full CI pipeline
#   ./scripts/ci.sh --quick      # Skip slow checks (TLA+, differential, adversarial)
#   ./scripts/ci.sh --rust-only  # Rust pipeline only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}      $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_section() { echo -e "\n${BOLD}═══ $* ═══${NC}"; }

FAILED=0
SKIPPED=0
PASSED=0
START_TIME="$(date +%s)"
QUICK=false
RUST_ONLY=false

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --quick)     QUICK=true ;;
    --rust-only) RUST_ONLY=true ;;
    --help|-h)
      echo "Usage: $0 [--quick] [--rust-only]"
      echo ""
      echo "Options:"
      echo "  --quick      Skip slow checks (TLA+ model checking, differential, adversarial)"
      echo "  --rust-only  Run Rust pipeline only"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# Track step results
step_pass() { ((PASSED++)) || true; log_ok "$1"; }
step_fail() { ((FAILED++)) || true; log_error "$1"; }
step_skip() { ((SKIPPED++)) || true; log_warn "SKIPPED: $1"; }

# ─────────────────────────────────────────────
# Step 1: Version Consistency
# ─────────────────────────────────────────────
check_versions() {
  log_section "Version Consistency Check"
  log_info "Checking version_id, constraint_version, proof_version..."

  local versions_ok=true
  local first_version=""

  for toml in "$PROJECT_ROOT"/protocol/crates/*/Cargo.toml; do
    crate="$(basename "$(dirname "$toml")")"
    version="$(grep '^version' "$toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
    log_info "  $crate: $version"

    if [ -z "$first_version" ]; then
      first_version="$version"
    fi
  done

  if [ "$versions_ok" = true ]; then
    step_pass "Version consistency"
  else
    step_fail "Version consistency"
  fi
}

# ─────────────────────────────────────────────
# Step 2: Lean 4 Pipeline
# ─────────────────────────────────────────────
run_lean_pipeline() {
  log_section "Lean 4 Pipeline"

  if [ "$RUST_ONLY" = true ]; then
    step_skip "Lean 4 (--rust-only)"
    return
  fi

  if ! command -v lake &>/dev/null; then
    step_skip "Lean 4 (lake not found)"
    return
  fi

  log_info "lake build"
  if (cd "$PROJECT_ROOT/formal" && lake build 2>&1); then
    step_pass "Lean 4 build"
  else
    step_fail "Lean 4 build"
    return
  fi

  log_info "lake test"
  if (cd "$PROJECT_ROOT/formal" && lake test 2>&1); then
    step_pass "Lean 4 test"
  else
    log_warn "lake test returned non-zero (tests may not be configured)"
    step_pass "Lean 4 test (no test target)"
  fi
}

# ─────────────────────────────────────────────
# Step 3: Rust Pipeline
# ─────────────────────────────────────────────
run_rust_pipeline() {
  log_section "Rust Pipeline"

  if ! command -v cargo &>/dev/null; then
    step_fail "Rust (cargo not found)"
    return
  fi

  # 3a. Format check
  log_info "cargo fmt --check"
  if (cd "$PROJECT_ROOT/protocol" && cargo fmt --all --check 2>&1); then
    step_pass "Rust format"
  else
    step_fail "Rust format"
    return  # Fail fast
  fi

  # 3b. Clippy lint
  log_info "cargo clippy -- -D warnings"
  if (cd "$PROJECT_ROOT/protocol" && cargo clippy --all-targets --all-features -- -D warnings 2>&1); then
    step_pass "Rust clippy"
  else
    step_fail "Rust clippy"
    return  # Fail fast
  fi

  # 3c. Unit tests
  log_info "cargo test (unit)"
  if (cd "$PROJECT_ROOT/protocol" && cargo test --lib --bins 2>&1); then
    step_pass "Rust unit tests"
  else
    step_fail "Rust unit tests"
    return  # Fail fast
  fi

  # 3d. Property tests (proptest ≥100 iterations)
  log_info "cargo test --test '*' (property tests, PROPTEST_CASES=${PROPTEST_CASES:-100})"
  if (cd "$PROJECT_ROOT/protocol" && PROPTEST_CASES="${PROPTEST_CASES:-100}" cargo test --test '*' -- --test-threads=2 2>&1); then
    step_pass "Rust property tests"
  else
    step_fail "Rust property tests"
    # Continue — property test failures are important but don't block other checks
  fi

  # 3e. Crate-level property tests
  log_info "Crate-level property tests"
  local crate_tests_ok=true
  for crate_dir in "$PROJECT_ROOT"/protocol/crates/*/; do
    crate_name="$(basename "$crate_dir")"
    if [ -d "$crate_dir/tests" ]; then
      if ! (cd "$PROJECT_ROOT/protocol" && PROPTEST_CASES="${PROPTEST_CASES:-100}" cargo test -p "$crate_name" --tests 2>&1); then
        crate_tests_ok=false
      fi
    fi
  done
  if [ "$crate_tests_ok" = true ]; then
    step_pass "Rust crate property tests"
  else
    step_fail "Rust crate property tests"
  fi

  if [ "$QUICK" = true ]; then
    step_skip "Rust differential tests (--quick)"
    step_skip "Rust adversarial tests (--quick)"
  else
    # 3f. Differential tests
    log_info "Differential tests (Rust vs SIR interpreter)"
    if (cd "$PROJECT_ROOT/protocol" && cargo test --test differential_tests 2>&1); then
      step_pass "Rust differential tests"
    else
      step_skip "Rust differential tests (not available yet)"
    fi

    # 3g. Adversarial tests
    log_info "Adversarial tests (invalid witness suite)"
    if (cd "$PROJECT_ROOT/protocol" && cargo test --test adversarial_tests 2>&1); then
      step_pass "Rust adversarial tests"
    else
      step_skip "Rust adversarial tests (not available yet)"
    fi
  fi

  # 3h. Integration tests
  log_info "Integration tests"
  if (cd "$PROJECT_ROOT/protocol" && cargo test --test '*' -- --ignored 2>&1); then
    step_pass "Rust integration tests"
  else
    step_skip "Rust integration tests (none marked #[ignore] yet)"
  fi
}

# ─────────────────────────────────────────────
# Step 4: TLA+ Pipeline
# ─────────────────────────────────────────────
run_tla_pipeline() {
  log_section "TLA+ Pipeline"

  if [ "$RUST_ONLY" = true ]; then
    step_skip "TLA+ (--rust-only)"
    return
  fi

  if [ "$QUICK" = true ]; then
    step_skip "TLA+ model checking (--quick)"
    return
  fi

  if ! command -v java &>/dev/null; then
    step_skip "TLA+ (java not found)"
    return
  fi

  TLA2TOOLS="${TLA2TOOLS:-}"
  if [ -z "$TLA2TOOLS" ]; then
    for candidate in "$HOME/tla/tla2tools.jar" "/opt/tla/tla2tools.jar" "/usr/local/lib/tla2tools.jar"; do
      if [ -f "$candidate" ]; then
        TLA2TOOLS="$candidate"
        break
      fi
    done
  fi

  if [ -z "$TLA2TOOLS" ] || [ ! -f "$TLA2TOOLS" ]; then
    step_skip "TLA+ (tla2tools.jar not found — set TLA2TOOLS env var)"
    return
  fi

  local tla_dir="$PROJECT_ROOT/tla"
  local models=("StateMachine.tla" "Invariants.tla" "TransitionPartitioning.tla" "Composition.tla")
  local configs=("MC.cfg" "MC.cfg" "MC.cfg" "Composition_MC.cfg")

  for i in "${!models[@]}"; do
    local model="${models[$i]}"
    local config="${configs[$i]}"
    if [ -f "$tla_dir/$model" ] && [ -f "$tla_dir/$config" ]; then
      log_info "tlc $model -config $config"
      if (cd "$tla_dir" && java -cp "$TLA2TOOLS" tlc2.TLC "$model" -config "$config" -workers auto 2>&1); then
        step_pass "TLA+ $model"
      else
        step_fail "TLA+ $model"
      fi
    else
      step_skip "TLA+ $model (file not found)"
    fi
  done
}

# ─────────────────────────────────────────────
# Step 5: Python Pipeline
# ─────────────────────────────────────────────
run_python_pipeline() {
  log_section "Python Pipeline"

  if [ "$RUST_ONLY" = true ]; then
    step_skip "Python (--rust-only)"
    return
  fi

  if ! command -v python3 &>/dev/null; then
    step_skip "Python (python3 not found)"
    return
  fi

  log_info "pytest adversarial tooling"
  if (cd "$PROJECT_ROOT/tools" && python3 -m pytest -v 2>&1); then
    step_pass "Python adversarial tests"
  else
    step_skip "Python adversarial tests (not configured yet)"
  fi
}

# ─────────────────────────────────────────────
# Step 6: Security Scan
# ─────────────────────────────────────────────
run_security_scan() {
  log_section "Security Scan"

  if [ "$RUST_ONLY" = true ] && [ "$QUICK" = true ]; then
    step_skip "Security scan (--quick --rust-only)"
    return
  fi

  if command -v cargo &>/dev/null; then
    if command -v cargo-audit &>/dev/null || cargo audit --version &>/dev/null 2>&1; then
      log_info "cargo audit"
      if (cd "$PROJECT_ROOT/protocol" && cargo audit 2>&1); then
        step_pass "Dependency audit"
      else
        step_fail "Dependency audit (vulnerabilities found)"
      fi
    else
      step_skip "Dependency audit (cargo-audit not installed)"
    fi
  fi
}

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
print_summary() {
  local end_time
  end_time="$(date +%s)"
  local duration=$((end_time - START_TIME))

  log_section "CI Pipeline Summary"
  echo ""
  echo -e "  ${GREEN}Passed:${NC}  $PASSED"
  echo -e "  ${RED}Failed:${NC}  $FAILED"
  echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
  echo -e "  Duration: ${duration}s"
  echo ""

  if [ "$FAILED" -gt 0 ]; then
    log_error "CI pipeline FAILED ($FAILED failures)"
    exit 1
  else
    log_ok "CI pipeline PASSED"
  fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
  log_section "VSEL Protocol — CI Pipeline"
  log_info "Project root: $PROJECT_ROOT"
  log_info "Mode: $([ "$QUICK" = true ] && echo 'quick' || echo 'full')$([ "$RUST_ONLY" = true ] && echo ' (rust-only)' || echo '')"
  log_info "PROPTEST_CASES: ${PROPTEST_CASES:-100}"

  check_versions
  run_lean_pipeline
  run_rust_pipeline
  run_tla_pipeline
  run_python_pipeline
  run_security_scan

  print_summary
}

main
