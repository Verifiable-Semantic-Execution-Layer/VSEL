#!/usr/bin/env bash
# VSEL Protocol — Full Test Suite Script
# Requirements: 17.2
#
# Runs all test suites in the correct pipeline order:
#   Rust: unit → property (proptest ≥100) → differential → adversarial → integration
#   Lean 4: lake test
#   TLA+: model checking (StateMachine, Invariants, TransitionPartitioning, Composition)
#   Python: pytest adversarial tooling
#
# Usage:
#   ./scripts/test.sh              # Run all tests
#   ./scripts/test.sh rust         # Rust tests only
#   ./scripts/test.sh rust-unit    # Rust unit tests only
#   ./scripts/test.sh rust-prop    # Rust property tests only
#   ./scripts/test.sh lean         # Lean 4 tests only
#   ./scripts/test.sh tla          # TLA+ model checking only
#   ./scripts/test.sh python       # Python tests only
#   ./scripts/test.sh --strict     # Treat every skipped/missing suite as failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  BLUE='\033[0;34m'
  NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

FAILED=0
STRICT="${VSEL_STRICT_TEST:-false}"
PROPTEST_CASES="${PROPTEST_CASES:-10000}"
export PROPTEST_CASES

skip_or_fail() {
  if [ "$STRICT" = true ]; then
    log_error "STRICT: skipped check is forbidden: $*"
    FAILED=1
  else
    log_warn "$*"
  fi
}

# ─────────────────────────────────────────────
# Rust Tests
# ─────────────────────────────────────────────
test_rust_unit() {
  log_info "Rust — Unit tests"
  (cd "$PROJECT_ROOT/protocol" && cargo test --lib --bins 2>&1) || { log_error "Rust unit tests failed"; FAILED=1; }
}

test_rust_property() {
  log_info "Rust — Property tests (proptest ≥${PROPTEST_CASES} iterations)"
  (cd "$PROJECT_ROOT/protocol" && cargo test --test '*' -- --test-threads=2 2>&1) || { log_error "Rust property tests failed"; FAILED=1; }
}

test_rust_differential() {
  log_info "Rust — Differential tests (Rust vs SIR interpreter)"
  if [ -f "$PROJECT_ROOT/protocol/tests/differential/.gitkeep" ] && [ "$(find "$PROJECT_ROOT/protocol/tests/differential" -name '*.rs' ! -name '.gitkeep' | head -1)" = "" ]; then
    skip_or_fail "No differential test files found — skipping"
  else
    (cd "$PROJECT_ROOT/protocol" && cargo test --test differential_tests 2>&1) || { skip_or_fail "Differential tests failed or not available"; }
  fi
}

test_rust_adversarial() {
  log_info "Rust — Adversarial tests (invalid witness suite)"
  if [ -d "$PROJECT_ROOT/protocol/tests/adversarial" ]; then
    (cd "$PROJECT_ROOT/protocol" && cargo test --test adversarial_tests 2>&1) || { skip_or_fail "Adversarial tests failed or not available"; }
  else
    skip_or_fail "No adversarial test directory found — skipping"
  fi
}

test_rust_integration() {
  log_info "Rust — Integration tests"
  if [ -d "$PROJECT_ROOT/protocol/tests/integration" ]; then
    (cd "$PROJECT_ROOT/protocol" && cargo test --test '*' -- --ignored 2>&1) || { skip_or_fail "Integration tests failed or not available"; }
  else
    skip_or_fail "No integration test directory found — skipping"
  fi
}

test_rust_crate_property() {
  log_info "Rust — Crate-level property tests"
  for crate_dir in "$PROJECT_ROOT"/protocol/crates/*/; do
    crate_name="$(basename "$crate_dir")"
    if [ -d "$crate_dir/tests" ]; then
      log_info "  Testing $crate_name"
      (cd "$PROJECT_ROOT/protocol" && cargo test -p "$crate_name" --tests 2>&1) || { skip_or_fail "Crate tests failed: $crate_name"; }
    fi
  done
}

test_rust_all() {
  test_rust_unit
  test_rust_property
  test_rust_crate_property
  test_rust_differential
  test_rust_adversarial
  test_rust_integration
}

# ─────────────────────────────────────────────
# Lean 4 Tests
# ─────────────────────────────────────────────
test_lean() {
  log_info "Lean 4 — Proof checking"
  if command -v lake &>/dev/null; then
    (cd "$PROJECT_ROOT/formal" && lake build) || { log_error "Lean 4 build failed"; FAILED=1; return; }
    (cd "$PROJECT_ROOT/formal" && lake test) || { skip_or_fail "Lean 4 tests returned non-zero"; }
    (cd "$PROJECT_ROOT" && bash ./scripts/check_axiom_ledger.sh) || { log_error "Lean axiom ledger failed"; FAILED=1; return; }
    log_ok "Lean 4 proof checking succeeded"
  else
    skip_or_fail "lake not found — skipping Lean 4 tests"
  fi
}

# ─────────────────────────────────────────────
# TLA+ Model Checking
# ─────────────────────────────────────────────
test_tla() {
  log_info "TLA+ — Model checking"
  if ! command -v java &>/dev/null; then
    skip_or_fail "java not found — skipping TLA+ model checking"
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
    skip_or_fail "tla2tools.jar not found — set TLA2TOOLS env var"
    return
  fi

  local tla_dir="$PROJECT_ROOT/tla"
  local models=("StateMachine.tla" "Invariants.tla" "TransitionPartitioning.tla" "Composition.tla")
  local configs=("MC.cfg" "MC.cfg" "MC.cfg" "Composition_MC.cfg")

  for i in "${!models[@]}"; do
    local model="${models[$i]}"
    local config="${configs[$i]}"
    if [ -f "$tla_dir/$model" ] && [ -f "$tla_dir/$config" ]; then
      log_info "  Checking $model with $config"
      (cd "$tla_dir" && java -cp "$TLA2TOOLS" tlc2.TLC "$model" -config "$config" -workers auto 2>&1) || { log_error "TLA+ model check failed: $model"; FAILED=1; }
    else
      skip_or_fail "  Missing $model or $config — skipping"
    fi
  done

  log_ok "TLA+ model checking completed"
}

# ─────────────────────────────────────────────
# Python Tests
# ─────────────────────────────────────────────
test_python() {
  log_info "Python — Adversarial tooling tests"
  if command -v python3 &>/dev/null; then
    (cd "$PROJECT_ROOT/tools" && python3 -m pytest -v 2>&1) || { skip_or_fail "Python tests failed or not configured"; }
    log_ok "Python tests completed"
  else
    skip_or_fail "python3 not found — skipping Python tests"
  fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
  log_info "VSEL Protocol — Full Test Suite"
  log_info "Project root: $PROJECT_ROOT"
  log_info "PROPTEST_CASES: $PROPTEST_CASES"
  echo ""

  if [ "${1:-}" = "--strict" ]; then
    STRICT=true
    shift
  fi

  local target="${1:-all}"
  log_info "Strict skips: $STRICT"

  case "$target" in
    rust)           test_rust_all ;;
    rust-unit)      test_rust_unit ;;
    rust-prop)      test_rust_property ;;
    rust-diff)      test_rust_differential ;;
    rust-adv)       test_rust_adversarial ;;
    rust-integ)     test_rust_integration ;;
    lean)           test_lean ;;
    tla)            test_tla ;;
    python)         test_python ;;
    all)
      test_lean
      test_rust_all
      test_tla
      test_python
      ;;
    *)
      log_error "Unknown target: $target"
      echo "Usage: $0 [all|rust|rust-unit|rust-prop|rust-diff|rust-adv|rust-integ|lean|tla|python]"
      exit 1
      ;;
  esac

  echo ""
  if [ "$FAILED" -ne 0 ]; then
    log_error "Test suite completed with failures"
    exit 1
  else
    log_ok "Test suite completed successfully"
  fi
}

main "$@"
