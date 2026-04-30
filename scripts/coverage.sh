#!/usr/bin/env bash
# VSEL Protocol — Coverage Analysis Script
# Requirements: 17.2
#
# Generates code coverage reports for the Rust workspace using
# cargo-llvm-cov (preferred) or cargo-tarpaulin (fallback).
#
# Coverage targets:
#   - Unit test coverage
#   - Property test coverage
#   - Combined coverage report (HTML + LCOV)
#
# Usage:
#   ./scripts/coverage.sh           # Full coverage analysis
#   ./scripts/coverage.sh unit      # Unit test coverage only
#   ./scripts/coverage.sh property  # Property test coverage only
#   ./scripts/coverage.sh report    # Generate report from existing data

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COVERAGE_DIR="$PROJECT_ROOT/protocol/target/coverage"

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

# ─────────────────────────────────────────────
# Detect coverage tool
# ─────────────────────────────────────────────
detect_coverage_tool() {
  if command -v cargo-llvm-cov &>/dev/null; then
    echo "llvm-cov"
  elif cargo llvm-cov --version &>/dev/null 2>&1; then
    echo "llvm-cov"
  elif command -v cargo-tarpaulin &>/dev/null; then
    echo "tarpaulin"
  else
    echo "none"
  fi
}

# ─────────────────────────────────────────────
# Install coverage tool if missing
# ─────────────────────────────────────────────
ensure_coverage_tool() {
  local tool
  tool="$(detect_coverage_tool)"

  if [ "$tool" = "none" ]; then
    log_info "No coverage tool found. Installing cargo-llvm-cov..."
    cargo install cargo-llvm-cov --locked || {
      log_warn "cargo-llvm-cov install failed. Trying cargo-tarpaulin..."
      cargo install cargo-tarpaulin --locked || {
        log_error "Could not install any coverage tool"
        exit 1
      }
    }
    tool="$(detect_coverage_tool)"
  fi

  echo "$tool"
}

# ─────────────────────────────────────────────
# Coverage with cargo-llvm-cov
# ─────────────────────────────────────────────
run_llvm_cov() {
  local target="${1:-all}"
  mkdir -p "$COVERAGE_DIR"

  case "$target" in
    unit)
      log_info "Running unit test coverage (llvm-cov)..."
      (cd "$PROJECT_ROOT/protocol" && cargo llvm-cov --lib --bins \
        --html --output-dir "$COVERAGE_DIR/unit" \
        --lcov --output-path "$COVERAGE_DIR/unit.lcov")
      ;;
    property)
      log_info "Running property test coverage (llvm-cov)..."
      (cd "$PROJECT_ROOT/protocol" && PROPTEST_CASES="${PROPTEST_CASES:-100}" \
        cargo llvm-cov --tests \
        --html --output-dir "$COVERAGE_DIR/property" \
        --lcov --output-path "$COVERAGE_DIR/property.lcov")
      ;;
    all)
      log_info "Running full coverage analysis (llvm-cov)..."
      (cd "$PROJECT_ROOT/protocol" && PROPTEST_CASES="${PROPTEST_CASES:-100}" \
        cargo llvm-cov --all-targets \
        --html --output-dir "$COVERAGE_DIR/full" \
        --lcov --output-path "$COVERAGE_DIR/full.lcov")
      ;;
  esac
}

# ─────────────────────────────────────────────
# Coverage with cargo-tarpaulin (fallback)
# ─────────────────────────────────────────────
run_tarpaulin() {
  local target="${1:-all}"
  mkdir -p "$COVERAGE_DIR"

  log_info "Running coverage analysis (tarpaulin)..."
  local args=("--out" "Html" "Lcov" "--output-dir" "$COVERAGE_DIR")

  case "$target" in
    unit)
      args+=("--lib")
      ;;
    property)
      args+=("--test" "*")
      ;;
    all)
      # Default: all targets
      ;;
  esac

  (cd "$PROJECT_ROOT/protocol" && PROPTEST_CASES="${PROPTEST_CASES:-100}" \
    cargo tarpaulin "${args[@]}")
}

# ─────────────────────────────────────────────
# Print coverage summary
# ─────────────────────────────────────────────
print_summary() {
  echo ""
  log_ok "Coverage analysis complete"
  log_info "Coverage reports:"

  if [ -d "$COVERAGE_DIR" ]; then
    find "$COVERAGE_DIR" -name '*.html' -o -name '*.lcov' | sort | while read -r f; do
      echo "  $f"
    done
  fi

  echo ""
  log_info "Open HTML report in browser:"
  if [ -f "$COVERAGE_DIR/full/index.html" ]; then
    echo "  open $COVERAGE_DIR/full/index.html"
  elif [ -f "$COVERAGE_DIR/tarpaulin-report.html" ]; then
    echo "  open $COVERAGE_DIR/tarpaulin-report.html"
  fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
  log_info "VSEL Protocol — Coverage Analysis"
  log_info "Project root: $PROJECT_ROOT"
  echo ""

  if ! command -v cargo &>/dev/null; then
    log_error "cargo not found — install Rust toolchain first"
    exit 1
  fi

  local target="${1:-all}"
  local tool
  tool="$(ensure_coverage_tool)"

  log_info "Coverage tool: $tool"
  log_info "Target: $target"
  echo ""

  case "$tool" in
    llvm-cov)  run_llvm_cov "$target" ;;
    tarpaulin) run_tarpaulin "$target" ;;
    *)
      log_error "No coverage tool available"
      exit 1
      ;;
  esac

  print_summary
}

main "$@"
