#!/usr/bin/env bash
# VSEL Protocol — Full Build Script
# Requirements: 17.2, 17.5
#
# Builds all project components:
#   1. Lean 4 formal proofs (lake build)
#   2. Rust Cargo workspace (cargo build)
#   3. TLA+ syntax check (parse only, no model checking)
#   4. Python tooling dependency install
#
# Usage:
#   ./scripts/build.sh          # Build all components
#   ./scripts/build.sh lean     # Build Lean 4 only
#   ./scripts/build.sh rust     # Build Rust only
#   ./scripts/build.sh tla      # Check TLA+ syntax only
#   ./scripts/build.sh python   # Install Python deps only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output (disabled if not a terminal)
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

# ─────────────────────────────────────────────
# Lean 4 Build
# ─────────────────────────────────────────────
build_lean() {
  log_info "Building Lean 4 formal proofs..."
  if command -v lake &>/dev/null; then
    (cd "$PROJECT_ROOT/formal" && lake build) || { log_error "Lean 4 build failed"; FAILED=1; return; }
    log_ok "Lean 4 build succeeded"
  else
    log_warn "lake not found — skipping Lean 4 build (install elan: https://github.com/leanprover/elan)"
  fi
}

# ─────────────────────────────────────────────
# Rust Build
# ─────────────────────────────────────────────
build_rust() {
  log_info "Building Rust workspace..."
  if command -v cargo &>/dev/null; then
    log_info "  cargo fmt --check"
    (cd "$PROJECT_ROOT/protocol" && cargo fmt --all --check) || { log_error "Rust format check failed"; FAILED=1; return; }

    log_info "  cargo clippy -- -D warnings"
    (cd "$PROJECT_ROOT/protocol" && cargo clippy --all-targets --all-features -- -D warnings) || { log_error "Rust clippy failed"; FAILED=1; return; }

    log_info "  cargo build"
    (cd "$PROJECT_ROOT/protocol" && cargo build --all-targets) || { log_error "Rust build failed"; FAILED=1; return; }

    log_ok "Rust build succeeded"
  else
    log_warn "cargo not found — skipping Rust build (install rustup: https://rustup.rs)"
  fi
}

# ─────────────────────────────────────────────
# TLA+ Syntax Check
# ─────────────────────────────────────────────
build_tla() {
  log_info "Checking TLA+ models (syntax parse)..."
  if command -v java &>/dev/null; then
    TLA2TOOLS="${TLA2TOOLS:-}"
    if [ -z "$TLA2TOOLS" ]; then
      # Try common locations
      for candidate in "$HOME/tla/tla2tools.jar" "/opt/tla/tla2tools.jar" "/usr/local/lib/tla2tools.jar"; do
        if [ -f "$candidate" ]; then
          TLA2TOOLS="$candidate"
          break
        fi
      done
    fi
    if [ -n "$TLA2TOOLS" ] && [ -f "$TLA2TOOLS" ]; then
      for tla_file in "$PROJECT_ROOT"/tla/*.tla; do
        if [ -f "$tla_file" ]; then
          basename_tla="$(basename "$tla_file")"
          log_info "  Parsing $basename_tla"
          java -cp "$TLA2TOOLS" tla2sany.SANY "$tla_file" || { log_error "TLA+ parse failed: $basename_tla"; FAILED=1; }
        fi
      done
      log_ok "TLA+ syntax check succeeded"
    else
      log_warn "tla2tools.jar not found — set TLA2TOOLS env var or install TLA+ tools"
    fi
  else
    log_warn "java not found — skipping TLA+ check"
  fi
}

# ─────────────────────────────────────────────
# Python Dependencies
# ─────────────────────────────────────────────
build_python() {
  log_info "Installing Python tooling dependencies..."
  if command -v python3 &>/dev/null; then
    if [ -f "$PROJECT_ROOT/tools/requirements.txt" ]; then
      python3 -m pip install --quiet -r "$PROJECT_ROOT/tools/requirements.txt" || { log_error "Python dependency install failed"; FAILED=1; return; }
    else
      log_info "  No requirements.txt found — installing pytest only"
      python3 -m pip install --quiet pytest || { log_error "pytest install failed"; FAILED=1; return; }
    fi
    log_ok "Python dependencies installed"
  else
    log_warn "python3 not found — skipping Python setup"
  fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
main() {
  log_info "VSEL Protocol — Full Build"
  log_info "Project root: $PROJECT_ROOT"
  echo ""

  local target="${1:-all}"

  case "$target" in
    lean)   build_lean ;;
    rust)   build_rust ;;
    tla)    build_tla ;;
    python) build_python ;;
    all)
      build_lean
      build_rust
      build_tla
      build_python
      ;;
    *)
      log_error "Unknown target: $target"
      echo "Usage: $0 [lean|rust|tla|python|all]"
      exit 1
      ;;
  esac

  echo ""
  if [ "$FAILED" -ne 0 ]; then
    log_error "Build completed with failures"
    exit 1
  else
    log_ok "Build completed successfully"
  fi
}

main "$@"
