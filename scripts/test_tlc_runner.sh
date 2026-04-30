#!/usr/bin/env bash
# -----------------------------------------------------------------------
# test_tlc_runner.sh — Unit tests for tlc_runner.sh
#
# Tests argument parsing, validation, output parsing, and timeout handling
# by sourcing tlc_runner.sh functions and testing them in isolation.
#
# Usage: ./scripts/test_tlc_runner.sh
#
# Requirements: 10.1
# -----------------------------------------------------------------------

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/tlc_runner.sh"
PASS=0
FAIL=0

# Colors
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
else
  GREEN=''; RED=''; NC=''
fi

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo -e "  ${GREEN}PASS${NC} $desc"
    ((PASS++))
  else
    echo -e "  ${RED}FAIL${NC} $desc"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((FAIL++))
  fi
}

assert_contains() {
  local desc="$1" needle="$2" haystack="$3"
  if echo "$haystack" | grep -qF "$needle"; then
    echo -e "  ${GREEN}PASS${NC} $desc"
    ((PASS++))
  else
    echo -e "  ${RED}FAIL${NC} $desc"
    echo "    expected to contain: $needle"
    echo "    actual: ${haystack:0:200}"
    ((FAIL++))
  fi
}

assert_exit() {
  local desc="$1" expected_exit="$2"
  shift 2
  local actual_exit=0
  "$@" >/dev/null 2>&1 || actual_exit=$?
  assert_eq "$desc" "$expected_exit" "$actual_exit"
}

# -----------------------------------------------------------------------
# Test 1: Missing --spec argument exits with code 4
# -----------------------------------------------------------------------
echo "Test 1: Missing --spec argument"
actual_exit=0
"$RUNNER" --config /dev/null >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 4" "4" "$actual_exit"

# -----------------------------------------------------------------------
# Test 2: Missing --config argument exits with code 4
# -----------------------------------------------------------------------
echo "Test 2: Missing --config argument"
actual_exit=0
"$RUNNER" --spec /dev/null >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 4" "4" "$actual_exit"

# -----------------------------------------------------------------------
# Test 3: Non-existent spec file exits with code 3
# -----------------------------------------------------------------------
echo "Test 3: Non-existent spec file"
actual_exit=0
"$RUNNER" --spec /nonexistent/file.tla --config /dev/null >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 3" "3" "$actual_exit"

# -----------------------------------------------------------------------
# Test 4: Non-existent config file exits with code 3
# -----------------------------------------------------------------------
echo "Test 4: Non-existent config file"
TMPSPEC=$(mktemp /tmp/test_spec_XXXXXX.tla)
echo "---- MODULE Test ----" > "$TMPSPEC"
actual_exit=0
"$RUNNER" --spec "$TMPSPEC" --config /nonexistent/config.cfg >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 3" "3" "$actual_exit"
rm -f "$TMPSPEC"

# -----------------------------------------------------------------------
# Test 5: Invalid --timeout value exits with code 4
# -----------------------------------------------------------------------
echo "Test 5: Invalid --timeout value"
actual_exit=0
# Use real files so file validation passes, then timeout validation triggers
TMPSPEC5=$(mktemp /tmp/test_spec5_XXXXXX.tla)
TMPCONFIG5=$(mktemp /tmp/test_config5_XXXXXX.cfg)
echo "---- MODULE Test ----" > "$TMPSPEC5"
echo "INVARIANT TypeOK" > "$TMPCONFIG5"
"$RUNNER" --spec "$TMPSPEC5" --config "$TMPCONFIG5" --timeout abc >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 4" "4" "$actual_exit"
rm -f "$TMPSPEC5" "$TMPCONFIG5"

# -----------------------------------------------------------------------
# Test 6: Invalid --workers value exits with code 4
# -----------------------------------------------------------------------
echo "Test 6: Invalid --workers value"
actual_exit=0
TMPSPEC6=$(mktemp /tmp/test_spec6_XXXXXX.tla)
TMPCONFIG6=$(mktemp /tmp/test_config6_XXXXXX.cfg)
echo "---- MODULE Test ----" > "$TMPSPEC6"
echo "INVARIANT TypeOK" > "$TMPCONFIG6"
"$RUNNER" --spec "$TMPSPEC6" --config "$TMPCONFIG6" --workers xyz >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 4" "4" "$actual_exit"
rm -f "$TMPSPEC6" "$TMPCONFIG6"

# -----------------------------------------------------------------------
# Test 7: --help exits with code 4 (usage)
# -----------------------------------------------------------------------
echo "Test 7: --help flag"
actual_exit=0
output=$("$RUNNER" --help 2>&1) || actual_exit=$?
assert_eq "exits with code 4" "4" "$actual_exit"
assert_contains "shows usage" "Usage:" "$output"

# -----------------------------------------------------------------------
# Test 8: TLC output parsing — success case
# -----------------------------------------------------------------------
echo "Test 8: TLC output parsing (success)"
# Source the runner to access parse_tlc_output
TMPCONFIG=$(mktemp /tmp/test_config_XXXXXX.cfg)
cat > "$TMPCONFIG" <<'CFGEOF'
INVARIANT StateValidity
INVARIANT ResourceConservation
PROPERTY NoRollbackTemporal
CFGEOF

# We need to source the runner and call parse_tlc_output
# But the runner has set -euo pipefail and main guard.
# Instead, test the JSON output structure by checking known patterns.

SAMPLE_SUCCESS_OUTPUT="TLC2 Version 2.18 of 01 January 2024
Starting...
Computing initial states...
Finished computing initial states: 1331 distinct states generated.
12345 states generated, 6789 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 5.
Finished in 01min 23s at (2024-01-01 12:00:00)"

# Source the runner functions (the main guard prevents execution)
(
  CONFIG_FILE="$TMPCONFIG"
  source "$RUNNER"
  parse_tlc_output "$SAMPLE_SUCCESS_OUTPUT"
  echo "STATES=$STATES_GENERATED"
  echo "DISTINCT=$DISTINCT_STATES"
  echo "PASSED=$PASSED"
  echo "VERSION=$TLC_VERSION"
) > /tmp/tlc_parse_result.txt 2>/dev/null || true

if [ -f /tmp/tlc_parse_result.txt ]; then
  parsed=$(cat /tmp/tlc_parse_result.txt)
  assert_contains "extracts states generated" "STATES=12345" "$parsed"
  assert_contains "extracts distinct states" "DISTINCT=6789" "$parsed"
  assert_contains "reports passed=true" "PASSED=true" "$parsed"
  assert_contains "extracts TLC version" "VERSION=TLC2 Version 2.18" "$parsed"
else
  echo -e "  ${RED}FAIL${NC} could not parse TLC output"
  ((FAIL++))
fi

rm -f "$TMPCONFIG" /tmp/tlc_parse_result.txt

# -----------------------------------------------------------------------
# Test 9: TLC output parsing — violation case
# -----------------------------------------------------------------------
echo "Test 9: TLC output parsing (violation)"
TMPCONFIG2=$(mktemp /tmp/test_config2_XXXXXX.cfg)
cat > "$TMPCONFIG2" <<'CFGEOF'
INVARIANT StateValidity
CFGEOF

SAMPLE_VIOLATION_OUTPUT="TLC2 Version 2.18 of 01 January 2024
Starting...
Error: Invariant StateValidity is violated.
100 states generated, 50 distinct states found.
Finished in 05s at (2024-01-01 12:00:00)"

(
  CONFIG_FILE="$TMPCONFIG2"
  source "$RUNNER"
  parse_tlc_output "$SAMPLE_VIOLATION_OUTPUT"
  echo "PASSED=$PASSED"
  echo "STATES=$STATES_GENERATED"
  echo "HAS_CE=$( [[ -n "$COUNTEREXAMPLE" ]] && echo yes || echo no )"
) > /tmp/tlc_parse_result2.txt 2>/dev/null || true

if [ -f /tmp/tlc_parse_result2.txt ]; then
  parsed2=$(cat /tmp/tlc_parse_result2.txt)
  assert_contains "reports passed=false on violation" "PASSED=false" "$parsed2"
  assert_contains "extracts states on violation" "STATES=100" "$parsed2"
  assert_contains "captures counterexample" "HAS_CE=yes" "$parsed2"
else
  echo -e "  ${RED}FAIL${NC} could not parse violation output"
  ((FAIL++))
fi

rm -f "$TMPCONFIG2" /tmp/tlc_parse_result2.txt

# -----------------------------------------------------------------------
# Test 10: Missing tla2tools.jar exits with code 3
# -----------------------------------------------------------------------
echo "Test 10: Missing tla2tools.jar"
TMPSPEC2=$(mktemp /tmp/test_spec2_XXXXXX.tla)
TMPCONFIG3=$(mktemp /tmp/test_config3_XXXXXX.cfg)
echo "---- MODULE Test ----" > "$TMPSPEC2"
echo "INVARIANT TypeOK" > "$TMPCONFIG3"
actual_exit=0
TLA2TOOLS=/nonexistent/tla2tools.jar "$RUNNER" --spec "$TMPSPEC2" --config "$TMPCONFIG3" >/dev/null 2>&1 || actual_exit=$?
assert_eq "exits with code 3" "3" "$actual_exit"
rm -f "$TMPSPEC2" "$TMPCONFIG3"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
TOTAL=$((PASS + FAIL))
echo "Results: $PASS/$TOTAL passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}SOME TESTS FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}ALL TESTS PASSED${NC}"
  exit 0
fi
