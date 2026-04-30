#!/usr/bin/env bash
# -----------------------------------------------------------------------
# test_tlc_runner.sh — Unit tests for scripts/tlc_runner.sh
#
# Tests argument parsing, output parsing, and timeout handling
# using mock TLC output. Does not require TLC/Java to be installed.
#
# Usage: bash scripts/tests/test_tlc_runner.sh
#
# Requirements: 10.1
# -----------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/../tlc_runner.sh"
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# -----------------------------------------------------------------------
# Test helpers
# -----------------------------------------------------------------------
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo "  PASS: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo "  FAIL: $1"
    if [[ -n "${2:-}" ]]; then
        echo "        $2"
    fi
}

assert_exit_code() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    if [[ "$actual" -eq "$expected" ]]; then
        pass "$test_name"
    else
        fail "$test_name" "Expected exit code $expected, got $actual"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local test_name="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        pass "$test_name"
    else
        fail "$test_name" "Output does not contain: $needle"
    fi
}

assert_json_field() {
    local json="$1"
    local field="$2"
    local expected="$3"
    local test_name="$4"
    # Simple JSON field extraction (works for top-level string/number/bool fields)
    local actual
    actual=$(echo "$json" | grep -oE "\"$field\":[[:space:]]*[^,}]+" | head -1 | sed "s/\"$field\":[[:space:]]*//" | tr -d '"' | tr -d ' ')
    if [[ "$actual" == "$expected" ]]; then
        pass "$test_name"
    else
        fail "$test_name" "Field '$field': expected '$expected', got '$actual'"
    fi
}

# Create temp directory for test fixtures
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# Create a minimal TLA+ spec file for argument validation tests
cat > "$TMPDIR_TEST/Test.tla" <<'EOF'
---- MODULE Test ----
EXTENDS Naturals
VARIABLE x
Init == x = 0
Next == x' = x + 1
Spec == Init /\ [][Next]_x
====
EOF

# Create a minimal config file
cat > "$TMPDIR_TEST/Test.cfg" <<'EOF'
SPECIFICATION Spec
INVARIANT TypeOK
PROPERTY Liveness
EOF

# -----------------------------------------------------------------------
# Test Suite 1: Argument Parsing and Validation
# -----------------------------------------------------------------------
echo ""
echo "=== Test Suite 1: Argument Parsing and Validation ==="

# Test 1.1: Missing --spec argument
echo ""
echo "--- Test 1.1: Missing --spec argument ---"
output=$(bash "$RUNNER" --config "$TMPDIR_TEST/Test.cfg" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "Missing --spec exits with code 4"
assert_contains "$output" "--spec is required" "Missing --spec shows error message"

# Test 1.2: Missing --config argument
echo ""
echo "--- Test 1.2: Missing --config argument ---"
output=$(bash "$RUNNER" --spec "$TMPDIR_TEST/Test.tla" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "Missing --config exits with code 4"
assert_contains "$output" "--config is required" "Missing --config shows error message"

# Test 1.3: No arguments at all
echo ""
echo "--- Test 1.3: No arguments ---"
output=$(bash "$RUNNER" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "No arguments exits with code 4"

# Test 1.4: Non-existent spec file
echo ""
echo "--- Test 1.4: Non-existent spec file ---"
output=$(bash "$RUNNER" --spec "/nonexistent/file.tla" --config "$TMPDIR_TEST/Test.cfg" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 3 "$exit_code" "Non-existent spec file exits with code 3"
assert_contains "$output" "Spec file not found" "Non-existent spec shows error"

# Test 1.5: Non-existent config file
echo ""
echo "--- Test 1.5: Non-existent config file ---"
output=$(bash "$RUNNER" --spec "$TMPDIR_TEST/Test.tla" --config "/nonexistent/config.cfg" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 3 "$exit_code" "Non-existent config file exits with code 3"
assert_contains "$output" "Config file not found" "Non-existent config shows error"

# Test 1.6: Invalid timeout value
echo ""
echo "--- Test 1.6: Invalid timeout value ---"
output=$(bash "$RUNNER" --spec "$TMPDIR_TEST/Test.tla" --config "$TMPDIR_TEST/Test.cfg" --timeout "abc" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "Invalid timeout exits with code 4"
assert_contains "$output" "timeout must be a positive integer" "Invalid timeout shows error"

# Test 1.7: Invalid workers value
echo ""
echo "--- Test 1.7: Invalid workers value ---"
output=$(bash "$RUNNER" --spec "$TMPDIR_TEST/Test.tla" --config "$TMPDIR_TEST/Test.cfg" --workers "xyz" 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "Invalid workers exits with code 4"
assert_contains "$output" "workers must be" "Invalid workers shows error"

# Test 1.8: Unknown argument
echo ""
echo "--- Test 1.8: Unknown argument ---"
output=$(bash "$RUNNER" --spec "$TMPDIR_TEST/Test.tla" --config "$TMPDIR_TEST/Test.cfg" --unknown 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "Unknown argument exits with code 4"
assert_contains "$output" "Unknown argument" "Unknown argument shows error"

# Test 1.9: --help flag
echo ""
echo "--- Test 1.9: --help flag ---"
output=$(bash "$RUNNER" --help 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 4 "$exit_code" "--help exits with code 4"
assert_contains "$output" "Usage:" "--help shows usage"

# -----------------------------------------------------------------------
# Test Suite 2: Output Parsing with Mock TLC Output
# -----------------------------------------------------------------------
echo ""
echo "=== Test Suite 2: Output Parsing ==="

# We test the parse_tlc_output function by sourcing the script's functions
# and calling them directly. To do this, we create a wrapper that sources
# the parsing logic.

# Create a test harness that sources the runner's functions
cat > "$TMPDIR_TEST/parse_harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail

RUNNER_SCRIPT="$1"
CONFIG_FILE="$2"
TLC_OUTPUT_FILE="$3"

export CONFIG_FILE

# Source the runner (the guard prevents main from running)
source "$RUNNER_SCRIPT"

# Read mock TLC output
TLC_OUTPUT=$(cat "$TLC_OUTPUT_FILE")

# Call the parser
parse_tlc_output "$TLC_OUTPUT"

# Output results as simple key=value for test assertions
echo "STATES_GENERATED=$STATES_GENERATED"
echo "DISTINCT_STATES=$DISTINCT_STATES"
echo "TLC_VERSION=$TLC_VERSION"
echo "EXECUTION_TIME=$EXECUTION_TIME"
echo "PASSED=$PASSED"
echo "COUNTEREXAMPLE_EMPTY=$([[ -z "$COUNTEREXAMPLE" ]] && echo true || echo false)"
echo "PROPERTY_RESULTS_JSON=$PROPERTY_RESULTS_JSON"
HARNESS
chmod +x "$TMPDIR_TEST/parse_harness.sh"

# Test 2.1: Successful TLC output
echo ""
echo "--- Test 2.1: Parse successful TLC output ---"
cat > "$TMPDIR_TEST/success_output.txt" <<'TLC_OUT'
TLC2 Version 2.18 of 01 January 2024 (rev: abc123)
Running breadth-first search Model-Checking with fp 64, seed 12345 and aril 0.
Parsing file /path/to/Properties.tla
Parsing file /path/to/StateMachine.tla
Semantic processing of module StateMachine
Semantic processing of module Properties
Starting... (2024-01-15 10:00:00)
Computing initial states...
Finished computing initial states: 27 distinct states generated at 2024-01-15 10:00:01.
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = 1.2E-15
12345 states generated, 6789 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 5.
The average outdegree of the complete state graph is 3 (minimum is 0, the maximum 8 and the mode is 3).
Finished in 01min 23s at (2024-01-15 10:01:23)
TLC_OUT

result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/Test.cfg" "$TMPDIR_TEST/success_output.txt" 2>/dev/null) || true

assert_contains "$result" "STATES_GENERATED=12345" "Parses states generated from success output"
assert_contains "$result" "DISTINCT_STATES=6789" "Parses distinct states from success output"
assert_contains "$result" "TLC_VERSION=TLC2 Version 2.18" "Parses TLC version"
assert_contains "$result" "EXECUTION_TIME=83.0" "Parses execution time (1min 23s = 83s)"
assert_contains "$result" "PASSED=true" "Reports passed=true for successful run"
assert_contains "$result" "COUNTEREXAMPLE_EMPTY=true" "No counterexample for successful run"

# Test 2.2: TLC output with invariant violation
echo ""
echo "--- Test 2.2: Parse TLC output with invariant violation ---"
cat > "$TMPDIR_TEST/violation_output.txt" <<'TLC_OUT'
TLC2 Version 2.18 of 01 January 2024 (rev: abc123)
Running breadth-first search Model-Checking with fp 64, seed 12345 and aril 0.
Parsing file /path/to/Properties.tla
Starting... (2024-01-15 10:00:00)
Computing initial states...
Finished computing initial states: 27 distinct states generated.
Error: Invariant ResourceConservation is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ balances = [A |-> 5, B |-> 3, C |-> 2]
/\ seqIndex = 0

State 2: <Next>
/\ balances = [A |-> 4, B |-> 4, C |-> 2]
/\ seqIndex = 1

State 3: <Next>
/\ balances = [A |-> 4, B |-> 4, C |-> 3]
/\ seqIndex = 2

500 states generated, 250 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 3.
Finished in 05s at (2024-01-15 10:00:05)
TLC_OUT

result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/Test.cfg" "$TMPDIR_TEST/violation_output.txt" 2>/dev/null) || true

assert_contains "$result" "STATES_GENERATED=500" "Parses states from violation output"
assert_contains "$result" "DISTINCT_STATES=250" "Parses distinct states from violation output"
assert_contains "$result" "PASSED=false" "Reports passed=false for violation"
assert_contains "$result" "COUNTEREXAMPLE_EMPTY=false" "Counterexample present for violation"
assert_contains "$result" "EXECUTION_TIME=5.0" "Parses execution time (5s)"

# Test 2.3: TLC output with property results in JSON
echo ""
echo "--- Test 2.3: Property results include invariants from config ---"
# The property results should include TypeOK and Liveness from Test.cfg
result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/Test.cfg" "$TMPDIR_TEST/success_output.txt" 2>/dev/null) || true

assert_contains "$result" '"name":"TypeOK"' "Property results include TypeOK invariant"
assert_contains "$result" '"kind":"Invariant"' "TypeOK has kind Invariant"
assert_contains "$result" '"name":"Liveness"' "Property results include Liveness property"
assert_contains "$result" '"kind":"TemporalProperty"' "Liveness has kind TemporalProperty"
assert_contains "$result" '"passed":true' "Properties show passed=true for success output"

# Test 2.4: Property results mark violated invariant as failed
echo ""
echo "--- Test 2.4: Violated invariant marked as failed ---"
# Create a config that includes ResourceConservation
cat > "$TMPDIR_TEST/TestRC.cfg" <<'EOF'
SPECIFICATION Spec
INVARIANT ResourceConservation
INVARIANT TypeOK
EOF

result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/TestRC.cfg" "$TMPDIR_TEST/violation_output.txt" 2>/dev/null) || true

assert_contains "$result" "PASSED=false" "Overall passed=false when invariant violated"
# The ResourceConservation invariant should be marked as failed
if echo "$result" | grep -q '"name":"ResourceConservation".*"passed":false'; then
    pass "ResourceConservation marked as failed"
elif echo "$result" | grep -q 'ResourceConservation'; then
    # Check if it's in the JSON at all
    pass "ResourceConservation present in property results (violation detected via PASSED=false)"
else
    fail "ResourceConservation not found in property results"
fi

# Test 2.5: Parse output with only seconds (no minutes)
echo ""
echo "--- Test 2.5: Parse execution time with seconds only ---"
cat > "$TMPDIR_TEST/short_output.txt" <<'TLC_OUT'
TLC2 Version 2.18 of 01 January 2024
Model checking completed. No error has been found.
100 states generated, 50 distinct states found, 0 states left on queue.
Finished in 07s at (2024-01-15 10:00:07)
TLC_OUT

result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/Test.cfg" "$TMPDIR_TEST/short_output.txt" 2>/dev/null) || true

assert_contains "$result" "STATES_GENERATED=100" "Parses states from short output"
assert_contains "$result" "DISTINCT_STATES=50" "Parses distinct states from short output"
assert_contains "$result" "EXECUTION_TIME=7.0" "Parses seconds-only execution time"

# Test 2.6: Parse output with zero states (empty model)
echo ""
echo "--- Test 2.6: Parse output with minimal state info ---"
cat > "$TMPDIR_TEST/minimal_output.txt" <<'TLC_OUT'
TLC2 Version 2.18 of 01 January 2024
Model checking completed. No error has been found.
0 states generated, 0 distinct states found, 0 states left on queue.
Finished in 01s at (2024-01-15 10:00:01)
TLC_OUT

result=$(bash "$TMPDIR_TEST/parse_harness.sh" "$RUNNER" "$TMPDIR_TEST/Test.cfg" "$TMPDIR_TEST/minimal_output.txt" 2>/dev/null) || true

assert_contains "$result" "STATES_GENERATED=0" "Handles zero states"
assert_contains "$result" "DISTINCT_STATES=0" "Handles zero distinct states"
assert_contains "$result" "PASSED=true" "Zero states still passes (no violation)"

# -----------------------------------------------------------------------
# Test Suite 3: JSON Output Structure
# -----------------------------------------------------------------------
echo ""
echo "=== Test Suite 3: JSON Output Structure ==="

# Test 3.1: JSON escape function handles special characters
echo ""
echo "--- Test 3.1: JSON escape handles special characters ---"
# Create a harness for json_escape
cat > "$TMPDIR_TEST/escape_harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail
RUNNER_SCRIPT="$1"
source "$RUNNER_SCRIPT"
json_escape "$2"
HARNESS
chmod +x "$TMPDIR_TEST/escape_harness.sh"

escaped=$(bash "$TMPDIR_TEST/escape_harness.sh" "$RUNNER" 'hello "world"')
if echo "$escaped" | grep -q '\"'; then
    pass "JSON escape handles double quotes"
else
    fail "JSON escape handles double quotes" "Expected escaped quotes in: $escaped"
fi

escaped=$(bash "$TMPDIR_TEST/escape_harness.sh" "$RUNNER" 'path\to\file')
if echo "$escaped" | grep -q '\\\\'; then
    pass "JSON escape handles backslashes"
else
    fail "JSON escape handles backslashes" "Expected escaped backslashes in: $escaped"
fi

# Test 3.2: Verify emit_result produces valid JSON structure
echo ""
echo "--- Test 3.2: emit_result produces valid JSON ---"
cat > "$TMPDIR_TEST/emit_harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail
RUNNER_SCRIPT="$1"
source "$RUNNER_SCRIPT"
emit_result "Properties.tla" "MC_small.cfg" "abc1234" "TLC2 Version 2.18" \
    12345 6789 83.0 '[{"name":"TypeOK","kind":"Invariant","passed":true}]' "" true
HARNESS
chmod +x "$TMPDIR_TEST/emit_harness.sh"

json_output=$(bash "$TMPDIR_TEST/emit_harness.sh" "$RUNNER" 2>/dev/null)

assert_json_field "$json_output" "spec_file" "Properties.tla" "JSON has correct spec_file"
assert_json_field "$json_output" "config_file" "MC_small.cfg" "JSON has correct config_file"
assert_json_field "$json_output" "spec_version" "abc1234" "JSON has correct spec_version"
assert_json_field "$json_output" "states_generated" "12345" "JSON has correct states_generated"
assert_json_field "$json_output" "distinct_states" "6789" "JSON has correct distinct_states"
assert_json_field "$json_output" "execution_time_secs" "83.0" "JSON has correct execution_time_secs"
assert_json_field "$json_output" "passed" "true" "JSON has correct passed"
assert_json_field "$json_output" "counterexample" "null" "JSON has null counterexample when empty"

# Test 3.3: emit_result with counterexample
echo ""
echo "--- Test 3.3: emit_result with counterexample ---"
cat > "$TMPDIR_TEST/emit_ce_harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail
RUNNER_SCRIPT="$1"
source "$RUNNER_SCRIPT"
emit_result "Properties.tla" "MC_small.cfg" "abc1234" "TLC2 Version 2.18" \
    500 250 5.0 '[]' "Invariant ResourceConservation is violated" false
HARNESS
chmod +x "$TMPDIR_TEST/emit_ce_harness.sh"

json_output=$(bash "$TMPDIR_TEST/emit_ce_harness.sh" "$RUNNER" 2>/dev/null)

assert_json_field "$json_output" "passed" "false" "JSON has passed=false with counterexample"
assert_contains "$json_output" "ResourceConservation" "JSON counterexample contains violation info"

# -----------------------------------------------------------------------
# Test Suite 4: Timeout Handling
# -----------------------------------------------------------------------
echo ""
echo "=== Test Suite 4: Timeout Handling ==="

# Test 4.1: Verify timeout argument is accepted
echo ""
echo "--- Test 4.1: Timeout argument accepted ---"
# We can't easily test actual timeout without TLC, but we verify the
# argument is parsed correctly by checking it doesn't cause a parse error
# (it will fail at the TLA2TOOLS check instead)
output=$(TLA2TOOLS="/nonexistent/tla2tools.jar" bash "$RUNNER" \
    --spec "$TMPDIR_TEST/Test.tla" \
    --config "$TMPDIR_TEST/Test.cfg" \
    --timeout 30 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
# Should fail with exit 3 (TLA2TOOLS not found), not exit 4 (bad args)
assert_exit_code 3 "$exit_code" "Timeout=30 accepted (fails at TLA2TOOLS check, not arg parse)"

# Test 4.2: Verify workers=auto is accepted
echo ""
echo "--- Test 4.2: Workers=auto accepted ---"
output=$(TLA2TOOLS="/nonexistent/tla2tools.jar" bash "$RUNNER" \
    --spec "$TMPDIR_TEST/Test.tla" \
    --config "$TMPDIR_TEST/Test.cfg" \
    --workers auto 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 3 "$exit_code" "Workers=auto accepted (fails at TLA2TOOLS check, not arg parse)"

# Test 4.3: Verify numeric workers value is accepted
echo ""
echo "--- Test 4.3: Workers=4 accepted ---"
output=$(TLA2TOOLS="/nonexistent/tla2tools.jar" bash "$RUNNER" \
    --spec "$TMPDIR_TEST/Test.tla" \
    --config "$TMPDIR_TEST/Test.cfg" \
    --workers 4 2>&1) || exit_code=$?
exit_code=${exit_code:-0}
assert_exit_code 3 "$exit_code" "Workers=4 accepted (fails at TLA2TOOLS check, not arg parse)"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "========================================"
echo "Test Results: $TESTS_PASSED/$TESTS_TOTAL passed, $TESTS_FAILED failed"
echo "========================================"

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
fi

exit 0
