#!/usr/bin/env bash
# -----------------------------------------------------------------------
# tlc_runner.sh — Structured TLC execution with JSON output
#
# Executes TLC against a TLA+ specification with a given configuration,
# parses the output, and produces a structured JSON result matching
# the TlcResult data model from the production-readiness design.
#
# Usage:
#   ./scripts/tlc_runner.sh --spec <file> --config <file> \
#       [--timeout <seconds>] [--workers <count|auto>]
#
# Exit codes:
#   0 — All invariants and properties passed
#   1 — Invariant or property violation (counterexample found)
#   2 — TLC execution timeout
#   3 — TLC execution error (Java error, missing files, etc.)
#   4 — Invalid arguments
#
# Requirements: 8.6, 8.7, 9.3, 9.4, 10.1, 10.2
# -----------------------------------------------------------------------

set -euo pipefail

# -----------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------
SPEC_FILE=""
CONFIG_FILE=""
TIMEOUT_SECS=120
WORKERS="auto"
TLA2TOOLS="${TLA2TOOLS:-/opt/tla/tla2tools.jar}"

# -----------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $0 --spec <file> --config <file> [--timeout <seconds>] [--workers <count|auto>]

Arguments:
  --spec <file>       TLA+ specification file (required)
  --config <file>     TLC configuration file (required)
  --timeout <seconds> Execution timeout in seconds (default: 120)
  --workers <n|auto>  Number of TLC worker threads (default: auto)

Environment:
  TLA2TOOLS           Path to tla2tools.jar (default: /opt/tla/tla2tools.jar)

Exit codes:
  0  All properties passed
  1  Invariant/property violation found
  2  Timeout exceeded
  3  TLC execution error
  4  Invalid arguments
EOF
    exit 4
}

# -----------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --spec)
                [[ $# -lt 2 ]] && { echo "Error: --spec requires a value" >&2; usage; }
                SPEC_FILE="$2"
                shift 2
                ;;
            --config)
                [[ $# -lt 2 ]] && { echo "Error: --config requires a value" >&2; usage; }
                CONFIG_FILE="$2"
                shift 2
                ;;
            --timeout)
                [[ $# -lt 2 ]] && { echo "Error: --timeout requires a value" >&2; usage; }
                TIMEOUT_SECS="$2"
                shift 2
                ;;
            --workers)
                [[ $# -lt 2 ]] && { echo "Error: --workers requires a value" >&2; usage; }
                WORKERS="$2"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            *)
                echo "Error: Unknown argument: $1" >&2
                usage
                ;;
        esac
    done
}

# -----------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------
validate_args() {
    if [[ -z "$SPEC_FILE" ]]; then
        echo "Error: --spec is required" >&2
        usage
    fi

    if [[ -z "$CONFIG_FILE" ]]; then
        echo "Error: --config is required" >&2
        usage
    fi

    if [[ ! -f "$SPEC_FILE" ]]; then
        echo "Error: Spec file not found: $SPEC_FILE" >&2
        exit 3
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Error: Config file not found: $CONFIG_FILE" >&2
        exit 3
    fi

    if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
        echo "Error: --timeout must be a positive integer, got: $TIMEOUT_SECS" >&2
        exit 4
    fi

    if [[ "$WORKERS" != "auto" ]] && ! [[ "$WORKERS" =~ ^[0-9]+$ ]]; then
        echo "Error: --workers must be 'auto' or a positive integer, got: $WORKERS" >&2
        exit 4
    fi

    if [[ ! -f "$TLA2TOOLS" ]]; then
        echo "Error: tla2tools.jar not found at: $TLA2TOOLS" >&2
        echo "Set TLA2TOOLS environment variable to the correct path." >&2
        exit 3
    fi
}

# -----------------------------------------------------------------------
# JSON helpers (pure bash, no jq dependency)
# -----------------------------------------------------------------------
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# -----------------------------------------------------------------------
# Output structured JSON result
# -----------------------------------------------------------------------
emit_result() {
    local spec_file="$1"
    local config_file="$2"
    local spec_version="$3"
    local tlc_version="$4"
    local states_generated="$5"
    local distinct_states="$6"
    local execution_time="$7"
    local property_results_json="$8"
    local counterexample="$9"
    local passed="${10}"

    local ce_field="null"
    if [[ -n "$counterexample" ]]; then
        ce_field="\"$(json_escape "$counterexample")\""
    fi

    cat <<EOF
{
  "spec_file": "$(json_escape "$spec_file")",
  "config_file": "$(json_escape "$config_file")",
  "spec_version": "$(json_escape "$spec_version")",
  "tlc_version": "$(json_escape "$tlc_version")",
  "states_generated": $states_generated,
  "distinct_states": $distinct_states,
  "execution_time_secs": $execution_time,
  "property_results": $property_results_json,
  "counterexample": $ce_field,
  "passed": $passed
}
EOF
}

# -----------------------------------------------------------------------
# Parse TLC output
# -----------------------------------------------------------------------
parse_tlc_output() {
    local output="$1"

    # Extract state counts
    # TLC outputs lines like:
    #   "12345 states generated, 6789 distinct states found"
    STATES_GENERATED=0
    DISTINCT_STATES=0
    if echo "$output" | grep -qE '[0-9]+ states generated'; then
        STATES_GENERATED=$(echo "$output" | grep -oE '[0-9]+ states generated' | head -1 | grep -oE '^[0-9]+')
        DISTINCT_STATES=$(echo "$output" | grep -oE '[0-9]+ distinct states found' | head -1 | grep -oE '^[0-9]+')
    fi
    STATES_GENERATED="${STATES_GENERATED:-0}"
    DISTINCT_STATES="${DISTINCT_STATES:-0}"

    # Extract TLC version
    # TLC outputs: "TLC2 Version 2.18 of ..."
    TLC_VERSION="unknown"
    if echo "$output" | grep -qE 'TLC2? Version'; then
        TLC_VERSION=$(echo "$output" | grep -oE 'TLC2? Version [0-9]+\.[0-9]+[^ ]*' | head -1)
    fi

    # Extract execution time
    # TLC outputs: "Finished in 01min 23s at (2024-01-01 ...)"
    # or: "The depth of the complete state graph search is 5."
    # followed by "Finished in XXs at ..."
    EXECUTION_TIME="0.0"
    if echo "$output" | grep -qE 'Finished in'; then
        local time_str
        time_str=$(echo "$output" | grep -oE 'Finished in [^a]+' | head -1)
        # Parse "Finished in XXmin YYs" or "Finished in XXs"
        local mins=0
        local secs=0
        if echo "$time_str" | grep -qE '[0-9]+min'; then
            mins=$(echo "$time_str" | grep -oE '[0-9]+min' | grep -oE '[0-9]+')
        fi
        if echo "$time_str" | grep -qE '[0-9]+s'; then
            secs=$(echo "$time_str" | grep -oE '[0-9]+s' | grep -oE '[0-9]+')
        fi
        EXECUTION_TIME=$(echo "$mins $secs" | awk '{printf "%.1f", $1 * 60 + $2}')
    fi

    # Check for violations
    COUNTEREXAMPLE=""
    PASSED=true

    # Check for invariant violations
    # TLC outputs: "Error: Invariant InvariantName is violated."
    if echo "$output" | grep -qiE '(invariant .* is violated|error:.*violated|property .* is violated)'; then
        PASSED=false
        # Extract the counterexample trace
        COUNTEREXAMPLE=$(echo "$output" | sed -n '/Error:/,/^$/p' | head -100)
        if [[ -z "$COUNTEREXAMPLE" ]]; then
            COUNTEREXAMPLE=$(echo "$output" | grep -A 50 -iE '(violated|counterexample|error trace)')
        fi
    fi

    # Check for general TLC errors
    if echo "$output" | grep -qiE '^Error:'; then
        if [[ "$PASSED" == "true" ]]; then
            PASSED=false
            COUNTEREXAMPLE=$(echo "$output" | grep -A 10 -iE '^Error:')
        fi
    fi

    # Build property results JSON
    # Parse INVARIANT and PROPERTY declarations from the config file
    local property_results="["
    local first=true

    # Read invariants from config
    while IFS= read -r line; do
        local name
        name=$(echo "$line" | sed 's/^INVARIANT[[:space:]]*//')
        name=$(echo "$name" | sed 's/[[:space:]]*$//')
        [[ -z "$name" ]] && continue

        local prop_passed=true
        if echo "$output" | grep -qiE "Invariant $name is violated"; then
            prop_passed=false
        fi

        if [[ "$first" == "true" ]]; then
            first=false
        else
            property_results+=","
        fi
        property_results+="{\"name\":\"$(json_escape "$name")\",\"kind\":\"Invariant\",\"passed\":$prop_passed}"
    done < <(grep '^INVARIANT' "$CONFIG_FILE" | grep -v '^\\\*')

    # Read temporal properties from config
    while IFS= read -r line; do
        local name
        name=$(echo "$line" | sed 's/^PROPERTY[[:space:]]*//')
        name=$(echo "$name" | sed 's/[[:space:]]*$//')
        [[ -z "$name" ]] && continue

        local prop_passed=true
        if echo "$output" | grep -qiE "property $name is violated"; then
            prop_passed=false
        fi

        if [[ "$first" == "true" ]]; then
            first=false
        else
            property_results+=","
        fi
        property_results+="{\"name\":\"$(json_escape "$name")\",\"kind\":\"TemporalProperty\",\"passed\":$prop_passed}"
    done < <(grep '^PROPERTY' "$CONFIG_FILE" | grep -v '^\\\*')

    property_results+="]"

    PROPERTY_RESULTS_JSON="$property_results"
}

# -----------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------
main() {
    parse_args "$@"
    validate_args

    # Get spec version from git
    local spec_version
    spec_version=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Determine the spec directory for TLC working directory
    local spec_dir
    spec_dir=$(dirname "$SPEC_FILE")

    # Get the spec module name (filename without .tla extension)
    local spec_name
    spec_name=$(basename "$SPEC_FILE" .tla)

    # Build TLC command
    local tlc_cmd=(
        java -cp "$TLA2TOOLS" tlc2.TLC
        "$spec_name"
        -config "$(realpath "$CONFIG_FILE")"
        -workers "$WORKERS"
        -noGenerateSpecTE
    )

    echo "Running TLC: ${tlc_cmd[*]}" >&2
    echo "  Spec: $SPEC_FILE" >&2
    echo "  Config: $CONFIG_FILE" >&2
    echo "  Timeout: ${TIMEOUT_SECS}s" >&2
    echo "  Workers: $WORKERS" >&2

    # Execute TLC with timeout
    local tlc_output=""
    local tlc_exit=0
    local timed_out=false

    if command -v timeout &>/dev/null; then
        tlc_output=$(timeout "${TIMEOUT_SECS}s" "${tlc_cmd[@]}" 2>&1) || tlc_exit=$?
        if [[ $tlc_exit -eq 124 ]]; then
            timed_out=true
        fi
    else
        # macOS fallback: use perl for timeout
        tlc_output=$(perl -e '
            use POSIX ":sys_wait_h";
            $SIG{ALRM} = sub { kill 9, $pid; exit 124; };
            alarm('"$TIMEOUT_SECS"');
            $pid = open(my $fh, "-|", @ARGV) or die "exec: $!";
            local $/;
            print <$fh>;
            close $fh;
            exit $? >> 8;
        ' -- "${tlc_cmd[@]}" 2>&1) || tlc_exit=$?
        if [[ $tlc_exit -eq 124 ]]; then
            timed_out=true
        fi
    fi

    # Handle timeout
    if [[ "$timed_out" == "true" ]]; then
        echo "Error: TLC execution timed out after ${TIMEOUT_SECS}s" >&2
        parse_tlc_output "$tlc_output"
        emit_result \
            "$SPEC_FILE" \
            "$CONFIG_FILE" \
            "$spec_version" \
            "${TLC_VERSION:-unknown}" \
            "${STATES_GENERATED:-0}" \
            "${DISTINCT_STATES:-0}" \
            "$TIMEOUT_SECS.0" \
            "${PROPERTY_RESULTS_JSON:-[]}" \
            "TLC execution timed out after ${TIMEOUT_SECS} seconds. Partial results: ${STATES_GENERATED:-0} states generated, ${DISTINCT_STATES:-0} distinct states." \
            "false"
        exit 2
    fi

    # Parse TLC output
    parse_tlc_output "$tlc_output"

    # Emit structured JSON result
    emit_result \
        "$SPEC_FILE" \
        "$CONFIG_FILE" \
        "$spec_version" \
        "$TLC_VERSION" \
        "$STATES_GENERATED" \
        "$DISTINCT_STATES" \
        "$EXECUTION_TIME" \
        "$PROPERTY_RESULTS_JSON" \
        "$COUNTEREXAMPLE" \
        "$PASSED"

    # Exit with appropriate code
    if [[ "$PASSED" == "true" ]]; then
        echo "TLC: All properties passed ($STATES_GENERATED states, $DISTINCT_STATES distinct)" >&2
        exit 0
    else
        echo "TLC: VIOLATION DETECTED" >&2
        echo "$COUNTEREXAMPLE" >&2
        exit 1
    fi
}

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
