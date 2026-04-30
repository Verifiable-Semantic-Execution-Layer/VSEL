#!/usr/bin/env bash
# -----------------------------------------------------------------------
# parse_tlc_audit.sh — Parse TLC output into structured audit evidence
#
# Reads TLC output from a file and produces a JSON audit evidence record
# linking results to requirements and MODEL_CHECKING_PLAN.md.
#
# Usage:
#   ./scripts/parse_tlc_audit.sh <tlc_output_file> <config_file>
#
# Output: JSON to stdout
#
# Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
# -----------------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <tlc_output_file> <config_file>" >&2
    exit 1
fi

TLC_OUTPUT_FILE="$1"
CONFIG_FILE="$2"

if [[ ! -f "$TLC_OUTPUT_FILE" ]]; then
    echo "Error: TLC output file not found: $TLC_OUTPUT_FILE" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found: $CONFIG_FILE" >&2
    exit 1
fi

OUTPUT=$(cat "$TLC_OUTPUT_FILE")

# Extract state counts
STATES_GENERATED=$(echo "$OUTPUT" | grep -oE '[0-9]+ states generated' | head -1 | grep -oE '^[0-9]+' || echo "0")
DISTINCT_STATES=$(echo "$OUTPUT" | grep -oE '[0-9]+ distinct states found' | head -1 | grep -oE '^[0-9]+' || echo "0")

# Extract TLC version
TLC_VERSION=$(echo "$OUTPUT" | grep -oE 'TLC2? Version [0-9]+\.[0-9]+[^ ]*' | head -1 || echo "unknown")

# Extract execution time
EXEC_TIME="0.0"
if echo "$OUTPUT" | grep -qE 'Finished in'; then
    MINS=$(echo "$OUTPUT" | grep -oE '[0-9]+min' | head -1 | grep -oE '[0-9]+' || echo "0")
    SECS=$(echo "$OUTPUT" | grep -oE '[0-9]+s' | head -1 | grep -oE '[0-9]+' || echo "0")
    EXEC_TIME=$(echo "$MINS $SECS" | awk '{printf "%.1f", $1 * 60 + $2}')
fi

# Check for violations
PASSED=true
VIOLATION=""
if echo "$OUTPUT" | grep -qiE '(invariant .* is violated|property .* is violated|^Error:)'; then
    PASSED=false
    VIOLATION=$(echo "$OUTPUT" | grep -iE '(violated|Error:)' | head -5)
fi

# Get spec version
SPEC_VERSION=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build property results
PROP_JSON="["
FIRST=true
while IFS= read -r line; do
    NAME=$(echo "$line" | sed 's/^INVARIANT[[:space:]]*//' | sed 's/[[:space:]]*$//')
    [[ -z "$NAME" ]] && continue
    PROP_PASSED=true
    if echo "$OUTPUT" | grep -qiE "Invariant $NAME is violated"; then PROP_PASSED=false; fi
    [[ "$FIRST" == "true" ]] && FIRST=false || PROP_JSON+=","
    PROP_JSON+="{\"name\":\"$NAME\",\"kind\":\"Invariant\",\"passed\":$PROP_PASSED}"
done < <(grep '^INVARIANT' "$CONFIG_FILE" 2>/dev/null | grep -v '^\\\*' || true)

while IFS= read -r line; do
    NAME=$(echo "$line" | sed 's/^PROPERTY[[:space:]]*//' | sed 's/[[:space:]]*$//')
    [[ -z "$NAME" ]] && continue
    PROP_PASSED=true
    if echo "$OUTPUT" | grep -qiE "property $NAME is violated"; then PROP_PASSED=false; fi
    [[ "$FIRST" == "true" ]] && FIRST=false || PROP_JSON+=","
    PROP_JSON+="{\"name\":\"$NAME\",\"kind\":\"TemporalProperty\",\"passed\":$PROP_PASSED}"
done < <(grep '^PROPERTY' "$CONFIG_FILE" 2>/dev/null | grep -v '^\\\*' || true)
PROP_JSON+="]"

# Determine config tier
CONFIG_NAME=$(basename "$CONFIG_FILE")
TIER="unknown"
case "$CONFIG_NAME" in
    MC_small.cfg) TIER="per-commit" ;;
    MC_medium.cfg) TIER="nightly" ;;
    MC_large.cfg) TIER="weekly" ;;
    Composition_MC.cfg) TIER="per-commit" ;;
esac

# Determine requirements covered
REQS="[]"
case "$TIER" in
    per-commit) REQS='["8.1","8.2","8.3","8.4","8.5","8.6","8.7"]' ;;
    nightly) REQS='["9.1","9.3","9.4","9.5"]' ;;
    weekly) REQS='["9.2","9.4","9.5","9.6","10.3","10.4"]' ;;
esac

# Escape violation for JSON
VIOLATION_JSON="null"
if [[ -n "$VIOLATION" ]]; then
    ESCAPED=$(echo "$VIOLATION" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')
    VIOLATION_JSON="\"$ESCAPED\""
fi

cat <<EOF
{
  "audit_evidence": {
    "type": "tlc_model_checking",
    "tier": "$TIER",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "spec_version": "$SPEC_VERSION",
    "tlc_version": "$TLC_VERSION",
    "config_file": "$CONFIG_NAME",
    "states_generated": $STATES_GENERATED,
    "distinct_states": $DISTINCT_STATES,
    "execution_time_secs": $EXEC_TIME,
    "property_results": $PROP_JSON,
    "counterexample": $VIOLATION_JSON,
    "passed": $PASSED,
    "requirements_covered": $REQS,
    "reference": "docs/MODEL_CHECKING_PLAN.md"
  }
}
EOF
