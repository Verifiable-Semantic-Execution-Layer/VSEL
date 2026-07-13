#!/usr/bin/env bash
# Check that Lean axioms are explicitly inventoried and validation-mapped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LEDGER="$PROJECT_ROOT/docs/AXIOM_LEDGER.tsv"
VALIDATION_MAP="$PROJECT_ROOT/docs/AXIOM_VALIDATION_MAP.md"
FORMAL_DIR="$PROJECT_ROOT/formal/VSEL"

if [ ! -s "$LEDGER" ]; then
  echo "[axiom-ledger] missing ledger: $LEDGER" >&2
  exit 1
fi

if [ ! -s "$VALIDATION_MAP" ]; then
  echo "[axiom-ledger] missing validation map: $VALIDATION_MAP" >&2
  exit 1
fi

if rg -n '\bsorry\b' "$FORMAL_DIR" --glob '*.lean'; then
  echo "[axiom-ledger] Lean sorry detected; formal gate fails closed" >&2
  exit 1
fi

actual="$(mktemp)"
expected="$(mktemp)"
trap 'rm -f "$actual" "$expected"' EXIT

awk '
  /^[[:space:]]*axiom[[:space:]]+/ {
    name=$2
    sub(/\(.*/, "", name)
    sub(/:.*/, "", name)
    print FILENAME "\t" name
  }
' $(find "$FORMAL_DIR" -name '*.lean' -type f | sort) \
  | sed "s|$PROJECT_ROOT/||" \
  | sort >"$actual"

awk '
  /^[[:space:]]*#/ { next }
  NF >= 2 { print $1 "\t" $2 }
' "$LEDGER" | sort >"$expected"

if ! diff -u "$expected" "$actual"; then
  echo "[axiom-ledger] actual Lean axioms diverge from docs/AXIOM_LEDGER.tsv" >&2
  exit 1
fi

while IFS=$'\t' read -r _file name; do
  if ! grep -Fq "$name" "$VALIDATION_MAP"; then
    echo "[axiom-ledger] axiom is missing from validation map: $name" >&2
    exit 1
  fi
done <"$actual"

count="$(wc -l <"$actual" | tr -d ' ')"
echo "[axiom-ledger] PASS: $count axioms inventoried, zero sorry, validation map complete"
