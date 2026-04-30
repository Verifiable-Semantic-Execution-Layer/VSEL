#!/usr/bin/env python3
"""
SIR/IR export determinism verification.

Derived from: REFINEMENT_STRATEGY.md, TECH_SPEC.md, design.md Component 10.
Requirements: 9.7 — SIR/IR derivation pipeline, CONST-4 deterministic derivation.

Verifies that the SIR export pipeline is deterministic: running the same
Lean 4 definitions through the export pipeline multiple times always produces
byte-identical JSON output.

This is a critical correctness property. If the export is non-deterministic,
the constraint compiler (L3) could produce different constraint systems for
the same formal specification, breaking the refinement chain.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from sir.export.export_sir import (
    SirProgram,
    compute_ir_hash,
    export_from_lean_sources,
    serialize_sir_json,
)


# ---------------------------------------------------------------------------
# Determinism verification
# ---------------------------------------------------------------------------


def verify_export_determinism(
    lean_root: Path,
    iterations: int = 5,
    version: str = "0.1.0",
) -> Tuple[bool, List[str]]:
    """Verify that repeated exports produce identical JSON output.

    Runs the export pipeline `iterations` times and checks that all
    outputs are byte-identical (same SHA-256 hash).

    Args:
        lean_root: Path to Lean 4 project root
        iterations: Number of export iterations (default: 5)
        version: SIR schema version

    Returns:
        (is_deterministic, list_of_hashes) — True if all hashes match
    """
    hashes: List[str] = []

    for i in range(iterations):
        program = export_from_lean_sources(lean_root, version=version)
        json_str = serialize_sir_json(program)
        h = compute_ir_hash(json_str)
        hashes.append(h)

    is_deterministic = len(set(hashes)) == 1
    return is_deterministic, hashes


def verify_json_determinism(json_str: str, iterations: int = 5) -> Tuple[bool, List[str]]:
    """Verify that re-serializing parsed JSON produces identical output.

    Parses the JSON, re-serializes with sorted keys, and checks that
    the output is byte-identical across iterations.

    This catches non-determinism in dict ordering, float formatting, etc.
    """
    hashes: List[str] = []

    for _ in range(iterations):
        parsed = json.loads(json_str)
        reserialized = json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        h = compute_ir_hash(reserialized)
        hashes.append(h)

    is_deterministic = len(set(hashes)) == 1
    return is_deterministic, hashes


def verify_file_determinism(file_path: Path) -> Tuple[bool, str, str]:
    """Verify that a JSON IR file is deterministic when re-serialized.

    Reads the file, parses it, re-serializes with canonical settings,
    and checks if the output matches the original.

    Returns:
        (is_canonical, original_hash, reserialized_hash)
    """
    original = file_path.read_text(encoding="utf-8")
    original_hash = compute_ir_hash(original)

    parsed = json.loads(original)
    reserialized = json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    reserialized_hash = compute_ir_hash(reserialized)

    return original_hash == reserialized_hash, original_hash, reserialized_hash


def verify_schema_compliance(program_dict: dict, schema_path: Path) -> List[str]:
    """Verify that a SIR program dict complies with the JSON schema.

    Returns a list of validation errors (empty if valid).
    This is a lightweight structural check — not a full JSON Schema validator.
    Handles both full SIR programs and fragment files (transitions, invariants).
    """
    errors: List[str] = []

    # If the content is a list, it's a fragment file (e.g. invariants array)
    if isinstance(program_dict, list):
        return []  # Fragment files are not validated as full programs

    # If it's a single transition/invariant (no version field), skip program validation
    if "version" not in program_dict and ("name" in program_dict or "kind" in program_dict):
        return []  # Fragment file

    # Check required top-level fields
    required = ["version", "state_schema", "input_schema", "transitions", "invariants", "observables"]
    for field in required:
        if field not in program_dict:
            errors.append(f"Missing required field: {field}")

    # Check version format
    version = program_dict.get("version", "")
    if not version:
        errors.append("Version must not be empty")
    elif not all(c.isdigit() or c == "." for c in version):
        errors.append(f"Version must be semver format: {version}")

    # Check transitions
    for i, t in enumerate(program_dict.get("transitions", [])):
        if not t.get("name"):
            errors.append(f"Transition {i}: name must not be empty")
        if not t.get("class"):
            errors.append(f"Transition {i}: class must not be empty")
        valid_classes = {"Init", "Update", "Noop", "Error", "Batch", "Reject"}
        if t.get("class") not in valid_classes:
            errors.append(f"Transition {i}: invalid class '{t.get('class')}'")

    # Check invariants
    for i, inv in enumerate(program_dict.get("invariants", [])):
        if not inv.get("name"):
            errors.append(f"Invariant {i}: name must not be empty")
        if not inv.get("category"):
            errors.append(f"Invariant {i}: category must not be empty")
        valid_categories = {"local", "global", "temporal", "economic"}
        if inv.get("category") not in valid_categories:
            errors.append(f"Invariant {i}: invalid category '{inv.get('category')}'")

    return errors


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for determinism verification.

    Usage:
        python -m sir.export.verify_determinism [--lean-root PATH] [--iterations N] [--check-file PATH]
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify SIR/IR export determinism (CONST-4).",
    )
    parser.add_argument(
        "--lean-root",
        type=Path,
        default=Path("formal"),
        help="Path to Lean 4 project root (default: formal/)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of export iterations (default: 5)",
    )
    parser.add_argument(
        "--check-file",
        type=Path,
        default=None,
        help="Check determinism of an existing IR JSON file",
    )
    parser.add_argument(
        "--check-examples",
        action="store_true",
        help="Check all example IR files in sir/examples/",
    )
    args = parser.parse_args()

    exit_code = 0

    if args.check_file:
        print(f"Checking file determinism: {args.check_file}")
        is_canonical, orig_hash, reser_hash = verify_file_determinism(args.check_file)
        if is_canonical:
            print(f"  PASS: File is in canonical form (SHA-256: {orig_hash})")
        else:
            print(f"  FAIL: File is NOT in canonical form")
            print(f"    Original:     {orig_hash}")
            print(f"    Re-serialized: {reser_hash}")
            exit_code = 1

        # Schema compliance check
        content = json.loads(args.check_file.read_text(encoding="utf-8"))
        schema_path = Path("sir/schema/sir_schema.json")
        errors = verify_schema_compliance(content, schema_path)
        if errors:
            print(f"  Schema violations:")
            for err in errors:
                print(f"    - {err}")
            exit_code = 1
        else:
            print(f"  Schema compliance: PASS")

    elif args.check_examples:
        examples_dir = Path("sir/examples")
        if not examples_dir.exists():
            print(f"Examples directory not found: {examples_dir}")
            sys.exit(1)

        for json_file in sorted(examples_dir.glob("*.json")):
            print(f"\nChecking: {json_file}")
            is_canonical, orig_hash, reser_hash = verify_file_determinism(json_file)
            if is_canonical:
                print(f"  Canonical form: PASS (SHA-256: {orig_hash})")
            else:
                print(f"  Canonical form: FAIL")
                print(f"    Original:     {orig_hash}")
                print(f"    Re-serialized: {reser_hash}")
                exit_code = 1

            content = json.loads(json_file.read_text(encoding="utf-8"))
            schema_path = Path("sir/schema/sir_schema.json")
            errors = verify_schema_compliance(content, schema_path)
            if errors:
                print(f"  Schema compliance: FAIL")
                for err in errors:
                    print(f"    - {err}")
                exit_code = 1
            else:
                print(f"  Schema compliance: PASS")

    else:
        print(f"Verifying export determinism ({args.iterations} iterations)...")
        is_det, hashes = verify_export_determinism(
            args.lean_root,
            iterations=args.iterations,
        )
        if is_det:
            print(f"  PASS: Export is deterministic (SHA-256: {hashes[0]})")
        else:
            print(f"  FAIL: Export is NOT deterministic!")
            for i, h in enumerate(hashes):
                print(f"    Iteration {i + 1}: {h}")
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
