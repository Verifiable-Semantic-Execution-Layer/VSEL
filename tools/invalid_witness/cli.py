#!/usr/bin/env python3
"""
CLI for the Invalid Witness Generator Suite.

Usage:
    python -m tools.invalid_witness.cli list              # List all families
    python -m tools.invalid_witness.cli generate           # Generate all witnesses
    python -m tools.invalid_witness.cli generate W1        # Generate W1 family only
    python -m tools.invalid_witness.cli summary            # Print summary report
    python -m tools.invalid_witness.cli protocol           # Run 5-step protocol on all
    python -m tools.invalid_witness.cli protocol W1.1      # Run protocol on one family
    python -m tools.invalid_witness.cli coverage           # Check constraint coverage
    python -m tools.invalid_witness.cli mapping            # Show witness→constraint map
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .constraint_mapping import (
    ALL_CONSTRAINTS,
    WITNESS_CONSTRAINT_MAP,
    ConstraintMapping,
)
from .generators import (
    W1StateViolation,
    W2TransitionViolation,
    W3TraceStructure,
    W4ObservableManipulation,
    W5AuthorizationManipulation,
    W6BatchManipulation,
    W7CommitmentManipulation,
    W8CrossSystem,
    generate_all_invalid_witnesses,
)
from .protocol import (
    print_protocol_report,
    run_protocol,
    run_protocol_all,
    verify_constraint_coverage,
)
from .types import InvalidWitness


FAMILIES = {
    "W1": ("State Violation", W1StateViolation),
    "W2": ("Transition Violation", W2TransitionViolation),
    "W3": ("Trace Structure", W3TraceStructure),
    "W4": ("Observable Manipulation", W4ObservableManipulation),
    "W5": ("Authorization Manipulation", W5AuthorizationManipulation),
    "W6": ("Batch Manipulation", W6BatchManipulation),
    "W7": ("Commitment Manipulation", W7CommitmentManipulation),
    "W8": ("Cross-System", W8CrossSystem),
}


def cmd_list() -> None:
    """List all invalid witness families."""
    print("Invalid Execution Witness Suite — Families")
    print("=" * 60)
    for family_id, (name, cls) in FAMILIES.items():
        witnesses = cls.all()
        print(f"\n{family_id}: {name} ({len(witnesses)} witnesses)")
        for w in witnesses:
            print(f"  {w.family}: {w.name}")
            print(f"    {w.description}")
            print(f"    Expected rejection: {w.expected_rejection}")


def cmd_generate(family_filter: str | None = None) -> None:
    """Generate invalid witnesses and print as JSON."""
    if family_filter:
        family_filter = family_filter.upper()
        if family_filter not in FAMILIES:
            print(f"Unknown family: {family_filter}", file=sys.stderr)
            print(f"Available: {', '.join(FAMILIES.keys())}", file=sys.stderr)
            sys.exit(1)
        _, cls = FAMILIES[family_filter]
        witnesses = cls.all()
    else:
        witnesses = generate_all_invalid_witnesses()

    output = []
    for w in witnesses:
        output.append({
            "family": w.family,
            "name": w.name,
            "description": w.description,
            "expected_rejection": w.expected_rejection,
        })

    print(json.dumps(output, indent=2))


def cmd_summary() -> None:
    """Print a summary report of all invalid witnesses."""
    witnesses = generate_all_invalid_witnesses()

    print("Invalid Execution Witness Suite — Summary Report")
    print("=" * 60)
    print(f"Total witnesses: {len(witnesses)}")
    print()

    # Group by family prefix
    by_family: dict[str, list[InvalidWitness]] = {}
    for w in witnesses:
        prefix = w.family.split(".")[0]
        by_family.setdefault(prefix, []).append(w)

    for family_id in sorted(by_family.keys()):
        family_witnesses = by_family[family_id]
        name = FAMILIES.get(family_id, ("Unknown",))[0]
        print(f"{family_id}: {name}")
        print(f"  Count: {len(family_witnesses)}")
        for w in family_witnesses:
            print(f"  - {w.family} {w.name}: {w.expected_rejection}")
        print()

    print("Coverage:")
    for family_id in ["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"]:
        count = len(by_family.get(family_id, []))
        status = "✓" if count > 0 else "✗"
        name = FAMILIES.get(family_id, ("Unknown",))[0]
        print(f"  {status} {family_id}: {name} ({count} witnesses)")


def cmd_protocol(family_filter: str | None = None) -> None:
    """Run the 5-step construction protocol."""
    if family_filter:
        # Run on a specific witness family (e.g. "W1.1")
        witnesses = generate_all_invalid_witnesses()
        matching = [w for w in witnesses if w.family == family_filter]
        if not matching:
            print(f"Unknown witness family: {family_filter}", file=sys.stderr)
            print("Available families:", file=sys.stderr)
            for w in witnesses:
                print(f"  {w.family}: {w.name}", file=sys.stderr)
            sys.exit(1)
        results = [run_protocol(w) for w in matching]
    else:
        results = run_protocol_all()

    print_protocol_report(results)


def cmd_coverage() -> None:
    """Check constraint coverage (Req 13.8)."""
    mapping = ConstraintMapping(WITNESS_CONSTRAINT_MAP)
    report = mapping.coverage_report()

    print("Constraint Coverage Report (Requirement 13.8)")
    print("=" * 60)
    print(f"Total constraints: {report['total_constraints']}")
    print(f"Covered: {report['covered_constraints']}")
    print(f"Coverage: {report['coverage_percentage']}%")
    print()

    print("Per-constraint coverage:")
    for constraint_id, families in sorted(report["per_constraint"].items()):
        if families:
            print(f"  ✓ {constraint_id}: {', '.join(families)}")
        else:
            print(f"  ✗ {constraint_id}: UNCOVERED")

    uncovered = report["uncovered_constraints"]
    if uncovered:
        print(f"\n⚠ {len(uncovered)} uncovered constraint(s):")
        for c in uncovered:
            print(f"  - {c}")
        sys.exit(1)
    else:
        print(f"\n✓ All {report['total_constraints']} constraints covered")


def cmd_mapping() -> None:
    """Show the witness → constraint mapping."""
    print("Witness → Constraint Mapping")
    print("=" * 60)

    for family_id in sorted(WITNESS_CONSTRAINT_MAP.keys()):
        constraints = WITNESS_CONSTRAINT_MAP[family_id]
        print(f"  {family_id} → {', '.join(constraints)}")

    print()
    print("Constraint → Witness Families (reverse)")
    print("-" * 60)
    mapping = ConstraintMapping(WITNESS_CONSTRAINT_MAP)
    for constraint_id in sorted(ALL_CONSTRAINTS):
        families = mapping.get_families_for_constraint(constraint_id)
        if families:
            print(f"  {constraint_id} ← {', '.join(sorted(families))}")
        else:
            print(f"  {constraint_id} ← (none)")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Invalid Witness Generator Suite for VSEL Protocol"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    subparsers.add_parser("list", help="List all invalid witness families")

    gen_parser = subparsers.add_parser("generate", help="Generate invalid witnesses")
    gen_parser.add_argument(
        "family", nargs="?", default=None, help="Family to generate (e.g. W1)"
    )

    subparsers.add_parser("summary", help="Print summary report")

    proto_parser = subparsers.add_parser(
        "protocol", help="Run 5-step construction protocol"
    )
    proto_parser.add_argument(
        "family", nargs="?", default=None,
        help="Witness family to run protocol on (e.g. W1.1)",
    )

    subparsers.add_parser("coverage", help="Check constraint coverage (Req 13.8)")

    subparsers.add_parser("mapping", help="Show witness→constraint mapping")

    args = parser.parse_args()

    if args.command == "list":
        cmd_list()
    elif args.command == "generate":
        cmd_generate(args.family)
    elif args.command == "summary":
        cmd_summary()
    elif args.command == "protocol":
        cmd_protocol(args.family)
    elif args.command == "coverage":
        cmd_coverage()
    elif args.command == "mapping":
        cmd_mapping()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
