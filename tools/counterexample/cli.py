#!/usr/bin/env python3
"""
CLI for the Counterexample Catalog.

Usage:
    python -m tools.counterexample.cli list                # List all families
    python -m tools.counterexample.cli show CEX-S-001      # Show one counterexample
    python -m tools.counterexample.cli family CEX-S        # Show all in a family
    python -m tools.counterexample.cli summary             # Print summary report
    python -m tools.counterexample.cli coverage            # Check family coverage
    python -m tools.counterexample.cli report              # Generate Markdown report
    python -m tools.counterexample.cli json                # Export as JSON
"""

from __future__ import annotations

import argparse
import sys

from .catalog import (
    CounterexampleCatalog,
    CounterexampleFamily,
    Severity,
    build_full_catalog,
)


FAMILY_DESCRIPTIONS = {
    "CEX-S": "State Space",
    "CEX-ECON": "Economic",
    "CEX-T": "Transition",
    "CEX-I": "Invariant",
    "CEX-M": "Semantic Mapping",
    "CEX-C": "Constraint",
    "CEX-P": "Proof/Verification",
    "CEX-COMP": "Composition",
    "CEX-TR": "Trace",
    "CEX-TEMP": "Temporal",
    "CEX-CRYPTO": "Cryptographic",
}


def cmd_list() -> None:
    """List all counterexample families and their entries."""
    catalog = build_full_catalog()
    print("Counterexample Catalog — All Families")
    print("=" * 60)

    for family in CounterexampleFamily:
        entries = catalog.by_family(family)
        desc = FAMILY_DESCRIPTIONS.get(family.value, "Unknown")
        print(f"\n{family.value}: {desc} ({len(entries)} entries)")
        for e in entries:
            print(f"  {e.id}: {e.property_violated}")
            print(f"    Severity: {e.severity.value}")
            if e.rust_test:
                print(f"    Rust test: {e.rust_test}")


def cmd_show(cex_id: str) -> None:
    """Show details of a single counterexample."""
    catalog = build_full_catalog()
    entry = catalog.get(cex_id)
    if entry is None:
        print(f"Unknown counterexample ID: {cex_id}", file=sys.stderr)
        print("Available IDs:", file=sys.stderr)
        for e in catalog.entries:
            print(f"  {e.id}", file=sys.stderr)
        sys.exit(1)

    print(f"Counterexample: {entry.id}")
    print("=" * 60)
    print(f"Family:           {entry.family.value}")
    print(f"Property violated: {entry.property_violated}")
    print(f"Severity:         {entry.severity.value}")
    print(f"Layer:            {entry.layer}")
    print(f"Shape:            {entry.shape}")
    print(f"State sequence:   {entry.state_sequence}")
    print(f"Root cause:       {entry.root_cause}")
    print(f"Resolution:       {entry.resolution}")
    print(f"Detection:        {entry.detection_method}")
    if entry.rust_test:
        print(f"Rust test:        {entry.rust_test}")
    print(f"Status:           {entry.status}")
    print(f"Date added:       {entry.date_added}")


def cmd_family(family_name: str) -> None:
    """Show all counterexamples in a family."""
    try:
        family = CounterexampleFamily(family_name)
    except ValueError:
        print(f"Unknown family: {family_name}", file=sys.stderr)
        print(f"Available: {', '.join(f.value for f in CounterexampleFamily)}", file=sys.stderr)
        sys.exit(1)

    catalog = build_full_catalog()
    entries = catalog.by_family(family)
    desc = FAMILY_DESCRIPTIONS.get(family.value, "Unknown")

    print(f"{family.value}: {desc} ({len(entries)} entries)")
    print("=" * 60)
    for e in entries:
        print(f"\n{e.id}: {e.property_violated}")
        print(f"  Severity:  {e.severity.value}")
        print(f"  Shape:     {e.shape}")
        print(f"  Root cause: {e.root_cause}")
        print(f"  Resolution: {e.resolution}")
        if e.rust_test:
            print(f"  Rust test: {e.rust_test}")


def cmd_summary() -> None:
    """Print a summary report."""
    catalog = build_full_catalog()
    report = catalog.coverage_report()

    print("Counterexample Catalog — Summary Report")
    print("=" * 60)
    print(f"Total entries:     {report['total_entries']}")
    print(f"Families covered:  {report['covered_families']}/{report['total_families']}")
    print(f"Coverage:          {report['coverage_percentage']}%")
    print()

    # Severity breakdown
    for sev in Severity:
        count = len(catalog.by_severity(sev))
        print(f"  {sev.value.capitalize():15s}: {count}")
    print()

    # Per-family breakdown
    print("Per-family coverage:")
    for family in CounterexampleFamily:
        info = report["by_family"][family.value]
        desc = FAMILY_DESCRIPTIONS.get(family.value, "Unknown")
        status = "\u2713" if info["count"] > 0 else "\u2717"
        print(f"  {status} {family.value:12s} {desc:20s} ({info['count']} entries)")

    missing = report["missing_families"]
    if missing:
        print(f"\n\u26a0 Missing families: {', '.join(missing)}")
        sys.exit(1)
    else:
        print(f"\n\u2713 All {report['total_families']} families covered")


def cmd_coverage() -> None:
    """Check family coverage."""
    catalog = build_full_catalog()
    report = catalog.coverage_report()

    print("Counterexample Catalog — Coverage Report")
    print("=" * 60)

    for family in CounterexampleFamily:
        info = report["by_family"][family.value]
        desc = FAMILY_DESCRIPTIONS.get(family.value, "Unknown")
        if info["count"] > 0:
            print(f"  \u2713 {family.value}: {desc} ({info['count']} entries)")
            for cex_id in info["ids"]:
                print(f"      - {cex_id}")
        else:
            print(f"  \u2717 {family.value}: {desc} (MISSING)")

    missing = report["missing_families"]
    if missing:
        print(f"\n\u26a0 {len(missing)} uncovered family/families:")
        for f in missing:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print(f"\n\u2713 All {report['total_families']} families covered "
              f"({report['total_entries']} total entries)")


def cmd_report() -> None:
    """Generate Markdown report."""
    catalog = build_full_catalog()
    print(catalog.to_markdown())


def cmd_json() -> None:
    """Export catalog as JSON."""
    catalog = build_full_catalog()
    print(catalog.to_json())


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Counterexample Catalog for VSEL Protocol"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    subparsers.add_parser("list", help="List all counterexample families")

    show_parser = subparsers.add_parser("show", help="Show one counterexample")
    show_parser.add_argument("id", help="Counterexample ID (e.g. CEX-S-001)")

    family_parser = subparsers.add_parser("family", help="Show all in a family")
    family_parser.add_argument("name", help="Family name (e.g. CEX-S)")

    subparsers.add_parser("summary", help="Print summary report")
    subparsers.add_parser("coverage", help="Check family coverage")
    subparsers.add_parser("report", help="Generate Markdown report")
    subparsers.add_parser("json", help="Export as JSON")

    args = parser.parse_args()

    if args.command == "list":
        cmd_list()
    elif args.command == "show":
        cmd_show(args.id)
    elif args.command == "family":
        cmd_family(args.name)
    elif args.command == "summary":
        cmd_summary()
    elif args.command == "coverage":
        cmd_coverage()
    elif args.command == "report":
        cmd_report()
    elif args.command == "json":
        cmd_json()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
