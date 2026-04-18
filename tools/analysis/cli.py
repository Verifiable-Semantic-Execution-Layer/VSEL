#!/usr/bin/env python3
"""
CLI for the Adversarial Constraint Analysis Suite.

Usage:
    python -m tools.analysis.cli static          # Phase 1: Static analysis
    python -m tools.analysis.cli symbolic         # Phase 2: Symbolic analysis
    python -m tools.analysis.cli semantic         # Phase 4: Semantic review
    python -m tools.analysis.cli all              # Run all phases
    python -m tools.analysis.cli summary          # Print summary report
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

from .static_analysis import StaticAnalyzer, build_vsel_model
from .symbolic_analysis import SymbolicAnalyzer
from .semantic_review import SemanticReviewer


def _print_header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def _print_findings(findings: List[str]) -> None:
    if findings:
        print("Findings:")
        for f in findings:
            print(f"  ⚠ {f}")
    else:
        print("  ✓ No findings")


def cmd_static() -> Dict[str, object]:
    """Run Phase 1: Static analysis."""
    _print_header("Phase 1: Static Analysis")

    model = build_vsel_model()
    analyzer = StaticAnalyzer(model)
    report = analyzer.run_all()

    census = report["variable_census"]
    connectivity = report["graph_connectivity"]
    branches = report["branch_coverage"]
    carry_over = report["carry_over"]

    print("Variable Census:")
    print(f"  Total variables:       {census.total_variables}")
    print(f"  Free variables (U1):   {len(census.free_variables)}")
    print(f"  Weakly constrained (U2): {len(census.weakly_constrained)}")
    print(f"  Structural-only (U4):  {len(census.structural_only)}")
    print(f"  Range-cosmetic (U6):   {len(census.range_cosmetic)}")
    print(f"  Public inputs:         {len(census.public_inputs)}")
    print(f"  CONST-1 sound:         {'✓' if census.is_sound else '✗'}")
    print()

    print("Graph Connectivity:")
    print(f"  Nodes:                 {connectivity.total_nodes}")
    print(f"  Edges:                 {connectivity.total_edges}")
    print(f"  Connected components:  {connectivity.connected_components}")
    print(f"  Orphan constraints:    {len(connectivity.orphan_constraints)}")
    print(f"  Isolated variables:    {len(connectivity.isolated_variables)}")
    print(f"  Max degree:            {connectivity.max_degree}")
    print(f"  Avg degree:            {connectivity.avg_degree:.1f}")
    print()

    print("Branch Coverage (CONST-3):")
    print(f"  Total conditionals:    {branches.total_conditionals}")
    print(f"  Covered:               {branches.covered_conditionals}")
    print(f"  Coverage:              {branches.coverage_pct:.1f}%")
    print(f"  Complete:              {'✓' if branches.is_complete else '✗'}")
    print()

    print("Carry-Over Verification (Req 5.8):")
    print(f"  Total fields:          {carry_over.total_fields}")
    print(f"  Total transitions:     {carry_over.total_transitions}")
    print(f"  Expected carry-overs:  {carry_over.expected_carry_overs}")
    print(f"  Actual carry-overs:    {carry_over.actual_carry_overs}")
    print(f"  Complete:              {'✓' if carry_over.is_complete else '✗'}")
    print()

    _print_findings(report["findings"])

    status = "SOUND" if report["is_sound"] else "FINDINGS DETECTED"
    print(f"\nPhase 1 result: {status}")

    return report


def cmd_symbolic() -> Dict[str, object]:
    """Run Phase 2: Symbolic analysis."""
    _print_header("Phase 2: Symbolic Analysis")

    model = build_vsel_model()
    analyzer = SymbolicAnalyzer(model)
    report = analyzer.run_all()

    witnesses = report["alternate_witnesses"]
    dof = report["degree_of_freedom"]
    ranges = report["range_analysis"]

    print("Alternate Witness Search (LEM-6):")
    print(f"  Total variables:       {witnesses.total_variables}")
    print(f"  Unique variables:      {witnesses.unique_variables}")
    print(f"  Potentially non-unique: {len(witnesses.potentially_non_unique)}")
    print(f"  Witness unique:        {'✓' if witnesses.is_unique else '✗'}")
    if witnesses.potentially_non_unique:
        for v in witnesses.potentially_non_unique:
            print(f"    - {v}")
    print()

    print("Degree of Freedom:")
    print(f"  Total variables:       {dof.total_variables}")
    print(f"  Total constraints:     {dof.total_constraints}")
    print(f"  Estimated DoF:         {dof.estimated_dof}")
    print(f"  Fully determined:      {'✓' if dof.is_fully_determined else '✗'}")
    if dof.underdetermined_variables:
        for v in dof.underdetermined_variables:
            print(f"    - {v} (DoF: {dof.per_variable_dof[v]})")
    print()

    print("Range Analysis:")
    print(f"  Unbounded variables:   {len(ranges.unbounded_variables)}")
    print(f"  Cosmetic-range-only:   {len(ranges.cosmetic_range_only)}")
    print(f"  All bounded:           {'✓' if ranges.all_bounded else '✗'}")
    print()

    _print_findings(report["findings"])

    status = "SOUND" if report["is_sound"] else "FINDINGS DETECTED"
    print(f"\nPhase 2 result: {status}")

    return report


def cmd_semantic() -> Dict[str, object]:
    """Run Phase 4: Semantic review."""
    _print_header("Phase 4: Semantic Review")

    model = build_vsel_model()
    reviewer = SemanticReviewer(model)
    report = reviewer.run_all()

    semantics = report["constraint_semantics"]
    coverage = report["property_coverage"]
    mapping = report["constraint_mapping_coverage"]

    print("Constraint Semantic Verification:")
    print(f"  Total constraints:     {semantics.total_constraints}")
    print(f"  Verified:              {semantics.verified_constraints}")
    print(f"  Unknown purpose:       {len(semantics.unknown_purpose)}")
    print(f"  All verified:          {'✓' if semantics.all_verified else '✗'}")
    if semantics.unknown_purpose:
        for u in semantics.unknown_purpose:
            print(f"    - {u}")
    print()

    print("Property Coverage:")
    print(f"  Total properties:      {coverage.total_properties}")
    print(f"  Covered:               {coverage.covered_properties}")
    print(f"  Coverage:              {coverage.coverage_pct:.1f}%")
    print(f"  All covered:           {'✓' if coverage.all_covered else '✗'}")
    if coverage.uncovered_properties:
        for p in coverage.uncovered_properties:
            print(f"    ✗ {p}")
    print()

    print("Proof Obligations:")
    for po, covered in coverage.proof_obligations.items():
        status = "✓" if covered else "✗"
        print(f"  {status} {po}")
    print()

    print("Constraint Mapping Coverage:")
    print(f"  Total constraints:     {mapping['total_constraints']}")
    print(f"  Covered:               {mapping['covered_constraints']}")
    print(f"  Coverage:              {mapping['coverage_percentage']}%")
    uncovered = mapping["uncovered_constraints"]
    if uncovered:
        for c in uncovered:
            print(f"    ✗ {c}")
    print()

    _print_findings(report["findings"])

    status = "SOUND" if report["is_sound"] else "FINDINGS DETECTED"
    print(f"\nPhase 4 result: {status}")

    return report


def cmd_all() -> None:
    """Run all analysis phases."""
    _print_header("VSEL Adversarial Constraint Analysis — All Phases")

    reports = {}
    reports["static"] = cmd_static()
    reports["symbolic"] = cmd_symbolic()
    reports["semantic"] = cmd_semantic()

    _print_header("Combined Results")

    all_sound = all(r["is_sound"] for r in reports.values())
    all_findings: List[str] = []
    for phase_name, report in reports.items():
        for f in report["findings"]:
            all_findings.append(f"[{phase_name}] {f}")

    print(f"Overall sound: {'✓' if all_sound else '✗'}")
    print(f"Total findings: {len(all_findings)}")
    if all_findings:
        print()
        for f in all_findings:
            print(f"  ⚠ {f}")

    if not all_sound:
        sys.exit(1)


def cmd_summary() -> None:
    """Print a compact summary of all phases."""
    _print_header("VSEL Adversarial Constraint Analysis — Summary")

    model = build_vsel_model()

    static = StaticAnalyzer(model).run_all()
    symbolic = SymbolicAnalyzer(model).run_all()
    semantic = SemanticReviewer(model).run_all()

    phases = [
        ("Phase 1: Static", static),
        ("Phase 2: Symbolic", symbolic),
        ("Phase 4: Semantic", semantic),
    ]

    for name, report in phases:
        status = "✓ SOUND" if report["is_sound"] else "✗ FINDINGS"
        finding_count = len(report["findings"])
        print(f"  {status:15s} {name} ({finding_count} finding(s))")

    all_sound = all(r["is_sound"] for _, r in phases)
    total_findings = sum(len(r["findings"]) for _, r in phases)

    print()
    print(f"Overall: {'✓ ALL SOUND' if all_sound else '✗ FINDINGS DETECTED'}")
    print(f"Total findings: {total_findings}")

    if not all_sound:
        sys.exit(1)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Adversarial Constraint Analysis Suite for VSEL Protocol"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    subparsers.add_parser("static", help="Phase 1: Static analysis")
    subparsers.add_parser("symbolic", help="Phase 2: Symbolic analysis")
    subparsers.add_parser("semantic", help="Phase 4: Semantic review")
    subparsers.add_parser("all", help="Run all analysis phases")
    subparsers.add_parser("summary", help="Print summary report")

    args = parser.parse_args()

    if args.command == "static":
        cmd_static()
    elif args.command == "symbolic":
        cmd_symbolic()
    elif args.command == "semantic":
        cmd_semantic()
    elif args.command == "all":
        cmd_all()
    elif args.command == "summary":
        cmd_summary()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
