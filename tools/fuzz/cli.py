#!/usr/bin/env python3
"""
CLI for the Adversarial Fuzzing Suite.

Usage:
    python -m tools.fuzz.cli random              # Generate random invalid traces
    python -m tools.fuzz.cli random --count 20   # Generate 20 random traces
    python -m tools.fuzz.cli u-types             # Generate targeted U-type inputs
    python -m tools.fuzz.cli campaign             # Run full fuzzing campaign
    python -m tools.fuzz.cli summary              # Print summary report
    python -m tools.fuzz.cli full-system          # Run full-system proptest fuzzer
    python -m tools.fuzz.cli full-system --json   # Output JSON report
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

from .adversarial_fuzzer import AdversarialFuzzer, FuzzStrategy, MutationKind
from .full_system_fuzzer import FullSystemFuzzer


def _print_header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def cmd_random(count: int = 10, seed: int = 42) -> None:
    """Generate random invalid traces."""
    _print_header("Phase 3a: Random Invalid Trace Generation")

    fuzzer = AdversarialFuzzer(seed=seed)
    traces = fuzzer.generate_random_traces(count)

    print(f"Generated {len(traces)} random invalid traces:\n")
    for i, trace in enumerate(traces):
        print(f"  [{i}] {trace.original_family}")
        print(f"      Mutation: {trace.mutation_kind.value}")
        print(f"      Description: {trace.description}")
        print(f"      Expected detection: {trace.expected_detection}")
        print()


def cmd_u_types(seed: int = 42) -> None:
    """Generate targeted U-type inputs."""
    _print_header("Phase 3c: Targeted U-Type Input Generation")

    fuzzer = AdversarialFuzzer(seed=seed)
    u_types = fuzzer.generate_u_type_inputs()

    total = sum(len(v) for v in u_types.values())
    print(f"Generated {total} targeted U-type inputs:\n")

    for u_type in sorted(u_types.keys()):
        witnesses = u_types[u_type]
        print(f"  {u_type}: {len(witnesses)} input(s)")
        for w in witnesses:
            print(f"    - {w.description}")
            print(f"      Expected: {w.expected_detection}")
        print()


def cmd_campaign(
    random_count: int = 10,
    mutations_per_witness: int = 3,
    seed: int = 42,
) -> None:
    """Run a full adversarial fuzzing campaign."""
    _print_header("Phase 3: Full Adversarial Fuzzing Campaign")

    fuzzer = AdversarialFuzzer(seed=seed)
    result = fuzzer.run_campaign(
        random_count=random_count,
        mutations_per_witness=mutations_per_witness,
    )

    print(f"Campaign result: {result.summary}\n")

    # Breakdown by mutation kind.
    by_kind: Dict[str, int] = {}
    for m in result.mutations:
        kind = m.mutation_kind.value
        by_kind[kind] = by_kind.get(kind, 0) + 1

    print("Mutations by kind:")
    for kind in sorted(by_kind.keys()):
        print(f"  {kind:25s}: {by_kind[kind]}")
    print()

    # U-type breakdown.
    print("U-type targets:")
    for u_type in sorted(result.targeted_u_types.keys()):
        count = len(result.targeted_u_types[u_type])
        print(f"  {u_type}: {count} input(s)")
    print()

    # Expected detection breakdown.
    by_detection: Dict[str, int] = {}
    for m in result.mutations:
        for det in m.expected_detection.split(", "):
            det = det.strip()
            if det:
                by_detection[det] = by_detection.get(det, 0) + 1

    print("Expected detection coverage:")
    for det in sorted(by_detection.keys()):
        print(f"  {det:30s}: {by_detection[det]} input(s)")


def cmd_summary(seed: int = 42) -> None:
    """Print a compact summary of fuzzing capabilities."""
    _print_header("Adversarial Fuzzing Suite — Summary")

    fuzzer = AdversarialFuzzer(seed=seed)
    result = fuzzer.run_campaign(random_count=5, mutations_per_witness=2)

    print(f"Total generated:  {result.total_generated}")
    print(f"Strategy:         {result.strategy.value}")
    print()

    # U-type coverage.
    print("U-type coverage:")
    for u_type in ["U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8"]:
        count = len(result.targeted_u_types.get(u_type, []))
        status = "✓" if count > 0 else "✗"
        print(f"  {status} {u_type}: {count} input(s)")

    all_covered = all(
        len(result.targeted_u_types.get(f"U{i}", [])) > 0
        for i in range(1, 9)
    )
    print()
    print(f"All U-types covered: {'✓' if all_covered else '✗'}")


def cmd_full_system(
    cases: int = 100,
    timeout: int = 300,
    output_json: bool = False,
) -> int:
    """Run the full-system proptest fuzzer and report results.

    Returns 0 on success, 1 on failure.
    """
    if not output_json:
        _print_header("Full-System Fuzzing (Rust proptest)")

    fuzzer = FullSystemFuzzer(proptest_cases=cases)
    report = fuzzer.run(timeout_secs=timeout)

    if output_json:
        print(report.to_json())
    else:
        fuzzer.print_report(report)

    return 0 if report.all_passed else 1


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Adversarial Fuzzing Suite for VSEL Protocol"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    random_parser = subparsers.add_parser("random", help="Generate random invalid traces")
    random_parser.add_argument(
        "--count", type=int, default=10, help="Number of traces to generate"
    )
    random_parser.add_argument(
        "--seed", type=int, default=42, help="Random seed"
    )

    u_types_parser = subparsers.add_parser("u-types", help="Generate targeted U-type inputs")
    u_types_parser.add_argument(
        "--seed", type=int, default=42, help="Random seed"
    )

    campaign_parser = subparsers.add_parser("campaign", help="Run full fuzzing campaign")
    campaign_parser.add_argument(
        "--random-count", type=int, default=10, help="Number of random traces"
    )
    campaign_parser.add_argument(
        "--mutations", type=int, default=3, help="Mutations per witness"
    )
    campaign_parser.add_argument(
        "--seed", type=int, default=42, help="Random seed"
    )

    subparsers.add_parser("summary", help="Print summary report")

    full_system_parser = subparsers.add_parser(
        "full-system", help="Run full-system proptest fuzzer"
    )
    full_system_parser.add_argument(
        "--cases", type=int, default=100, help="Number of proptest cases per property"
    )
    full_system_parser.add_argument(
        "--timeout", type=int, default=300, help="Timeout in seconds"
    )
    full_system_parser.add_argument(
        "--json", action="store_true", help="Output JSON report"
    )

    args = parser.parse_args()

    if args.command == "random":
        cmd_random(count=args.count, seed=args.seed)
    elif args.command == "u-types":
        cmd_u_types(seed=args.seed)
    elif args.command == "campaign":
        cmd_campaign(
            random_count=args.random_count,
            mutations_per_witness=args.mutations,
            seed=args.seed,
        )
    elif args.command == "summary":
        cmd_summary()
    elif args.command == "full-system":
        exit_code = cmd_full_system(
            cases=args.cases,
            timeout=args.timeout,
            output_json=args.json,
        )
        sys.exit(exit_code)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
