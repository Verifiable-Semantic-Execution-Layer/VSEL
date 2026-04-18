"""
Full-system fuzzing orchestrator — Python orchestration for the VSEL
full-system proptest fuzzer.

Derived from: THREAT_MODEL.md, FORMAL_SPECIFICATION.md.
Requirements: 18.6 (adversarial testing under invalid inputs, edge-case
transitions, adversarial compositions, and worst-case execution scenarios).

This module orchestrates the Rust proptest-based full-system fuzzer:
1. Runs the Rust proptest suite with configurable case counts.
2. Collects and parses test results.
3. Generates a structured report of fuzzing coverage.
4. Supports CI integration with exit codes and JSON output.

The Rust fuzzer (protocol/crates/vsel-invariants/tests/full_system_fuzzing.rs)
exercises:
- All transition classes (Init, Update, Noop, Error, Batch, Reject)
- AX-2 closure, AX-1 determinism, LEM-7 error safety
- Failure recovery after error transitions
- Cascading error resilience (consecutive errors)
- Multi-step trace fuzzing with random input sequences
- Resource conservation (L_cons) across all classes
- Observable determinism (DEF-4)
- Environment immutability
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class FuzzProperty(Enum):
    """Properties verified by the full-system fuzzer."""
    AX2_CLOSURE = "fuzz_ax2_closure_all_states_and_inputs"
    AX1_DETERMINISM = "fuzz_ax1_determinism_all_transitions"
    LEM7_ERROR_SAFETY = "fuzz_lem7_error_states_preserve_invariants"
    ALL_CLASSES_NO_PANICS = "fuzz_all_transition_classes_no_panics"
    FAILURE_RECOVERY = "fuzz_failure_recovery_after_error"
    CASCADING_ERRORS = "fuzz_cascading_error_resilience"
    MULTI_STEP_TRACE = "fuzz_multi_step_trace_all_invariants"
    RESOURCE_CONSERVATION = "fuzz_resource_conservation_all_classes"
    OBSERVABLE_DETERMINISM = "fuzz_observable_determinism"
    ENVIRONMENT_IMMUTABILITY = "fuzz_environment_immutability"


@dataclass
class PropertyResult:
    """Result of a single property test."""
    name: str
    passed: bool
    cases_run: int = 0
    duration_secs: float = 0.0
    failure_message: Optional[str] = None
    counterexample: Optional[str] = None


@dataclass
class FuzzReport:
    """Complete report from a full-system fuzzing run."""
    total_properties: int = 0
    passed_properties: int = 0
    failed_properties: int = 0
    total_cases: int = 0
    total_duration_secs: float = 0.0
    results: List[PropertyResult] = field(default_factory=list)
    rust_exit_code: int = 0
    raw_output: str = ""

    @property
    def all_passed(self) -> bool:
        return self.failed_properties == 0

    @property
    def summary(self) -> str:
        status = "PASS" if self.all_passed else "FAIL"
        return (
            f"[{status}] {self.passed_properties}/{self.total_properties} properties passed, "
            f"{self.total_cases} total cases in {self.total_duration_secs:.1f}s"
        )

    def to_json(self) -> str:
        return json.dumps({
            "status": "pass" if self.all_passed else "fail",
            "total_properties": self.total_properties,
            "passed": self.passed_properties,
            "failed": self.failed_properties,
            "total_cases": self.total_cases,
            "duration_secs": self.total_duration_secs,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "cases_run": r.cases_run,
                    "duration_secs": r.duration_secs,
                    "failure_message": r.failure_message,
                    "counterexample": r.counterexample,
                }
                for r in self.results
            ],
        }, indent=2)


class FullSystemFuzzer:
    """Orchestrates the Rust proptest-based full-system fuzzer.

    Runs the Rust test binary, parses output, and generates structured
    reports for CI integration and audit evidence.
    """

    # The Rust test file containing the proptest-based fuzzer.
    TEST_FILE = "full_system_fuzzing"
    CRATE = "vsel-invariants"
    WORKSPACE = "protocol"

    # All property test function names.
    PROPERTIES = [p.value for p in FuzzProperty]

    def __init__(
        self,
        workspace_root: Optional[str] = None,
        proptest_cases: int = 100,
    ) -> None:
        if workspace_root is None:
            # Assume we're run from the repo root.
            workspace_root = str(Path(__file__).resolve().parent.parent.parent)
        self._root = Path(workspace_root)
        self._proptest_cases = proptest_cases

    def run(self, timeout_secs: int = 300) -> FuzzReport:
        """Run the full-system fuzzer and return a structured report."""
        start = time.monotonic()

        cmd = [
            "cargo", "test",
            "--test", self.TEST_FILE,
            "--",
            "--test-threads=1",
        ]

        env = os.environ.copy()
        env["PROPTEST_CASES"] = str(self._proptest_cases)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self._root / self.WORKSPACE),
                capture_output=True,
                text=True,
                timeout=timeout_secs,
                env=env,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            report = FuzzReport(
                total_duration_secs=elapsed,
                rust_exit_code=-1,
                raw_output=f"Timeout after {timeout_secs}s",
            )
            return report

        elapsed = time.monotonic() - start
        output = result.stdout + "\n" + result.stderr

        report = self._parse_output(output)
        report.total_duration_secs = elapsed
        report.rust_exit_code = result.returncode
        report.raw_output = output

        return report

    def _parse_output(self, output: str) -> FuzzReport:
        """Parse cargo test output into a structured report."""
        report = FuzzReport()

        # Match test result lines: "test <name> ... ok" or "test <name> ... FAILED"
        test_pattern = re.compile(r"test\s+(\S+)\s+\.\.\.\s+(ok|FAILED)")
        found_tests: Dict[str, bool] = {}

        for match in test_pattern.finditer(output):
            test_name = match.group(1)
            passed = match.group(2) == "ok"
            found_tests[test_name] = passed

        # Match the summary line: "test result: ok. X passed; Y failed; ..."
        summary_pattern = re.compile(
            r"test result:\s+\S+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed"
        )
        summary_match = summary_pattern.search(output)

        for prop in self.PROPERTIES:
            passed = found_tests.get(prop, None)
            if passed is None:
                # Test wasn't found in output — might not have run.
                result = PropertyResult(
                    name=prop,
                    passed=False,
                    failure_message="Test not found in output",
                )
            else:
                failure_msg = None
                counterexample = None
                if not passed:
                    # Try to extract failure details.
                    fail_pattern = re.compile(
                        rf"---- {re.escape(prop)} stdout ----\n(.*?)(?=\n---- |\nfailures:)",
                        re.DOTALL,
                    )
                    fail_match = fail_pattern.search(output)
                    if fail_match:
                        failure_msg = fail_match.group(1).strip()[:500]
                        # Extract counterexample if present.
                        ce_pattern = re.compile(
                            r"minimal failing input:\s*(.*?)(?:\n\n|\Z)",
                            re.DOTALL,
                        )
                        ce_match = ce_pattern.search(failure_msg)
                        if ce_match:
                            counterexample = ce_match.group(1).strip()[:200]

                result = PropertyResult(
                    name=prop,
                    passed=passed,
                    failure_message=failure_msg,
                    counterexample=counterexample,
                )

            report.results.append(result)

        report.total_properties = len(report.results)
        report.passed_properties = sum(1 for r in report.results if r.passed)
        report.failed_properties = report.total_properties - report.passed_properties

        if summary_match:
            total_passed = int(summary_match.group(1))
            total_failed = int(summary_match.group(2))
            report.total_cases = total_passed + total_failed

        return report

    def print_report(self, report: FuzzReport) -> None:
        """Print a human-readable report to stdout."""
        print()
        print("=" * 70)
        print("  VSEL Full-System Fuzzing Report")
        print("=" * 70)
        print()
        print(f"  {report.summary}")
        print()

        for result in report.results:
            status = "✓" if result.passed else "✗"
            print(f"  {status} {result.name}")
            if result.failure_message:
                # Print first line of failure message.
                first_line = result.failure_message.split("\n")[0]
                print(f"    → {first_line}")
            if result.counterexample:
                print(f"    Counterexample: {result.counterexample}")

        print()
        print(f"  Exit code: {report.rust_exit_code}")
        print(f"  Duration:  {report.total_duration_secs:.1f}s")
        print()
