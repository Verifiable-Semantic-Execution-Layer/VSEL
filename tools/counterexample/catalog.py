"""
Counterexample Catalog — formal artifact management for VSEL counterexamples.

Derived from: COUNTEREXAMPLE_CATALOG.md, Requirements 13.4, 14.6.

Each counterexample is preserved as a formal artifact with:
  - ID: Unique identifier (e.g. CEX-S-001)
  - Property violated: Which obligation/invariant this destroys
  - State sequence: Concrete demonstration of the violation
  - Root cause: Why this violation could occur
  - Resolution: How the system prevents it
  - Severity: catastrophic / critical / serious / moderate
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Severity classification per COUNTEREXAMPLE_CATALOG.md."""
    CATASTROPHIC = "catastrophic"
    CRITICAL = "critical"
    SERIOUS = "serious"
    MODERATE = "moderate"


class CounterexampleFamily(Enum):
    """Counterexample family identifiers."""
    CEX_S = "CEX-S"
    CEX_ECON = "CEX-ECON"
    CEX_T = "CEX-T"
    CEX_I = "CEX-I"
    CEX_M = "CEX-M"
    CEX_C = "CEX-C"
    CEX_P = "CEX-P"
    CEX_COMP = "CEX-COMP"
    CEX_TR = "CEX-TR"
    CEX_TEMP = "CEX-TEMP"
    CEX_CRYPTO = "CEX-CRYPTO"


@dataclass
class Counterexample:
    """A single counterexample formal artifact (Requirement 14.6)."""
    id: str
    family: CounterexampleFamily
    property_violated: str
    shape: str
    layer: str
    state_sequence: str
    root_cause: str
    resolution: str
    severity: Severity
    detection_method: str
    rust_test: str = ""
    date_added: str = field(default_factory=lambda: datetime.now().isoformat()[:10])
    status: str = "verified"

    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "family": self.family.value,
            "property_violated": self.property_violated,
            "shape": self.shape,
            "layer": self.layer,
            "state_sequence": self.state_sequence,
            "root_cause": self.root_cause,
            "resolution": self.resolution,
            "severity": self.severity.value,
            "detection_method": self.detection_method,
            "rust_test": self.rust_test,
            "date_added": self.date_added,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "Counterexample":
        """Deserialize from dictionary."""
        return cls(
            id=d["id"],
            family=CounterexampleFamily(d["family"]),
            property_violated=d["property_violated"],
            shape=d["shape"],
            layer=d["layer"],
            state_sequence=d["state_sequence"],
            root_cause=d["root_cause"],
            resolution=d["resolution"],
            severity=Severity(d["severity"]),
            detection_method=d["detection_method"],
            rust_test=d.get("rust_test", ""),
            date_added=d.get("date_added", ""),
            status=d.get("status", "verified"),
        )


class CounterexampleCatalog:
    """Manages the full counterexample catalog as formal artifacts."""

    def __init__(self, entries: Optional[List[Counterexample]] = None):
        self.entries: List[Counterexample] = entries or []

    def add(self, entry: Counterexample) -> None:
        """Add a counterexample to the catalog."""
        if any(e.id == entry.id for e in self.entries):
            raise ValueError(f"Duplicate counterexample ID: {entry.id}")
        self.entries.append(entry)

    def get(self, cex_id: str) -> Optional[Counterexample]:
        """Look up a counterexample by ID."""
        for e in self.entries:
            if e.id == cex_id:
                return e
        return None

    def by_family(self, family: CounterexampleFamily) -> List[Counterexample]:
        """Get all counterexamples in a family."""
        return [e for e in self.entries if e.family == family]

    def by_severity(self, severity: Severity) -> List[Counterexample]:
        """Get all counterexamples of a given severity."""
        return [e for e in self.entries if e.severity == severity]

    def families_present(self) -> List[CounterexampleFamily]:
        """List all families that have at least one entry."""
        seen = set()
        result = []
        for e in self.entries:
            if e.family not in seen:
                seen.add(e.family)
                result.append(e.family)
        return result

    def coverage_report(self) -> Dict:
        """Generate a coverage report across all families."""
        all_families = list(CounterexampleFamily)
        present = set(self.families_present())
        missing = [f for f in all_families if f not in present]
        by_family = {}
        for f in all_families:
            entries = self.by_family(f)
            by_family[f.value] = {
                "count": len(entries),
                "ids": [e.id for e in entries],
                "severities": [e.severity.value for e in entries],
            }
        return {
            "total_entries": len(self.entries),
            "total_families": len(all_families),
            "covered_families": len(present),
            "missing_families": [f.value for f in missing],
            "coverage_percentage": round(
                100 * len(present) / len(all_families), 1
            ) if all_families else 0,
            "by_family": by_family,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize catalog to JSON."""
        return json.dumps(
            [e.to_dict() for e in self.entries],
            indent=indent,
        )

    @classmethod
    def from_json(cls, data: str) -> "CounterexampleCatalog":
        """Deserialize catalog from JSON."""
        entries = [Counterexample.from_dict(d) for d in json.loads(data)]
        return cls(entries)

    def to_markdown(self) -> str:
        """Generate a Markdown report of the catalog."""
        lines = [
            "# Counterexample Catalog Report",
            "",
            f"**Total entries:** {len(self.entries)}",
            f"**Families covered:** {len(self.families_present())}/{len(CounterexampleFamily)}",
            "",
        ]

        for family in CounterexampleFamily:
            entries = self.by_family(family)
            lines.append(f"## {family.value} ({len(entries)} entries)")
            lines.append("")
            if not entries:
                lines.append("_No entries._")
                lines.append("")
                continue
            for e in entries:
                lines.append(f"### {e.id}")
                lines.append(f"- **Property violated:** {e.property_violated}")
                lines.append(f"- **Severity:** {e.severity.value}")
                lines.append(f"- **Layer:** {e.layer}")
                lines.append(f"- **Shape:** {e.shape}")
                lines.append(f"- **Root cause:** {e.root_cause}")
                lines.append(f"- **Resolution:** {e.resolution}")
                lines.append(f"- **Detection:** {e.detection_method}")
                if e.rust_test:
                    lines.append(f"- **Rust test:** `{e.rust_test}`")
                lines.append(f"- **Status:** {e.status}")
                lines.append("")

        return "\n".join(lines)


def build_full_catalog() -> CounterexampleCatalog:
    """Build the complete counterexample catalog with all families.

    Each entry corresponds to a Rust test in
    protocol/crates/vsel-invariants/tests/counterexample_catalog.rs
    """
    catalog = CounterexampleCatalog()

    # -----------------------------------------------------------------------
    # CEX-S: State Space Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-S-001",
        family=CounterexampleFamily.CEX_S,
        property_violated="SAFE-1 (Unreachability of Invalid States)",
        shape="State s where ValidState(s) = true but s not in Reachable(I, T)",
        layer="FSL / EL",
        state_sequence="Construct state satisfying structural predicates but not "
                       "reachable from any initial state via valid transitions.",
        root_cause="State passes ValidState but has no legitimate history.",
        resolution="L_valid rejects transitions producing unreachable post-states; "
                   "Apply(s, sigma) is the only way to produce new states.",
        severity=Severity.CRITICAL,
        detection_method="L_valid check: post == Apply(pre, input)",
        rust_test="cex_s_001_unreachable_state_rejected_by_l_valid",
    ))
    catalog.add(Counterexample(
        id="CEX-S-002",
        family=CounterexampleFamily.CEX_S,
        property_violated="DEF-1 (Derived State Functional Dependence), G_commit",
        shape="State s where D != Derive(C) but Commit(s) passes verification",
        layer="EL / CDL",
        state_sequence="Modify D independently of C. Check if downstream trusts D.",
        root_cause="Derived state trusted without recomputation.",
        resolution="G_commit and valid_state enforce D = Derive(C) at every observation.",
        severity=Severity.CATASTROPHIC,
        detection_method="G_commit: derived.state_root == Hash(Encode(canonical))",
        rust_test="cex_s_002_derived_state_inconsistency",
    ))
    catalog.add(Counterexample(
        id="CEX-S-003",
        family=CounterexampleFamily.CEX_S,
        property_violated="DEF-2 (Canonical Encoding Injectivity)",
        shape="s1 != s2 but Encode(s1) = Encode(s2)",
        layer="EL / CDL",
        state_sequence="Two distinct canonical states must produce distinct commitments.",
        root_cause="Encoding collision collapses distinct states.",
        resolution="Injective encoding with length-prefixed fields and SHA3-256.",
        severity=Severity.CATASTROPHIC,
        detection_method="Property-based testing with random state generation.",
        rust_test="cex_s_003_encoding_injectivity",
    ))
    catalog.add(Counterexample(
        id="CEX-S-004",
        family=CounterexampleFamily.CEX_S,
        property_violated="Economic Admissibility",
        shape="State s where ValidState(s) and G(s) but not EconomicallyValid(s)",
        layer="FSL / EL",
        state_sequence="Single account holds 100% of supply, violating G_concentration.",
        root_cause="Structural validity does not imply economic validity.",
        resolution="Admissible(s) = ValidState(s) AND EconomicallyValid(s).",
        severity=Severity.CRITICAL,
        detection_method="G_concentration check on every state.",
        rust_test="cex_s_004_structurally_valid_economically_absurd",
    ))

    # -----------------------------------------------------------------------
    # CEX-ECON: Economic Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-ECON-001",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="E_cost (Non-Zero Acquisition Cost)",
        shape="Fee rate exceeds 100% (10,000 bps)",
        layer="EL / CDL",
        state_sequence="Set fee_rate_bps to 20,000 (200%).",
        root_cause="Unbounded fee parameters allow absurd fee schedules.",
        resolution="E_cost bounds fee_rate_bps to <= 10,000.",
        severity=Severity.CATASTROPHIC,
        detection_method="E_cost invariant check.",
        rust_test="cex_econ_001_excessive_fee_rate",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-002",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="E_leverage (Bounded Leverage)",
        shape="Entity exposure exceeds max_leverage_bps",
        layer="EL / CDL",
        state_sequence="Inject exposure limit exceeding max leverage.",
        root_cause="Accumulated small position adjustments bypass per-step checks.",
        resolution="E_leverage checks EffectiveLeverage at every state.",
        severity=Severity.CRITICAL,
        detection_method="E_leverage invariant check.",
        rust_test="cex_econ_002_excessive_leverage",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-003",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="G_dust (Bounded Minimum Balance)",
        shape="Account with balance below dust threshold",
        layer="EL",
        state_sequence="Create account with balance 5, dust threshold 100.",
        root_cause="Micro-transactions create state bloat.",
        resolution="G_dust rejects accounts with 0 < balance < dust_threshold.",
        severity=Severity.SERIOUS,
        detection_method="G_dust invariant check.",
        rust_test="cex_econ_003_dust_account",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-004",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="G_solvency",
        shape="Account balances don't sum to total_supply",
        layer="EL",
        state_sequence="Account balance 1000, total_supply 2000.",
        root_cause="Resource creation/destruction without proper accounting.",
        resolution="G_solvency checks sum(balances) == total_supply.",
        severity=Severity.CATASTROPHIC,
        detection_method="G_solvency invariant check.",
        rust_test="cex_econ_004_insolvency",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-005",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="TE_extraction (Bounded Epoch Extraction)",
        shape="Fees collected exceed 10% of total supply in one epoch",
        layer="EL / FSL",
        state_sequence="total_fees_collected = 500, total_supply = 1000.",
        root_cause="Unbounded fee extraction enables value drain.",
        resolution="TE_extraction bounds fees per epoch.",
        severity=Severity.CRITICAL,
        detection_method="TE_extraction invariant check.",
        rust_test="cex_econ_005_excessive_extraction",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-006",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="E_slippage",
        shape="Price oracle contains zero price for an asset pair",
        layer="EL",
        state_sequence="Insert ETH/USD price = 0 in oracle.",
        root_cause="Zero price enables infinite slippage / division by zero.",
        resolution="E_slippage rejects zero prices.",
        severity=Severity.CRITICAL,
        detection_method="E_slippage invariant check.",
        rust_test="cex_econ_006_zero_price_oracle",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-007",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="E_collateral",
        shape="Position collateral ratio below min_collateral_ratio_bps",
        layer="EL / CDL",
        state_sequence="Collateral ratio 5,000 with minimum 15,000.",
        root_cause="Under-collateralized positions create systemic risk.",
        resolution="E_collateral checks all positions against minimum ratio.",
        severity=Severity.CRITICAL,
        detection_method="E_collateral invariant check.",
        rust_test="cex_econ_007_undercollateralized_position",
    ))
    catalog.add(Counterexample(
        id="CEX-ECON-008",
        family=CounterexampleFamily.CEX_ECON,
        property_violated="G_econ_valid",
        shape="Economic parameters with max_leverage_bps = 0",
        layer="EL",
        state_sequence="Set max_leverage_bps to 0.",
        root_cause="Zero max leverage makes all positions invalid.",
        resolution="G_econ_valid rejects zero max leverage.",
        severity=Severity.CRITICAL,
        detection_method="G_econ_valid invariant check.",
        rust_test="cex_econ_008_invalid_economic_params",
    ))

    # -----------------------------------------------------------------------
    # CEX-T: Transition Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-T-001",
        family=CounterexampleFamily.CEX_T,
        property_violated="AX-1 (Determinism of Apply)",
        shape="Apply(s, sigma) producing different results on repeated execution",
        layer="EL",
        state_sequence="Apply same (s, sigma) twice, compare byte-for-byte.",
        root_cause="Hidden randomness or timing dependency.",
        resolution="L_det verifies Apply is deterministic by double-application.",
        severity=Severity.CATASTROPHIC,
        detection_method="L_det invariant check.",
        rust_test="cex_t_001_determinism_verified",
    ))
    catalog.add(Counterexample(
        id="CEX-T-002",
        family=CounterexampleFamily.CEX_T,
        property_violated="AX-2 (Closure of State Space)",
        shape="Apply(s, sigma) producing s' not in S",
        layer="EL",
        state_sequence="Various edge-case inputs; all must produce valid post-states.",
        root_cause="Edge-case inputs pushing state beyond valid ranges.",
        resolution="Apply always returns valid state; L_state checks both pre and post.",
        severity=Severity.CATASTROPHIC,
        detection_method="valid_state check on every Apply result.",
        rust_test="cex_t_002_closure_preserved",
    ))
    catalog.add(Counterexample(
        id="CEX-T-003",
        family=CounterexampleFamily.CEX_T,
        property_violated="SAFE-3 (No Hidden State Mutation)",
        shape="Noop transition where Diff(s, s') not subset of AllowedMutations(sigma)",
        layer="EL",
        state_sequence="Inject hidden parameter mutation into noop result.",
        root_cause="Side effects in noop path.",
        resolution="L_valid rejects any post-state != Apply(pre, input).",
        severity=Severity.CRITICAL,
        detection_method="L_valid invariant check.",
        rust_test="cex_t_003_hidden_mutation_in_noop",
    ))
    catalog.add(Counterexample(
        id="CEX-T-004",
        family=CounterexampleFamily.CEX_T,
        property_violated="Transition Partitioning (Guard Disjointness)",
        shape="(s, sigma) matching multiple transition classes",
        layer="FSL / STATE_MACHINE",
        state_sequence="Various inputs; each must classify to exactly one class.",
        root_cause="Overlapping guard preconditions.",
        resolution="Priority ordering ensures deterministic classification.",
        severity=Severity.CRITICAL,
        detection_method="Deterministic classification verification.",
        rust_test="cex_t_004_guard_disjointness",
    ))
    catalog.add(Counterexample(
        id="CEX-T-005",
        family=CounterexampleFamily.CEX_T,
        property_violated="LEM-7 (Error State Invariant Preservation)",
        shape="Apply(s, sigma_invalid) = s_error where not G(s_error)",
        layer="EL / FSL",
        state_sequence="Invalid input triggers error path; verify invariants hold.",
        root_cause="Error handling path not preserving invariants.",
        resolution="Error paths produce valid states with invariants preserved.",
        severity=Severity.CRITICAL,
        detection_method="G_valid, G_struct checks on error state.",
        rust_test="cex_t_005_error_preserves_invariants",
    ))
    catalog.add(Counterexample(
        id="CEX-T-006",
        family=CounterexampleFamily.CEX_T,
        property_violated="LEM-9 (Batch Decomposition Equivalence)",
        shape="Apply(s, [s1, s2]) != Apply(Apply(s, s1), s2)",
        layer="EL",
        state_sequence="Batch of two deposits vs sequential application.",
        root_cause="Batch processing skipping intermediate validation.",
        resolution="execute_batch applies sequentially with intermediate checks.",
        severity=Severity.CRITICAL,
        detection_method="Differential testing: batch vs sequential.",
        rust_test="cex_t_006_batch_sequential_equivalence",
    ))

    # -----------------------------------------------------------------------
    # CEX-I: Invariant Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-I-001",
        family=CounterexampleFamily.CEX_I,
        property_violated="LEM-1 (Invariant Preservation Under Transition)",
        shape="Transition satisfying local checks but breaking global invariant",
        layer="FSL",
        state_sequence="State with total_supply mismatch (999 vs 1000).",
        root_cause="Per-transition checks insufficient for global properties.",
        resolution="G_struct checks balance sum == total_supply at every state.",
        severity=Severity.CATASTROPHIC,
        detection_method="G_struct invariant check.",
        rust_test="cex_i_001_local_holds_global_breaks",
    ))
    catalog.add(Counterexample(
        id="CEX-I-002",
        family=CounterexampleFamily.CEX_I,
        property_violated="T_cons, T_no_revert",
        shape="Long trace where small per-step deviations accumulate",
        layer="FSL",
        state_sequence="Multi-step trace; verify monotonic metadata at every step.",
        root_cause="Invisible in short traces, manifests over many steps.",
        resolution="Temporal invariants checked over complete traces.",
        severity=Severity.CRITICAL,
        detection_method="Temporal invariant monitoring at every step.",
        rust_test="cex_i_002_temporal_accumulation",
    ))
    catalog.add(Counterexample(
        id="CEX-I-003",
        family=CounterexampleFamily.CEX_I,
        property_violated="Invariant Completeness",
        shape="Execution where all invariants hold but execution is semantically invalid",
        layer="FSL",
        state_sequence="Fake post-state that might pass some invariants but is not Apply(s, sigma).",
        root_cause="Invariant set is incomplete.",
        resolution="L_valid ensures post = Apply(pre, input) as the definitive check.",
        severity=Severity.CATASTROPHIC,
        detection_method="L_valid as definitive semantic check.",
        rust_test="cex_i_003_invariant_completeness",
    ))

    # -----------------------------------------------------------------------
    # CEX-M: Semantic Mapping Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-M-001",
        family=CounterexampleFamily.CEX_M,
        property_violated="THM-4 (Auxiliary Data Exclusion)",
        shape="Two executions with identical (payload, auth) but different aux producing different outcomes",
        layer="EL / SIR",
        state_sequence="Same deposit with different aux data; compare post-states.",
        root_cause="Auxiliary data leaking into semantic outcome.",
        resolution="Apply ignores aux field entirely.",
        severity=Severity.CRITICAL,
        detection_method="Witness independence testing.",
        rust_test="cex_m_001_auxiliary_data_exclusion",
    ))
    catalog.add(Counterexample(
        id="CEX-M-002",
        family=CounterexampleFamily.CEX_M,
        property_violated="DEF-5 (Canonicalization Idempotence)",
        shape="Canonical(Canonical(sigma)) != Canonical(sigma)",
        layer="SIR / EL",
        state_sequence="Apply same input twice; result must be deterministic.",
        root_cause="Canonicalization altering semantic content.",
        resolution="Apply is deterministic regardless of input normalization.",
        severity=Severity.CRITICAL,
        detection_method="Deterministic application testing.",
        rust_test="cex_m_002_canonicalization_idempotence",
    ))
    catalog.add(Counterexample(
        id="CEX-M-003",
        family=CounterexampleFamily.CEX_M,
        property_violated="DEF-4 (Observable Determinism)",
        shape="obs(s, sigma, s') producing different results on repeated calls",
        layer="EL",
        state_sequence="Compute obs twice for same (s, sigma, s'); compare.",
        root_cause="Observable depending on hidden state.",
        resolution="obs is a pure function of (s, sigma, s').",
        severity=Severity.CRITICAL,
        detection_method="Observable determinism testing.",
        rust_test="cex_m_003_observable_determinism",
    ))

    # -----------------------------------------------------------------------
    # CEX-C: Constraint Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-C-001",
        family=CounterexampleFamily.CEX_C,
        property_violated="LEM-4 (Constraint Soundness)",
        shape="Invalid trace satisfying constraints",
        layer="CDL",
        state_sequence="Construct invalid post-state with resource creation; verify rejection.",
        root_cause="Underconstrained variable allowing invalid witness.",
        resolution="L_valid, L_cons, G_struct collectively reject invalid traces.",
        severity=Severity.CATASTROPHIC,
        detection_method="Constraint fuzzing with invalid trace injection.",
        rust_test="cex_c_001_invalid_trace_rejected",
    ))
    catalog.add(Counterexample(
        id="CEX-C-002",
        family=CounterexampleFamily.CEX_C,
        property_violated="LEM-5 (Constraint Completeness)",
        shape="Valid trace failing constraints",
        layer="CDL",
        state_sequence="Valid deposit; verify all invariants pass.",
        root_cause="Overly restrictive constraints rejecting valid executions.",
        resolution="All invariants pass for legitimate Apply(s, sigma) results.",
        severity=Severity.CRITICAL,
        detection_method="Proof generation testing over valid trace corpus.",
        rust_test="cex_c_002_valid_trace_accepted",
    ))
    catalog.add(Counterexample(
        id="CEX-C-003",
        family=CounterexampleFamily.CEX_C,
        property_violated="L_cons (Resource Conservation)",
        shape="Post-state balance sum != total_supply",
        layer="CDL",
        state_sequence="Inject resource creation into post-state.",
        root_cause="Resource creation/destruction without accounting.",
        resolution="L_cons checks balance sum == total_supply in both states.",
        severity=Severity.CRITICAL,
        detection_method="L_cons invariant check.",
        rust_test="cex_c_003_resource_conservation_violation",
    ))

    # -----------------------------------------------------------------------
    # CEX-P: Proof/Verification Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-P-001",
        family=CounterexampleFamily.CEX_P,
        property_violated="PROOF-1 (Full Trace Binding)",
        shape="Proof validating without committing to all intermediate states",
        layer="PL",
        state_sequence="Trace with missing intermediate entry.",
        root_cause="Proof binding only to endpoints, skipping intermediates.",
        resolution="verify_trace checks sequential indices and commitment chain.",
        severity=Severity.CATASTROPHIC,
        detection_method="Commitment structure analysis.",
        rust_test="cex_p_001_partial_trace_rejected",
    ))
    catalog.add(Counterexample(
        id="CEX-P-002",
        family=CounterexampleFamily.CEX_P,
        property_violated="PROOF-3 (Domain Separation)",
        shape="Proof from Domain_A accepted by verifier in Domain_B",
        layer="VL",
        state_sequence="Input with zero domain tag submitted to engine.",
        root_cause="Missing domain tag validation.",
        resolution="Domain tag is part of state and checked by G_env.",
        severity=Severity.CRITICAL,
        detection_method="Cross-domain proof injection testing.",
        rust_test="cex_p_002_cross_domain_rejection",
    ))
    catalog.add(Counterexample(
        id="CEX-P-003",
        family=CounterexampleFamily.CEX_P,
        property_violated="Trace Commitment Integrity",
        shape="Trace with tampered chain hash",
        layer="TE",
        state_sequence="Tamper chain_hash of middle entry.",
        root_cause="Commitment chain not verified end-to-end.",
        resolution="verify_trace validates h_{i+1} = Hash(h_i | Commit(e_i)).",
        severity=Severity.CRITICAL,
        detection_method="Chain verification and mutation testing.",
        rust_test="cex_p_003_tampered_commitment_chain",
    ))

    # -----------------------------------------------------------------------
    # CEX-COMP: Composition Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-COMP-001",
        family=CounterexampleFamily.CEX_COMP,
        property_violated="COMP-3 (Compositional Invariant Preservation)",
        shape="Systems A, B both locally valid but composed state violates G_cross",
        layer="CL",
        state_sequence="Two systems with same account ID but different balances.",
        root_cause="No cross-system invariant enforcement.",
        resolution="Cross-system resource accounting verification.",
        severity=Severity.CATASTROPHIC,
        detection_method="Composition stress testing.",
        rust_test="cex_comp_001_local_valid_global_invalid",
    ))
    catalog.add(Counterexample(
        id="CEX-COMP-002",
        family=CounterexampleFamily.CEX_COMP,
        property_violated="COMP-1 (Cross-System Resource Conservation)",
        shape="Resource consumed in A but still available in B",
        layer="CL",
        state_sequence="System A: 1000->500, System B: 0->600. Total changes.",
        root_cause="No cross-system resource debit/credit synchronization.",
        resolution="CI-1 enforces Total_A + Total_B = constant.",
        severity=Severity.CATASTROPHIC,
        detection_method="Cross-system resource accounting verification.",
        rust_test="cex_comp_002_double_spend",
    ))

    # -----------------------------------------------------------------------
    # CEX-TR: Trace Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-TR-001",
        family=CounterexampleFamily.CEX_TR,
        property_violated="T_complete (No Hidden Transitions)",
        shape="State change with no trace entry recording it",
        layer="TE",
        state_sequence="Remove middle entry from valid trace.",
        root_cause="State mutation outside traced execution pipeline.",
        resolution="verify_trace checks sequential indices and state chain.",
        severity=Severity.CATASTROPHIC,
        detection_method="Trace reconstruction comparison.",
        rust_test="cex_tr_001_missing_transition",
    ))
    catalog.add(Counterexample(
        id="CEX-TR-002",
        family=CounterexampleFamily.CEX_TR,
        property_violated="Trace Commitment Integrity",
        shape="h_{i+1} != Hash(h_i | Commit(e_i))",
        layer="TE",
        state_sequence="Tamper first hash in chain; verify rejection.",
        root_cause="Modified trace entry after commitment.",
        resolution="verify_chain validates incremental hash chain.",
        severity=Severity.CRITICAL,
        detection_method="Chain verification.",
        rust_test="cex_tr_002_commitment_chain_break",
    ))
    catalog.add(Counterexample(
        id="CEX-TR-003",
        family=CounterexampleFamily.CEX_TR,
        property_violated="Trace Determinism",
        shape="Replay(tau) != tau",
        layer="TE / EL",
        state_sequence="Replay from initial state with recorded inputs; compare.",
        root_cause="Environment differences or randomness sources.",
        resolution="Apply is deterministic; replay produces identical trace.",
        severity=Severity.CATASTROPHIC,
        detection_method="Replay testing under controlled environment.",
        rust_test="cex_tr_003_deterministic_replay",
    ))
    catalog.add(Counterexample(
        id="CEX-TR-004",
        family=CounterexampleFamily.CEX_TR,
        property_violated="Trace Sequential Integrity",
        shape="Trace entries swapped out of order",
        layer="TE",
        state_sequence="Swap entries 1 and 2 in valid trace.",
        root_cause="Entries not validated for sequential ordering.",
        resolution="verify_trace checks index ordering and commitment chain.",
        severity=Severity.CRITICAL,
        detection_method="Index ordering verification.",
        rust_test="cex_tr_004_reordered_entries",
    ))

    # -----------------------------------------------------------------------
    # CEX-TEMP: Temporal Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-TEMP-001",
        family=CounterexampleFamily.CEX_TEMP,
        property_violated="Temporal Invariants",
        shape="All invariants hold for first N steps but fail at step N+1",
        layer="FSL",
        state_sequence="Multi-step trace; verify invariants at every step.",
        root_cause="Precision loss, counter overflow, resource drift.",
        resolution="Temporal invariants checked at every step; monotonic metadata.",
        severity=Severity.CRITICAL,
        detection_method="Extended simulation with invariant monitoring.",
        rust_test="cex_temp_001_delayed_invariant_failure",
    ))
    catalog.add(Counterexample(
        id="CEX-TEMP-002",
        family=CounterexampleFamily.CEX_TEMP,
        property_violated="Replay Resistance",
        shape="Valid trace segment resubmitted and accepted as new execution",
        layer="TE / VL",
        state_sequence="Verify all chain hashes in trace are unique.",
        root_cause="Missing nonce/sequence verification.",
        resolution="Trace commitment chain with unique chain hashes prevents replay.",
        severity=Severity.CRITICAL,
        detection_method="Nonce/sequence verification.",
        rust_test="cex_temp_002_replay_resistance",
    ))
    catalog.add(Counterexample(
        id="CEX-TEMP-003",
        family=CounterexampleFamily.CEX_TEMP,
        property_violated="G_mono (Monotonic Metadata)",
        shape="Non-genesis state with zero commitment",
        layer="FSL / EL",
        state_sequence="Set previous_commitment to zero on seq=5 state.",
        root_cause="Metadata regression allowing state reversion.",
        resolution="G_mono checks sequence_index/commitment consistency.",
        severity=Severity.CRITICAL,
        detection_method="G_mono invariant check.",
        rust_test="cex_temp_003_metadata_monotonicity",
    ))

    # -----------------------------------------------------------------------
    # CEX-CRYPTO: Cryptographic Counterexamples
    # -----------------------------------------------------------------------
    catalog.add(Counterexample(
        id="CEX-CRYPTO-001",
        family=CounterexampleFamily.CEX_CRYPTO,
        property_violated="DEF-3, AX-5 (Commitment Collision Resistance)",
        shape="s1 != s2 but Commit(s1) = Commit(s2)",
        layer="All",
        state_sequence="Five distinct canonical states; verify all commitments differ.",
        root_cause="Weak hash function or insufficient domain separation.",
        resolution="SHA3-256 with domain-separated encoding provides collision resistance.",
        severity=Severity.CATASTROPHIC,
        detection_method="Cryptographic analysis and parameter validation.",
        rust_test="cex_crypto_001_commitment_collision_resistance",
    ))
    catalog.add(Counterexample(
        id="CEX-CRYPTO-002",
        family=CounterexampleFamily.CEX_CRYPTO,
        property_violated="Cryptographic Model (Hybrid Signatures)",
        shape="Valid signature on unauthorized input under quantum adversary",
        layer="EL / PL",
        state_sequence="Input with missing classical or PQC signature component.",
        root_cause="Accepting single-component signature bypasses hybrid security.",
        resolution="Engine rejects inputs with empty classical_sig or pqc_sig.",
        severity=Severity.CATASTROPHIC,
        detection_method="Hybrid signature verification.",
        rust_test="cex_crypto_002_hybrid_signature_both_required",
    ))
    catalog.add(Counterexample(
        id="CEX-CRYPTO-003",
        family=CounterexampleFamily.CEX_CRYPTO,
        property_violated="PROOF-3 (Domain Separation)",
        shape="State or input with zero domain tag",
        layer="EL / VL",
        state_sequence="Zero domain tag in state and in auth; verify rejection.",
        root_cause="Missing domain separation enables cross-protocol attacks.",
        resolution="G_env rejects zero domain tag; engine rejects zero domain in auth.",
        severity=Severity.CRITICAL,
        detection_method="Domain separation testing.",
        rust_test="cex_crypto_003_domain_separation",
    ))
    catalog.add(Counterexample(
        id="CEX-CRYPTO-004",
        family=CounterexampleFamily.CEX_CRYPTO,
        property_violated="Incremental Commitment Chaining",
        shape="Chain with tampered intermediate hash",
        layer="TE",
        state_sequence="Three-entry chain; tamper middle hash; verify rejection.",
        root_cause="Chain hash not verified incrementally.",
        resolution="verify_chain validates h_{i+1} = Hash(h_i | Commit(e_i)).",
        severity=Severity.CRITICAL,
        detection_method="Chain verification with mutation testing.",
        rust_test="cex_crypto_004_chain_hash_integrity",
    ))

    return catalog
