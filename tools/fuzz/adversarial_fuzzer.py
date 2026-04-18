"""
Phase 3: Adversarial fuzzing — random invalid trace generation, witness mutation,
targeted U-type inputs.

Derived from: UNDERCONSTRAINT_ANALYSIS.md, INVALID_EXECUTION_WITNESS_SUITE.md.
Requirements: 13.6 (adversarial constraint testing).

Generates adversarial inputs designed to exploit potential underconstraint
vulnerabilities:
- Random invalid traces: randomly generated trace entries with invalid structure.
- Witness mutation: takes valid witnesses and applies targeted mutations.
- Targeted U-type inputs: generates inputs specifically targeting each U-type
  vulnerability class (U1-U8).

The Python fuzzer generates test vectors that can be fed to the Rust constraint
system for validation. The Rust proptest-based fuzzer provides complementary
coverage with property-based testing.
"""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from tools.invalid_witness.types import (
    AccountData,
    Authorization,
    CanonicalState,
    DerivedState,
    Environment,
    Input,
    InvalidWitness,
    Observable,
    State,
    SystemData,
    TraceEntry,
    TraceMetadata,
    sha3_256,
)


# ---------------------------------------------------------------------------
# Mutation kinds
# ---------------------------------------------------------------------------


class MutationKind(Enum):
    """Kind of mutation applied to a witness."""
    # Structural mutations
    FLIP_SIGN = "flip_sign"
    OVERFLOW = "overflow"
    ZERO_OUT = "zero_out"
    MAX_VALUE = "max_value"
    RANDOM_BYTES = "random_bytes"

    # Semantic mutations
    SWAP_FIELDS = "swap_fields"
    DUPLICATE_ENTRY = "duplicate_entry"
    REMOVE_ENTRY = "remove_entry"
    REORDER_ENTRIES = "reorder_entries"

    # Targeted U-type mutations
    FREE_VARIABLE = "free_variable"           # U1
    WEAKEN_CONSTRAINT = "weaken_constraint"   # U2
    SKIP_BRANCH = "skip_branch"               # U3
    STRUCTURAL_ONLY = "structural_only"       # U4
    ORPHAN_CONSTRAINT = "orphan_constraint"   # U5
    RANGE_COSMETIC = "range_cosmetic"         # U6
    TEMPORAL_GAP = "temporal_gap"             # U7
    COMPOSITION_GAP = "composition_gap"       # U8


class FuzzStrategy(Enum):
    """Fuzzing strategy."""
    RANDOM_TRACE = "random_trace"
    WITNESS_MUTATION = "witness_mutation"
    TARGETED_U_TYPE = "targeted_u_type"
    COMBINED = "combined"


# ---------------------------------------------------------------------------
# Fuzz result
# ---------------------------------------------------------------------------


@dataclass
class MutatedWitness:
    """A witness that has been mutated for adversarial testing."""
    original_family: str
    mutation_kind: MutationKind
    description: str
    state: Optional[State] = None
    input: Optional[Input] = None
    post_state: Optional[State] = None
    trace_entries: Optional[List[TraceEntry]] = None
    expected_detection: str = ""


@dataclass
class FuzzResult:
    """Result of a fuzzing campaign."""
    strategy: FuzzStrategy
    total_generated: int = 0
    mutations: List[MutatedWitness] = field(default_factory=list)
    targeted_u_types: Dict[str, List[MutatedWitness]] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        return (
            f"Strategy: {self.strategy.value}, "
            f"Generated: {self.total_generated}, "
            f"U-type targets: {len(self.targeted_u_types)}"
        )


# ---------------------------------------------------------------------------
# Adversarial fuzzer
# ---------------------------------------------------------------------------


class AdversarialFuzzer:
    """Phase 3: Adversarial fuzzer for the VSEL constraint system.

    Generates adversarial inputs using three strategies:
    1. Random invalid traces — randomly generated trace entries.
    2. Witness mutation — targeted mutations of valid witnesses.
    3. Targeted U-type inputs — inputs targeting specific vulnerability classes.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed if seed is not None else 42)

    # -------------------------------------------------------------------
    # Random invalid trace generation
    # -------------------------------------------------------------------

    def generate_random_traces(self, count: int = 10) -> List[MutatedWitness]:
        """Generate random invalid trace entries.

        Creates trace entries with randomly corrupted fields that should
        be rejected by the constraint system.
        """
        results: List[MutatedWitness] = []

        for i in range(count):
            mutation = self._rng.choice([
                MutationKind.FLIP_SIGN,
                MutationKind.OVERFLOW,
                MutationKind.ZERO_OUT,
                MutationKind.MAX_VALUE,
                MutationKind.RANDOM_BYTES,
            ])

            state = self._make_random_state()
            inp = self._make_random_input()
            post_state = self._make_random_state()

            # Apply mutation.
            if mutation == MutationKind.FLIP_SIGN:
                state.canonical.accounts[b"\x01" * 20] = AccountData(
                    balance=-self._rng.randint(1, 100_000)
                )
                desc = "negative balance in canonical state"
                expected = "G_valid, L_cons"
            elif mutation == MutationKind.OVERFLOW:
                state.canonical.accounts[b"\x01" * 20] = AccountData(
                    balance=2**63
                )
                desc = "overflow balance value"
                expected = "G_valid, L_bounded"
            elif mutation == MutationKind.ZERO_OUT:
                state.derived.state_root = b"\x00" * 32
                state.canonical.accounts[b"\x01" * 20] = AccountData(balance=100)
                desc = "zeroed state root with non-empty canonical state"
                expected = "G_commit"
            elif mutation == MutationKind.MAX_VALUE:
                state.canonical.system_data.total_supply = 2**63 - 1
                desc = "max total supply value"
                expected = "G_valid"
            else:  # RANDOM_BYTES
                state.derived.state_root = os.urandom(32)
                desc = "random state root (commitment mismatch)"
                expected = "G_commit"

            results.append(MutatedWitness(
                original_family=f"FUZZ-RAND-{i}",
                mutation_kind=mutation,
                description=desc,
                state=state,
                input=inp,
                post_state=post_state,
                expected_detection=expected,
            ))

        return results

    # -------------------------------------------------------------------
    # Witness mutation
    # -------------------------------------------------------------------

    def mutate_witness(
        self,
        witness: InvalidWitness,
        mutations_per_witness: int = 3,
    ) -> List[MutatedWitness]:
        """Apply targeted mutations to an existing invalid witness.

        Takes a valid or invalid witness and applies structural mutations
        to create new adversarial test vectors.
        """
        results: List[MutatedWitness] = []

        mutation_kinds = [
            MutationKind.FLIP_SIGN,
            MutationKind.SWAP_FIELDS,
            MutationKind.ZERO_OUT,
            MutationKind.RANDOM_BYTES,
            MutationKind.OVERFLOW,
        ]

        for _ in range(mutations_per_witness):
            mutation = self._rng.choice(mutation_kinds)
            mutated = self._apply_mutation(witness, mutation)
            if mutated is not None:
                results.append(mutated)

        return results

    def _apply_mutation(
        self,
        witness: InvalidWitness,
        mutation: MutationKind,
    ) -> Optional[MutatedWitness]:
        """Apply a single mutation to a witness."""
        state = witness.state or State()
        post_state = witness.post_state or State()
        inp = witness.input or Input()

        if mutation == MutationKind.FLIP_SIGN:
            # Flip the sign of a balance.
            for addr, acct in state.canonical.accounts.items():
                mutated_state = State(
                    canonical=CanonicalState(
                        accounts={addr: AccountData(balance=-acct.balance)},
                        storage=state.canonical.storage,
                        system_data=state.canonical.system_data,
                    ),
                    derived=state.derived,
                    environment=state.environment,
                    metadata=state.metadata,
                )
                return MutatedWitness(
                    original_family=witness.family,
                    mutation_kind=mutation,
                    description=f"flipped sign of balance in {witness.family}",
                    state=mutated_state,
                    input=inp,
                    post_state=post_state,
                    expected_detection="G_valid, L_cons",
                )

        elif mutation == MutationKind.SWAP_FIELDS:
            # Swap pre and post state.
            return MutatedWitness(
                original_family=witness.family,
                mutation_kind=mutation,
                description=f"swapped pre/post state in {witness.family}",
                state=post_state,
                input=inp,
                post_state=state,
                expected_detection="L_valid, verify_trace",
            )

        elif mutation == MutationKind.ZERO_OUT:
            # Zero out the state root.
            mutated_state = State(
                canonical=state.canonical,
                derived=DerivedState(state_root=b"\x00" * 32),
                environment=state.environment,
                metadata=state.metadata,
            )
            return MutatedWitness(
                original_family=witness.family,
                mutation_kind=mutation,
                description=f"zeroed state root in {witness.family}",
                state=mutated_state,
                input=inp,
                post_state=post_state,
                expected_detection="G_commit",
            )

        elif mutation == MutationKind.RANDOM_BYTES:
            # Randomize the chain hash in trace entries.
            if witness.trace_entries:
                mutated_entries = []
                for entry in witness.trace_entries:
                    mutated_entry = TraceEntry(
                        index=entry.index,
                        pre_state_commitment=entry.pre_state_commitment,
                        input=entry.input,
                        post_state_commitment=entry.post_state_commitment,
                        observable=entry.observable,
                        environment=entry.environment,
                        chain_hash=os.urandom(32),
                    )
                    mutated_entries.append(mutated_entry)
                return MutatedWitness(
                    original_family=witness.family,
                    mutation_kind=mutation,
                    description=f"randomized chain hashes in {witness.family}",
                    trace_entries=mutated_entries,
                    expected_detection="verify_trace, verify_chain",
                )

        elif mutation == MutationKind.OVERFLOW:
            # Set nonce to max value.
            mutated_state = State(
                canonical=CanonicalState(
                    accounts={
                        b"\x01" * 20: AccountData(nonce=2**63 - 1),
                    },
                    storage=state.canonical.storage,
                    system_data=state.canonical.system_data,
                ),
                derived=state.derived,
                environment=state.environment,
                metadata=state.metadata,
            )
            return MutatedWitness(
                original_family=witness.family,
                mutation_kind=mutation,
                description=f"overflow nonce in {witness.family}",
                state=mutated_state,
                input=inp,
                post_state=post_state,
                expected_detection="G_valid, G_mono",
            )

        return None

    # -------------------------------------------------------------------
    # Targeted U-type input generation
    # -------------------------------------------------------------------

    def generate_u_type_inputs(self) -> Dict[str, List[MutatedWitness]]:
        """Generate inputs targeting each U-type vulnerability class.

        Creates adversarial inputs specifically designed to exploit each
        of the eight underconstraint vulnerability types (U1-U8).
        """
        results: Dict[str, List[MutatedWitness]] = {}

        results["U1"] = self._generate_u1_free_variable()
        results["U2"] = self._generate_u2_weakly_constrained()
        results["U3"] = self._generate_u3_missing_branch()
        results["U4"] = self._generate_u4_structural_only()
        results["U5"] = self._generate_u5_orphan()
        results["U6"] = self._generate_u6_range_cosmetic()
        results["U7"] = self._generate_u7_temporal()
        results["U8"] = self._generate_u8_composition()

        return results

    def _generate_u1_free_variable(self) -> List[MutatedWitness]:
        """U1: Generate inputs exploiting free (unconstrained) variables.

        If a witness variable is not referenced by any constraint, the prover
        can set it to any value. We generate witnesses with adversarial values
        for fields that might be unconstrained.
        """
        results = []

        # Try setting auxiliary data to adversarial values.
        for value_desc, balance in [
            ("negative", -999_999),
            ("overflow", 2**62),
            ("zero", 0),
        ]:
            state = State(
                canonical=CanonicalState(
                    accounts={b"\x01" * 20: AccountData(balance=balance)},
                ),
            )
            results.append(MutatedWitness(
                original_family="U1-FREE",
                mutation_kind=MutationKind.FREE_VARIABLE,
                description=(
                    f"U1: free variable exploit — {value_desc} balance ({balance}) "
                    f"in unconstrained field"
                ),
                state=state,
                expected_detection="G_valid (if constrained), none (if truly free)",
            ))

        return results

    def _generate_u2_weakly_constrained(self) -> List[MutatedWitness]:
        """U2: Generate inputs exploiting weakly constrained variables.

        Variables with only one constraint may have degrees of freedom.
        We generate witnesses that satisfy the single constraint but use
        adversarial values.
        """
        results = []

        # Satisfy a single range constraint but use boundary values.
        for nonce in [0, 1, 2**31 - 1, 2**31]:
            state = State(
                canonical=CanonicalState(
                    accounts={b"\x01" * 20: AccountData(balance=100, nonce=nonce)},
                ),
            )
            results.append(MutatedWitness(
                original_family="U2-WEAK",
                mutation_kind=MutationKind.WEAKEN_CONSTRAINT,
                description=(
                    f"U2: weakly constrained exploit — nonce={nonce} "
                    f"(boundary value for single constraint)"
                ),
                state=state,
                expected_detection="L_valid (if multiple constraints), none (if weak)",
            ))

        return results

    def _generate_u3_missing_branch(self) -> List[MutatedWitness]:
        """U3: Generate inputs targeting missing branch constraints.

        If a conditional in SIR is missing branch constraints, the prover
        can choose either branch freely. We generate inputs that should
        trigger specific branches.
        """
        results = []

        # Generate inputs for both branches of a conditional.
        for amount, desc in [(0, "zero amount (else branch)"), (-1, "negative (else branch)")]:
            inp = Input(
                payload_type="deposit",
                payload_data=amount.to_bytes(8, "big", signed=True),
            )
            results.append(MutatedWitness(
                original_family="U3-BRANCH",
                mutation_kind=MutationKind.SKIP_BRANCH,
                description=f"U3: missing branch exploit — {desc}",
                input=inp,
                expected_detection="PreconditionViolation, CONST-3",
            ))

        return results

    def _generate_u4_structural_only(self) -> List[MutatedWitness]:
        """U4: Generate inputs exploiting structural-only constraints.

        Variables constrained only structurally (no semantic constraints)
        may allow semantically invalid values that are structurally correct.
        """
        results = []

        # Create a state that is structurally valid but semantically wrong.
        state = State(
            canonical=CanonicalState(
                accounts={
                    b"\x01" * 20: AccountData(balance=100, nonce=0),
                    b"\x02" * 20: AccountData(balance=100, nonce=0),
                },
                system_data=SystemData(total_supply=100),  # Should be 200
            ),
        )
        results.append(MutatedWitness(
            original_family="U4-STRUCT",
            mutation_kind=MutationKind.STRUCTURAL_ONLY,
            description=(
                "U4: structural-only exploit — total_supply=100 but sum of "
                "balances=200 (structurally valid, semantically invalid)"
            ),
            state=state,
            expected_detection="L_cons, G_valid",
        ))

        return results

    def _generate_u5_orphan(self) -> List[MutatedWitness]:
        """U5: Generate inputs testing orphan constraint detection.

        Orphan constraints reference no witness variables. We generate
        inputs that should be caught by non-orphan constraints.
        """
        results = []

        # Generate a trace with invalid structure.
        entry = TraceEntry(
            index=0,
            pre_state_commitment=b"\x00" * 32,
            post_state_commitment=b"\xff" * 32,
            chain_hash=b"\x00" * 32,
        )
        results.append(MutatedWitness(
            original_family="U5-ORPHAN",
            mutation_kind=MutationKind.ORPHAN_CONSTRAINT,
            description=(
                "U5: orphan constraint test — trace entry with mismatched "
                "commitments (should be caught by non-orphan constraints)"
            ),
            trace_entries=[entry],
            expected_detection="verify_trace, G_commit",
        ))

        return results

    def _generate_u6_range_cosmetic(self) -> List[MutatedWitness]:
        """U6: Generate inputs exploiting range-cosmetic constraints.

        Variables with only range constraints can be set to any value
        within the range. We generate boundary and adversarial values.
        """
        results = []

        # Test boundary values within valid ranges.
        for balance in [0, 1, 2**32 - 1, 2**32, 2**63 - 1]:
            state = State(
                canonical=CanonicalState(
                    accounts={b"\x01" * 20: AccountData(balance=balance)},
                ),
            )
            results.append(MutatedWitness(
                original_family="U6-RANGE",
                mutation_kind=MutationKind.RANGE_COSMETIC,
                description=(
                    f"U6: range-cosmetic exploit — balance={balance} "
                    f"(within range but potentially adversarial)"
                ),
                state=state,
                expected_detection="L_cons (if equality constrained), none (if range-only)",
            ))

        return results

    def _generate_u7_temporal(self) -> List[MutatedWitness]:
        """U7: Generate inputs exploiting temporal constraint gaps.

        Multi-step traces where temporal invariants might not be enforced
        between steps.
        """
        results = []

        # Generate a trace with time regression.
        entries = [
            TraceEntry(
                index=0,
                pre_state_commitment=sha3_256(b"state0"),
                post_state_commitment=sha3_256(b"state1"),
                environment=Environment(timestamp=1_000_000, block_height=1),
            ),
            TraceEntry(
                index=1,
                pre_state_commitment=sha3_256(b"state1"),
                post_state_commitment=sha3_256(b"state2"),
                environment=Environment(timestamp=999_999, block_height=2),  # Time regression
            ),
        ]
        results.append(MutatedWitness(
            original_family="U7-TEMPORAL",
            mutation_kind=MutationKind.TEMPORAL_GAP,
            description=(
                "U7: temporal gap exploit — time regression between trace steps "
                "(timestamp 1000000 → 999999)"
            ),
            trace_entries=entries,
            expected_detection="T_causal, G_mono",
        ))

        # Generate a trace with sequence gap.
        entries_gap = [
            TraceEntry(index=0),
            TraceEntry(index=2),  # Skipped index 1
        ]
        results.append(MutatedWitness(
            original_family="U7-TEMPORAL",
            mutation_kind=MutationKind.TEMPORAL_GAP,
            description="U7: temporal gap exploit — skipped sequence index (0 → 2)",
            trace_entries=entries_gap,
            expected_detection="T_complete, verify_trace",
        ))

        return results

    def _generate_u8_composition(self) -> List[MutatedWitness]:
        """U8: Generate inputs exploiting composition constraint gaps.

        Cross-system interactions where constraints might not be enforced
        across system boundaries.
        """
        results = []

        # Generate states with inconsistent cross-system data.
        state = State(
            canonical=CanonicalState(
                accounts={
                    b"\x01" * 20: AccountData(balance=1000),
                },
                system_data=SystemData(total_supply=500),  # Inconsistent
            ),
        )
        results.append(MutatedWitness(
            original_family="U8-COMP",
            mutation_kind=MutationKind.COMPOSITION_GAP,
            description=(
                "U8: composition gap exploit — total_supply=500 but account "
                "balance=1000 (cross-system inconsistency)"
            ),
            state=state,
            expected_detection="CI-1, G_valid",
        ))

        return results

    # -------------------------------------------------------------------
    # Combined fuzzing campaign
    # -------------------------------------------------------------------

    def run_campaign(
        self,
        random_count: int = 10,
        mutations_per_witness: int = 3,
    ) -> FuzzResult:
        """Run a complete adversarial fuzzing campaign.

        Combines all three strategies: random traces, witness mutation,
        and targeted U-type inputs.
        """
        result = FuzzResult(strategy=FuzzStrategy.COMBINED)

        # Phase 3a: Random invalid traces.
        random_traces = self.generate_random_traces(random_count)
        result.mutations.extend(random_traces)

        # Phase 3b: Witness mutation (using random traces as base).
        for trace in random_traces[:3]:
            # Convert MutatedWitness to InvalidWitness for mutation.
            base_witness = InvalidWitness(
                family=trace.original_family,
                name=trace.description,
                description=trace.description,
                state=trace.state,
                input=trace.input,
                post_state=trace.post_state,
                trace_entries=trace.trace_entries,
                expected_rejection=trace.expected_detection,
            )
            mutated = self.mutate_witness(base_witness, mutations_per_witness)
            result.mutations.extend(mutated)

        # Phase 3c: Targeted U-type inputs.
        result.targeted_u_types = self.generate_u_type_inputs()
        for u_type, witnesses in result.targeted_u_types.items():
            result.mutations.extend(witnesses)

        result.total_generated = len(result.mutations)

        return result

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _make_random_state(self) -> State:
        """Generate a random state for fuzzing."""
        balance = self._rng.randint(-100_000, 100_000)
        nonce = self._rng.randint(0, 1_000_000)
        return State(
            canonical=CanonicalState(
                accounts={
                    b"\x01" * 20: AccountData(balance=balance, nonce=nonce),
                },
                system_data=SystemData(
                    total_supply=self._rng.randint(0, 1_000_000),
                ),
            ),
            derived=DerivedState(
                state_root=bytes(self._rng.getrandbits(8) for _ in range(32)),
            ),
            environment=Environment(
                timestamp=self._rng.randint(0, 2**32),
                block_height=self._rng.randint(0, 1_000_000),
            ),
            metadata=TraceMetadata(
                sequence_index=self._rng.randint(0, 1_000),
                epoch=self._rng.randint(0, 100),
            ),
        )

    def _make_random_input(self) -> Input:
        """Generate a random input for fuzzing."""
        return Input(
            payload_type=self._rng.choice(["deposit", "withdraw", "transfer", "init"]),
            payload_data=bytes(self._rng.getrandbits(8) for _ in range(48)),
            auth=Authorization(
                classical_sig=bytes(self._rng.getrandbits(8) for _ in range(64)),
                pqc_sig=bytes(self._rng.getrandbits(8) for _ in range(128)),
                nonce=self._rng.randint(0, 1_000_000),
            ),
        )
