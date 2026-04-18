"""
Invalid witness generators for all eight families (W1-W8).

Each generator class produces minimal invalid witness instances that should
be rejected by the Rust constraint system and invariant checks.

Derived from: INVALID_EXECUTION_WITNESS_SUITE.md, Requirements 13.1, 13.2.
"""

from __future__ import annotations

from typing import List

from .types import (
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


def _account_id(fill: int) -> bytes:
    """Create a 32-byte account ID filled with a single byte value."""
    return bytes([fill]) * 32


def _valid_state(balance: int = 0, seq: int = 1) -> State:
    """Create a minimal valid state for testing."""
    accounts = {}
    if balance > 0:
        accounts[_account_id(1)] = AccountData(balance=balance)
    return State(
        canonical=CanonicalState(
            accounts=accounts,
            system_data=SystemData(total_supply=balance),
        ),
        metadata=TraceMetadata(
            sequence_index=seq,
            previous_commitment=b"\xab" * 32 if seq > 0 else b"\x00" * 32,
        ),
    )


def _deposit_input(account_fill: int, amount: int) -> Input:
    """Create a deposit input."""
    data = _account_id(account_fill) + amount.to_bytes(16, "little")
    return Input(payload_type="deposit", payload_data=data)


class W1StateViolation:
    """W1: State violation generators."""

    @staticmethod
    def negative_balance() -> InvalidWitness:
        """W1.1: total_supply doesn't match sum of balances."""
        state = _valid_state(balance=500, seq=1)
        state.canonical.system_data.total_supply = 999  # Mismatch
        return InvalidWitness(
            family="W1.1",
            name="negative_balance_total_supply_mismatch",
            description="total_supply (999) != sum of balances (500)",
            state=state,
            expected_rejection="G_valid / P_C",
        )

    @staticmethod
    def inconsistent_derived() -> InvalidWitness:
        """W1.2: derived state root doesn't match canonical state."""
        state = _valid_state(balance=1000, seq=1)
        state.derived.state_root = b"\xff" * 32  # Corrupted
        return InvalidWitness(
            family="W1.2",
            name="inconsistent_derived_state_root",
            description="D.state_root is corrupted (0xFF*32), doesn't match Derive(C)",
            state=state,
            expected_rejection="G_commit / P_D",
        )

    @staticmethod
    def invalid_environment() -> InvalidWitness:
        """W1.3: zero domain tag in environment."""
        state = _valid_state(seq=0)
        state.environment.execution_domain = b"\x00" * 32
        return InvalidWitness(
            family="W1.3",
            name="invalid_environment_zero_domain",
            description="Environment execution_domain is the zero hash",
            state=state,
            expected_rejection="G_env / P_E",
        )

    @staticmethod
    def metadata_regression() -> InvalidWitness:
        """W1.4: non-zero commitment at genesis."""
        state = _valid_state(seq=0)
        state.metadata.previous_commitment = b"\xab" * 32  # Non-zero at genesis
        return InvalidWitness(
            family="W1.4",
            name="metadata_regression_nonzero_at_genesis",
            description="Genesis state (seq=0) has non-zero previous_commitment",
            state=state,
            expected_rejection="G_mono / P_τ",
        )

    @staticmethod
    def unreachable_state() -> InvalidWitness:
        """W1.5: state that cannot be produced by apply()."""
        state = _valid_state(balance=1000, seq=2)
        state.canonical.system_data.parameters["rogue_param"] = b"\xde\xad"
        return InvalidWitness(
            family="W1.5",
            name="unreachable_state",
            description="State contains rogue_param not producible by any apply()",
            state=state,
            expected_rejection="L_valid",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W1 invalid witnesses."""
        return [
            cls.negative_balance(),
            cls.inconsistent_derived(),
            cls.invalid_environment(),
            cls.metadata_regression(),
            cls.unreachable_state(),
        ]


class W2TransitionViolation:
    """W2: Transition violation generators."""

    @staticmethod
    def arbitrary_jump() -> InvalidWitness:
        """W2.1: post-state is completely unrelated to pre + input."""
        pre = _valid_state(balance=1000, seq=1)
        post = _valid_state(balance=777, seq=2)
        post.canonical.accounts = {_account_id(99): AccountData(balance=777)}
        post.canonical.system_data.total_supply = 777
        return InvalidWitness(
            family="W2.1",
            name="arbitrary_jump",
            description="Post-state is unrelated to pre-state + input",
            state=pre,
            input=_deposit_input(2, 500),
            post_state=post,
            expected_rejection="L_valid",
        )

    @staticmethod
    def hidden_mutation() -> InvalidWitness:
        """W2.2: noop transition changes canonical state."""
        pre = _valid_state(balance=1000, seq=1)
        post = _valid_state(balance=1000, seq=2)
        post.canonical.system_data.parameters["hidden"] = b"\xff"
        return InvalidWitness(
            family="W2.2",
            name="hidden_mutation_noop",
            description="Noop transition injected hidden parameter change",
            state=pre,
            input=Input(payload_type="unknown_op", payload_data=b"\x01"),
            post_state=post,
            expected_rejection="L_valid",
        )

    @staticmethod
    def resource_creation() -> InvalidWitness:
        """W2.3: balance increases without corresponding total_supply change."""
        pre = _valid_state(balance=1000, seq=1)
        post = _valid_state(balance=1500, seq=2)  # 500 created from nothing
        return InvalidWitness(
            family="W2.3",
            name="resource_creation",
            description="Balance increased by 500 without total_supply update",
            state=pre,
            post_state=post,
            expected_rejection="L_cons",
        )

    @staticmethod
    def resource_destruction() -> InvalidWitness:
        """W2.3b: balance decreases without corresponding total_supply change."""
        pre = _valid_state(balance=1000, seq=1)
        post = _valid_state(balance=0, seq=2)
        post.canonical.accounts = {}
        # total_supply still 1000 but no accounts
        return InvalidWitness(
            family="W2.3",
            name="resource_destruction",
            description="All balance removed but total_supply unchanged",
            state=pre,
            post_state=post,
            expected_rejection="L_cons",
        )

    @staticmethod
    def unauthorized() -> InvalidWitness:
        """W2.4: empty classical signature."""
        return InvalidWitness(
            family="W2.4",
            name="unauthorized_empty_sig",
            description="Input has empty classical_sig",
            input=Input(
                payload_type="deposit",
                payload_data=_account_id(1) + (100).to_bytes(16, "little"),
                auth=Authorization(classical_sig=b""),
            ),
            expected_rejection="MalformedInput",
        )

    @staticmethod
    def precondition_violating() -> InvalidWitness:
        """W2.5: transfer from non-existent account."""
        pre = _valid_state(seq=1)  # No accounts
        sender = _account_id(1)
        receiver = _account_id(2)
        data = sender + receiver + (100).to_bytes(16, "little")
        return InvalidWitness(
            family="W2.5",
            name="precondition_violating_transfer",
            description="Transfer from non-existent sender account",
            state=pre,
            input=Input(payload_type="transfer", payload_data=data),
            expected_rejection="PreconditionViolation",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W2 invalid witnesses."""
        return [
            cls.arbitrary_jump(),
            cls.hidden_mutation(),
            cls.resource_creation(),
            cls.resource_destruction(),
            cls.unauthorized(),
            cls.precondition_violating(),
        ]


class W3TraceStructure:
    """W3: Trace structure violation generators."""

    @staticmethod
    def broken_chain() -> InvalidWitness:
        """W3.1: tampered chain hash in trace entry."""
        entry = TraceEntry(index=1, chain_hash=b"\xde" * 32)
        return InvalidWitness(
            family="W3.1",
            name="broken_chain_hash",
            description="Chain hash tampered to 0xDE*32",
            trace_entries=[entry],
            expected_rejection="verify_trace",
        )

    @staticmethod
    def missing_transition() -> InvalidWitness:
        """W3.2: gap in trace entry indices."""
        e0 = TraceEntry(index=0)
        e2 = TraceEntry(index=2)  # Gap: missing index 1
        return InvalidWitness(
            family="W3.2",
            name="missing_transition",
            description="Trace has gap: indices [0, 2] instead of [0, 1, 2]",
            trace_entries=[e0, e2],
            expected_rejection="verify_trace",
        )

    @staticmethod
    def reordered_entries() -> InvalidWitness:
        """W3.3: trace entries in wrong order."""
        e0 = TraceEntry(index=0)
        e1 = TraceEntry(index=1)
        return InvalidWitness(
            family="W3.3",
            name="reordered_entries",
            description="Trace entries swapped: [1, 0] instead of [0, 1]",
            trace_entries=[e1, e0],  # Swapped
            expected_rejection="verify_trace",
        )

    @staticmethod
    def duplicate_entries() -> InvalidWitness:
        """W3.3b: duplicate trace entries."""
        e0 = TraceEntry(index=0)
        return InvalidWitness(
            family="W3.3",
            name="duplicate_entries",
            description="Trace has duplicate entry at index 0",
            trace_entries=[e0, TraceEntry(index=0)],
            expected_rejection="verify_trace",
        )

    @staticmethod
    def invalid_initial_state() -> InvalidWitness:
        """W3.4: trace starts from wrong initial state."""
        fake_state = _valid_state(balance=777, seq=0)
        return InvalidWitness(
            family="W3.4",
            name="invalid_initial_state",
            description="Trace initial state doesn't match first entry's pre_state_commitment",
            state=fake_state,
            trace_entries=[TraceEntry(index=0)],
            expected_rejection="verify_trace",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W3 invalid witnesses."""
        return [
            cls.broken_chain(),
            cls.missing_transition(),
            cls.reordered_entries(),
            cls.duplicate_entries(),
            cls.invalid_initial_state(),
        ]


class W4ObservableManipulation:
    """W4: Observable manipulation generators."""

    @staticmethod
    def fabricated() -> InvalidWitness:
        """W4.1: observable with fabricated outputs."""
        return InvalidWitness(
            family="W4.1",
            name="fabricated_observable",
            description="Observable contains fabricated_event not derivable from state diff",
            state=_valid_state(balance=1000, seq=1),
            input=_deposit_input(2, 500),
            expected_rejection="obs() re-derivation",
        )

    @staticmethod
    def missing() -> InvalidWitness:
        """W4.2: observable with missing outputs."""
        return InvalidWitness(
            family="W4.2",
            name="missing_observable_outputs",
            description="Observable has empty outputs despite state change",
            state=_valid_state(balance=1000, seq=1),
            input=_deposit_input(2, 500),
            expected_rejection="obs() re-derivation",
        )

    @staticmethod
    def noop_with_non_null() -> InvalidWitness:
        """W4.3: noop transition with non-null observable."""
        return InvalidWitness(
            family="W4.3",
            name="noop_with_non_null_observable",
            description="Noop transition has phantom output events and Success status",
            state=_valid_state(balance=1000, seq=1),
            input=Input(payload_type="unknown_op", payload_data=b"\x01"),
            expected_rejection="obs() re-derivation",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W4 invalid witnesses."""
        return [
            cls.fabricated(),
            cls.missing(),
            cls.noop_with_non_null(),
        ]


class W5AuthorizationManipulation:
    """W5: Authorization manipulation generators."""

    @staticmethod
    def wrong_payload() -> InvalidWitness:
        """W5.1: auth with empty public key component."""
        return InvalidWitness(
            family="W5.1",
            name="wrong_payload_empty_key",
            description="Authorization has empty classical public key",
            input=Input(
                payload_type="deposit",
                payload_data=_account_id(1) + (100).to_bytes(16, "little"),
                auth=Authorization(classical_pubkey=b""),
            ),
            expected_rejection="MalformedInput",
        )

    @staticmethod
    def replayed() -> InvalidWitness:
        """W5.2: replayed authorization with same nonce."""
        auth = Authorization(nonce=42)
        return InvalidWitness(
            family="W5.2",
            name="replayed_authorization",
            description="Two inputs with identical nonce=42 (replay)",
            input=Input(
                payload_type="deposit",
                payload_data=_account_id(1) + (100).to_bytes(16, "little"),
                auth=auth,
            ),
            expected_rejection="trace/proof level replay detection",
        )

    @staticmethod
    def cross_domain() -> InvalidWitness:
        """W5.3: authorization with zero domain tag."""
        return InvalidWitness(
            family="W5.3",
            name="cross_domain_zero",
            description="Authorization domain tag is all zeros",
            input=Input(
                payload_type="deposit",
                payload_data=_account_id(1) + (100).to_bytes(16, "little"),
                auth=Authorization(domain=b"\x00" * 32),
            ),
            expected_rejection="MalformedInput",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W5 invalid witnesses."""
        return [
            cls.wrong_payload(),
            cls.replayed(),
            cls.cross_domain(),
        ]


class W6BatchManipulation:
    """W6: Batch manipulation generators."""

    @staticmethod
    def reordered() -> InvalidWitness:
        """W6.1: batch inputs in wrong order."""
        return InvalidWitness(
            family="W6.1",
            name="reordered_batch",
            description="Batch inputs reversed: transfer before deposit (fails precondition)",
            state=_valid_state(seq=1),
            input=_deposit_input(1, 1000),
            expected_rejection="execute_batch ordering",
        )

    @staticmethod
    def skipping_validation() -> InvalidWitness:
        """W6.2: batch with invalid intermediate input."""
        return InvalidWitness(
            family="W6.2",
            name="skipping_validation",
            description="Batch contains invalid input at position 1 — must halt",
            input=Input(payload_type="", payload_data=b""),
            expected_rejection="MalformedInput (batch halts)",
        )

    @staticmethod
    def phantom_operations() -> InvalidWitness:
        """W6.3: extra operations injected into batch."""
        return InvalidWitness(
            family="W6.3",
            name="phantom_operations",
            description="Extra deposit injected into batch — changes outcome",
            state=_valid_state(seq=1),
            input=_deposit_input(99, 9999),
            expected_rejection="intermediate_results count mismatch",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W6 invalid witnesses."""
        return [
            cls.reordered(),
            cls.skipping_validation(),
            cls.phantom_operations(),
        ]


class W7CommitmentManipulation:
    """W7: Commitment manipulation generators."""

    @staticmethod
    def wrong_state() -> InvalidWitness:
        """W7.1: state commitment doesn't match actual state."""
        entry = TraceEntry(
            index=0,
            pre_state_commitment=b"\xff" * 32,  # Wrong
        )
        return InvalidWitness(
            family="W7.1",
            name="wrong_state_commitment",
            description="pre_state_commitment is 0xFF*32, doesn't match actual state",
            trace_entries=[entry],
            expected_rejection="verify_trace",
        )

    @staticmethod
    def chain_hash() -> InvalidWitness:
        """W7.2: chain hash doesn't follow h_{i+1} = Hash(h_i | Commit(e_i))."""
        entry = TraceEntry(
            index=0,
            chain_hash=b"\xbb" * 32,  # Wrong
        )
        return InvalidWitness(
            family="W7.2",
            name="wrong_chain_hash",
            description="chain_hash is 0xBB*32, doesn't follow commitment chain formula",
            trace_entries=[entry],
            expected_rejection="verify_trace / verify_chain",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W7 invalid witnesses."""
        return [
            cls.wrong_state(),
            cls.chain_hash(),
        ]


class W8CrossSystem:
    """W8: Cross-system violation generators."""

    @staticmethod
    def inconsistent_shared_state() -> InvalidWitness:
        """W8.1: two systems disagree on shared account balance."""
        state_a = _valid_state(balance=1000, seq=1)
        state_b = _valid_state(balance=500, seq=1)
        return InvalidWitness(
            family="W8.1",
            name="inconsistent_shared_state",
            description="System A: balance=1000, System B: balance=500 for same account",
            state=state_a,
            post_state=state_b,
            expected_rejection="CI-2 (shared state consistency)",
        )

    @staticmethod
    def resource_creation() -> InvalidWitness:
        """W8.2: total resources increase across systems."""
        state_a = _valid_state(balance=500, seq=1)
        return InvalidWitness(
            family="W8.2",
            name="cross_system_resource_creation",
            description="System A sends 500, System B receives 600 — 100 created",
            state=state_a,
            expected_rejection="CI-1 (resource conservation)",
        )

    @classmethod
    def all(cls) -> List[InvalidWitness]:
        """Generate all W8 invalid witnesses."""
        return [
            cls.inconsistent_shared_state(),
            cls.resource_creation(),
        ]


def generate_all_invalid_witnesses() -> List[InvalidWitness]:
    """Generate all invalid witnesses across all eight families."""
    witnesses = []
    witnesses.extend(W1StateViolation.all())
    witnesses.extend(W2TransitionViolation.all())
    witnesses.extend(W3TraceStructure.all())
    witnesses.extend(W4ObservableManipulation.all())
    witnesses.extend(W5AuthorizationManipulation.all())
    witnesses.extend(W6BatchManipulation.all())
    witnesses.extend(W7CommitmentManipulation.all())
    witnesses.extend(W8CrossSystem.all())
    return witnesses
