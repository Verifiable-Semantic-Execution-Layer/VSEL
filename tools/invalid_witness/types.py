"""
Type definitions for invalid witness generation.

Mirrors the Rust types in vsel-core for Python-side witness construction.
All types use deterministic ordering (sorted dicts) to match Rust BTreeMap behavior.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AccountData:
    """Per-account data — mirrors vsel_core::state::AccountData."""
    balance: int = 0
    nonce: int = 0
    data: bytes = b""


@dataclass
class SystemData:
    """System-wide data — mirrors vsel_core::types::SystemData."""
    protocol_version: tuple[int, int, int] = (0, 1, 0)
    total_supply: int = 0
    parameters: Dict[str, bytes] = field(default_factory=dict)


@dataclass
class CanonicalState:
    """Canonical state — mirrors vsel_core::state::CanonicalState."""
    accounts: Dict[bytes, AccountData] = field(default_factory=dict)
    storage: Dict[bytes, bytes] = field(default_factory=dict)
    system_data: SystemData = field(default_factory=SystemData)


@dataclass
class DerivedState:
    """Derived state — mirrors vsel_core::state::DerivedState."""
    state_root: bytes = b"\x00" * 32
    auxiliary_roots: Dict[str, bytes] = field(default_factory=dict)
    aggregates: Dict[str, int] = field(default_factory=dict)


@dataclass
class Environment:
    """Environment — mirrors vsel_core::state::Environment."""
    timestamp: int = 1_000_000
    block_height: int = 1
    execution_domain: bytes = b"\xab" + b"\x00" * 31


@dataclass
class TraceMetadata:
    """Trace metadata — mirrors vsel_core::state::TraceMetadata."""
    sequence_index: int = 0
    previous_commitment: bytes = b"\x00" * 32
    epoch: int = 0
    timestamp: int = 1_000_000


@dataclass
class State:
    """Full state tuple s = (C, D, E, Ω, τ) — mirrors vsel_core::state::State."""
    canonical: CanonicalState = field(default_factory=CanonicalState)
    derived: DerivedState = field(default_factory=DerivedState)
    environment: Environment = field(default_factory=Environment)
    metadata: TraceMetadata = field(default_factory=TraceMetadata)


@dataclass
class Authorization:
    """Authorization — mirrors vsel_core::input::Authorization."""
    classical_sig: bytes = b"\x01\x02\x03"
    pqc_sig: bytes = b"\x04\x05\x06"
    classical_pubkey: bytes = b"\x0a\x0b"
    pqc_pubkey: bytes = b"\x14\x15"
    nonce: int = 42
    domain: bytes = b"\xab" + b"\x00" * 31


@dataclass
class Input:
    """Input — mirrors vsel_core::input::Input."""
    payload_type: str = "deposit"
    payload_data: bytes = b"\x00" * 48
    auth: Authorization = field(default_factory=Authorization)
    aux_data: bytes = b""


@dataclass
class Observable:
    """Observable — mirrors vsel_core::observable::Observable."""
    transition_class: str = "Update"
    outputs: List[Dict[str, bytes]] = field(default_factory=list)
    gas_used: int = 21_000
    status: str = "Success"


@dataclass
class TraceEntry:
    """Trace entry — mirrors vsel_trace::engine::TraceEntry."""
    index: int = 0
    pre_state_commitment: bytes = b"\x00" * 32
    input: Input = field(default_factory=Input)
    post_state_commitment: bytes = b"\x00" * 32
    observable: Observable = field(default_factory=Observable)
    environment: Environment = field(default_factory=Environment)
    chain_hash: bytes = b"\x00" * 32


@dataclass
class InvalidWitness:
    """An invalid witness instance with metadata about the violation."""
    family: str  # e.g. "W1.1"
    name: str  # Human-readable name
    description: str  # What makes this witness invalid
    state: Optional[State] = None
    input: Optional[Input] = None
    post_state: Optional[State] = None
    trace_entries: Optional[List[TraceEntry]] = None
    expected_rejection: str = ""  # Which check should reject this


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash — matches Rust's sha3::Sha3_256."""
    return hashlib.sha3_256(data).digest()
