# ZK Backend Integration Plan

## Overview

This document defines the interface contract, component boundaries, and migration
path for replacing the current SHA3-256 hash-based proof system with a real
zero-knowledge backend (Plonky3 or Halo2).

The current proof system uses hash commitments as a faithful structural
simulation. All semantic properties (PROOF-1 through PROOF-4) are enforced
at the structural level. The ZK backend replaces the cryptographic layer
while preserving the semantic layer unchanged.

_Remediates: M-003 from ULTRA_ADVERSARIAL_AUDIT.md_

---

## Current Architecture

```
┌─────────────────────────────────────────────────┐
│                  vsel-proof                      │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  Prover  │  │ Verifier │  │   Witness     │  │
│  │          │  │          │  │               │  │
│  │ SHA3-256 │  │ SHA3-256 │  │ Construction  │  │
│  │ commits  │  │ recompute│  │ Classification│  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ PublicInputs │  │ Recursive/Composition    │  │
│  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Components

| Component | File | Role |
|-----------|------|------|
| Prover | `prover.rs` | Generates proof: witness → commitments → proof_data |
| Verifier | `verifier.rs` | 7-step pipeline: domain → structure → commitment → crypto → constraints → semantic → invariant |
| Witness | `witness.rs` | Constructs W = (S_intermediate, Σ_sequence, Aux) from trace |
| PublicInputs | `public_inputs.rs` | Pub = (root_init, root_final, observables, domain, version) |
| Recursive | `recursive.rs` | Proof composition and recursive verification |

---

## Interface Contract for ZK Backend

### Trait: `ZkBackend`

The ZK backend must implement this trait. All other components interact
with the backend exclusively through this interface.

```rust
/// Trait for ZK proof backends (Plonky3, Halo2, etc.)
///
/// The backend receives a witness, constraint system, and public inputs,
/// and produces an opaque proof that can be verified.
pub trait ZkBackend {
    /// Opaque proof type produced by this backend.
    type Proof: Clone + AsRef<[u8]>;

    /// Error type for proof generation failures.
    type Error: std::error::Error;

    /// Generate a ZK proof from witness, constraints, and public inputs.
    ///
    /// The backend must:
    /// 1. Encode the witness into the circuit's private inputs
    /// 2. Encode the public inputs into the circuit's public inputs
    /// 3. Evaluate the constraint system as circuit gates
    /// 4. Generate the cryptographic proof
    ///
    /// Returns opaque proof bytes on success.
    fn prove(
        &self,
        witness: &Witness,
        constraints: &ConstraintSystem,
        public_inputs: &PublicInputs,
    ) -> Result<Self::Proof, Self::Error>;

    /// Verify a ZK proof against public inputs and constraint commitment.
    ///
    /// The backend must:
    /// 1. Deserialize the proof
    /// 2. Verify the proof against the public inputs
    /// 3. Verify the constraint system commitment matches
    ///
    /// Returns true if the proof is valid.
    fn verify(
        &self,
        proof: &Self::Proof,
        public_inputs: &PublicInputs,
        constraint_commitment: &Hash,
    ) -> bool;

    /// Return the backend identifier (e.g., "plonky3", "halo2").
    fn backend_id(&self) -> &str;

    /// Return whether this backend provides post-quantum security.
    fn is_post_quantum(&self) -> bool;
}
```

### Trait: `CircuitBuilder`

Translates the VSEL constraint system into backend-specific circuit gates.

```rust
/// Trait for building ZK circuits from VSEL constraint systems.
pub trait CircuitBuilder {
    /// Backend-specific circuit representation.
    type Circuit;

    /// Build a circuit from a VSEL constraint system.
    ///
    /// Each ConstraintExpr maps to circuit gates:
    /// - BoolConstant → constant gate
    /// - Eq → equality gate
    /// - Add/Sub/Mul → arithmetic gates
    /// - And/Or → boolean gates
    /// - IfThenElse → selector + multiplexer gates
    fn build_circuit(&self, constraints: &ConstraintSystem) -> Self::Circuit;

    /// Assign witness values to circuit wires.
    fn assign_witness(
        &self,
        circuit: &Self::Circuit,
        witness: &Witness,
    ) -> WireAssignment;

    /// Assign public input values to circuit public wires.
    fn assign_public_inputs(
        &self,
        circuit: &Self::Circuit,
        public_inputs: &PublicInputs,
    ) -> PublicWireAssignment;
}
```

---

## Components That Change vs. Remain Stable

### Components That Change

| Component | What Changes | Why |
|-----------|-------------|-----|
| **Prover** (`prover.rs`) | `generate_proof_data()` replaced by `ZkBackend::prove()` | Hash-based proof data replaced by real ZK proof bytes |
| **Prover** (`prover.rs`) | `commit_witness()` may change | Witness commitment scheme may use backend-native commitments |
| **Prover** (`prover.rs`) | `commit_constraints()` may change | Constraint commitment may use backend-native scheme |
| **Verifier** (`verifier.rs`) | `verify_cryptographic()` replaced by `ZkBackend::verify()` | Hash recomputation replaced by ZK proof verification |
| **Verifier** (`verifier.rs`) | Step 4.5 constraint satisfaction may become implicit | ZK proof already proves constraint satisfaction |

### Components That Remain Stable

| Component | Why Stable |
|-----------|-----------|
| **Witness** (`witness.rs`) | Witness structure W = (S, Σ, Aux) is backend-agnostic |
| **PublicInputs** (`public_inputs.rs`) | Pub = (root_init, root_final, observables, domain, version) is backend-agnostic |
| **Constraint System** (`vsel-constraints`) | Algebraic constraints are compiled from SIR, not backend-specific |
| **Recursive** (`recursive.rs`) | Composition logic is structural, not cryptographic |
| **Verifier pipeline** (steps 1-3, 5-7) | Domain, structural, commitment, semantic, invariant checks are backend-agnostic |
| **Proof struct** | `Proof { commitments, proof_data, public_inputs, metadata }` — only `proof_data` contents change |

---

## Migration Path

### Phase 1: Abstraction Layer (Current → Interface)

1. Extract `ZkBackend` trait from `DefaultProver`/`DefaultVerifier`
2. Implement `HashBackend` wrapping current SHA3-256 logic
3. Make `DefaultProver` and `DefaultVerifier` generic over `ZkBackend`
4. All existing tests pass unchanged against `HashBackend`

```rust
// Phase 1: Generic prover
pub struct GenericProver<B: ZkBackend> {
    backend: B,
    version: String,
}

// HashBackend implements ZkBackend using current SHA3-256 logic
pub struct HashBackend;
impl ZkBackend for HashBackend { ... }

// DefaultProver becomes an alias
pub type DefaultProver = GenericProver<HashBackend>;
```

### Phase 2: Circuit Compilation (Constraints → Circuit)

1. Implement `CircuitBuilder` for Plonky3
2. Map each `ConstraintExpr` variant to Plonky3 gates
3. Verify circuit output matches `satisfies_constraints()` for all test traces
4. Differential testing: `HashBackend` vs `Plonky3Backend` on same inputs

### Phase 3: Plonky3 Backend Integration

1. Implement `ZkBackend` for Plonky3
2. `prove()`: witness assignment → circuit evaluation → STARK proof generation
3. `verify()`: STARK proof verification against public inputs
4. Run full test suite against `Plonky3Backend`
5. Verify all property tests (P33-P38) pass with real ZK proofs

### Phase 4: Recursive Proofs

1. Implement recursive proof composition in Plonky3
2. Inner proof verification becomes a circuit within the outer proof
3. Update `recursive.rs` to use backend-native recursion
4. Verify composition properties (THM-10) with real recursive proofs

### Phase 5: Deprecation and Cleanup

1. Mark `HashBackend` as `#[deprecated]`
2. Remove hash-based proof generation from production paths
3. Keep `HashBackend` for testing and development
4. Update documentation and audit evidence

---

## Constraint Expression → Circuit Gate Mapping

| ConstraintExpr | Plonky3 Gate | Notes |
|---------------|-------------|-------|
| `Constant(v)` | Constant wire | Fixed value |
| `BoolConstant(b)` | Constant wire (0 or 1) | Boolean constraint |
| `WitnessRef(name)` | Private input wire | Witness variable |
| `PublicInputRef(name)` | Public input wire | Public input |
| `Eq(a, b)` | `a - b = 0` | Equality gate |
| `Neq(a, b)` | `(a - b) * inv(a - b) = 1` | Non-zero check |
| `Add(a, b)` | `a + b = c` | Addition gate |
| `Sub(a, b)` | `a - b = c` | Subtraction gate |
| `Mul(a, b)` | `a * b = c` | Multiplication gate |
| `And(a, b)` | `a * b = c` (boolean) | Boolean AND |
| `Or(a, b)` | `a + b - a*b = c` | Boolean OR |
| `Lt(a, b)` | Range proof: `b - a - 1 ∈ [0, 2^n)` | Comparison |
| `IfThenElse(c, t, e)` | `c * t + (1-c) * e = r` | Selector/MUX |

---

## Security Considerations

### Post-Quantum Security

- **STARKs (Plonky3)**: Transparent setup, post-quantum secure (T4 horizon)
- **SNARKs (Halo2)**: Trusted setup, NOT post-quantum secure (T2 horizon)
- **Recommendation**: Use Plonky3 STARKs as the primary backend for long-term security
- **Optional**: Halo2 SNARKs for recursion/compression where proof size matters

### Soundness Guarantees

The ZK backend must maintain:
- **Soundness**: Pr[invalid τ accepted] ≤ ε (negligible)
- **Completeness**: ValidTrace(τ) ⟹ ∃ π
- **Knowledge soundness**: Proof implies knowledge of valid witness (PROOF-4)
- **Zero-knowledge**: Proof reveals nothing beyond public inputs

### Migration Security

During migration:
- Both backends run in parallel (dual-proof mode)
- Proofs include backend identifier in metadata
- Verifier accepts proofs from either backend during transition
- After transition period, old backend proofs are rejected

---

## Testing Strategy

### Differential Testing

For every test trace:
1. Generate proof with `HashBackend`
2. Generate proof with `Plonky3Backend`
3. Verify both proofs pass verification
4. Verify public inputs are identical
5. Verify witness commitments are semantically equivalent

### Property Tests

All existing property tests (P33-P38) must pass with the ZK backend:
- P33: Full trace binding (PROOF-1)
- P34: Observable binding (PROOF-2)
- P35: Domain separation (PROOF-3)
- P36: Witness semantic uniqueness (LEM-6)
- P37: Proof composition correctness (THM-10)
- P38: Recursive proof correctness (THM-13)

### Adversarial Tests

All adversarial proof tampering tests must pass:
- Tampered witness rejection
- Wrong constraint system version rejection
- Modified intermediate state rejection
- Altered input rejection

---

## Dependencies

### Plonky3

```toml
[dependencies]
plonky3 = { version = "0.1", features = ["std"] }
```

### Halo2 (Optional)

```toml
[dependencies]
halo2_proofs = { version = "0.3", optional = true }
```

### Feature Flags

```toml
[features]
default = ["hash-backend"]
hash-backend = []
plonky3-backend = ["plonky3"]
halo2-backend = ["halo2_proofs"]
```
