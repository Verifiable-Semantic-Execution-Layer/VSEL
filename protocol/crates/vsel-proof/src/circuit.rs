//! CircuitBuilder trait — translates VSEL constraint systems into
//! backend-specific circuit gates.
//!
//! Derived from: ZK_BACKEND_INTEGRATION.md, design.md Component 2,
//! Requirement 1.2.
//!
//! The `CircuitBuilder` trait defines the interface for converting a
//! VSEL `ConstraintSystem` (compiled from SIR/IR by the constraint
//! compiler in `vsel-constraints`) into a backend-specific circuit
//! representation. Each backend (e.g., Plonky3) implements this trait
//! to map algebraic constraint expressions to native gates.
//!
//! # ConstraintExpr → Gate Mapping
//!
//! The following table defines how each `ConstraintExpr` variant from
//! `vsel_constraints::compiler::ConstraintExpr` maps to circuit gates.
//! Every `CircuitBuilder` implementation MUST respect this mapping:
//!
//! | ConstraintExpr variant     | Circuit gate                                    |
//! |----------------------------|-------------------------------------------------|
//! | `Constant(v)`              | Constant wire with value `v`                    |
//! | `BoolConstant(b)`          | Constant wire: `0` for false, `1` for true      |
//! | `WitnessRef(name)`         | Private input wire bound to witness variable     |
//! | `PublicInputRef(name)`     | Public input wire bound to public input variable |
//! | `Eq(a, b)`                 | Equality gate: `a - b = 0`                      |
//! | `Neq(a, b)`               | Non-zero check: `(a - b) * inv(a - b) = 1`      |
//! | `Add(a, b)`               | Arithmetic gate: `a + b = c`                    |
//! | `Sub(a, b)`               | Arithmetic gate: `a - b = c`                    |
//! | `Mul(a, b)`               | Arithmetic gate: `a * b = c`                    |
//! | `And(a, b)`               | Boolean gate: `a * b = c` (both inputs ∈ {0,1}) |
//! | `Or(a, b)`                | Boolean gate: `a + b - a*b = c`                 |
//! | `Lt(a, b)`                | Range proof: `b - a - 1 ∈ [0, 2^n)`             |
//! | `Le(a, b)`                | Range proof: `b - a ∈ [0, 2^n)`                 |
//! | `Gt(a, b)`                | Range proof: `a - b - 1 ∈ [0, 2^n)`             |
//! | `Ge(a, b)`                | Range proof: `a - b ∈ [0, 2^n)`                 |
//! | `IfThenElse(c, t, e)`     | Selector/MUX: `c*t + (1-c)*e = r`               |
//! | `FieldAccess(base, field)`| Wire indirection: resolve `base.field` to wire  |
//!
//! # Design Rationale
//!
//! The trait is generic over associated types so that each backend can
//! define its own circuit, wire assignment, and public wire assignment
//! representations. For example:
//!
//! - **Plonky3Backend** maps to `Plonky3Circuit`, with gates expressed
//!   as AIR constraints over the Goldilocks field.
//! - **HashBackend** uses a no-op circuit builder (hash-based proofs
//!   do not require circuit compilation).
//!
//! The `build_circuit` method is the primary entry point: it receives
//! the full `ConstraintSystem` (constraints, witness variables, public
//! inputs) and produces a backend-native circuit. The `assign_witness`
//! and `assign_public_inputs` methods then populate the circuit wires
//! with concrete values for proof generation.
//!
//! # Invariants
//!
//! - **Faithful translation**: The circuit MUST be a faithful translation
//!   of the algebraic constraints. Evaluating the constraint system
//!   directly and evaluating the circuit must produce the same result
//!   for any witness (Property 4 from design document).
//! - **No silent constraint dropping**: If a `ConstraintExpr` variant
//!   is unsupported by a backend, `build_circuit` MUST return an error
//!   or the implementation must document the limitation. Silent omission
//!   of constraints is a soundness violation.
//! - **Deterministic**: The same `ConstraintSystem` always produces the
//!   same `Circuit`. This is required for reproducible proof generation
//!   and differential testing between backends.

use vsel_constraints::ConstraintSystem;

use crate::public_inputs::PublicInputs;
use crate::witness::Witness;

// ---------------------------------------------------------------------------
// CircuitBuilder — backend-specific circuit compilation trait
// ---------------------------------------------------------------------------

/// Trait for building ZK circuits from VSEL constraint systems.
///
/// Implementors translate the algebraic `ConstraintSystem` (produced by
/// the constraint compiler from SIR/IR) into a backend-native circuit
/// representation. The circuit is then populated with witness and public
/// input values for proof generation.
///
/// # Associated Types
///
/// - `Circuit`: The backend-specific compiled circuit. Contains gate
///   structure, wire topology, and any lookup tables derived from the
///   constraint system. Must be deterministically produced from the
///   same `ConstraintSystem`.
///
/// - `WireAssignment`: Assignment of witness (private) values to circuit
///   wires. Maps each `WitnessRef(name)` in the constraint system to a
///   concrete field element on the corresponding private input wire.
///
/// - `PublicWireAssignment`: Assignment of public input values to circuit
///   wires. Maps each `PublicInputRef(name)` in the constraint system to
///   a concrete field element on the corresponding public input wire.
///
/// # ConstraintExpr → Gate Mapping
///
/// Every implementation MUST map `ConstraintExpr` variants to gates as
/// follows (see module-level documentation for the full table):
///
/// - `Constant(v)` → constant wire with value `v`
/// - `BoolConstant(b)` → constant wire (`0` or `1`)
/// - `WitnessRef(name)` → private input wire
/// - `PublicInputRef(name)` → public input wire
/// - `Eq(a, b)` → equality gate: `a - b = 0`
/// - `Neq(a, b)` → non-zero check: `(a-b) * inv(a-b) = 1`
/// - `Add(a, b)` → arithmetic gate: `a + b = c`
/// - `Sub(a, b)` → arithmetic gate: `a - b = c`
/// - `Mul(a, b)` → arithmetic gate: `a * b = c`
/// - `And(a, b)` → boolean gate: `a * b = c`
/// - `Or(a, b)` → boolean gate: `a + b - a*b = c`
/// - `Lt(a, b)` → range proof: `b - a - 1 ∈ [0, 2^n)`
/// - `IfThenElse(c, t, e)` → selector: `c*t + (1-c)*e = r`
///
/// # Contract
///
/// - **Faithful translation** (Property 4): For any constraint system
///   and witness, evaluating constraints directly must agree with
///   evaluating the compiled circuit with assigned wires.
/// - **Deterministic**: `build_circuit(cs)` always produces the same
///   `Circuit` for the same `ConstraintSystem` `cs`.
/// - **No silent drops**: Unsupported `ConstraintExpr` variants must
///   produce an explicit error, never be silently omitted.
///
/// # Implementors
///
/// - `Plonky3CircuitBuilder`: Production circuit builder mapping to
///   Plonky3 AIR constraints over the Goldilocks field (behind
///   `plonky3-backend` feature flag).
/// - `NoOpCircuitBuilder`: Trivial implementation for `HashBackend`
///   which does not require circuit compilation.
///
/// Requirement 1.2.
pub trait CircuitBuilder {
    /// Backend-specific compiled circuit representation.
    ///
    /// Contains the gate structure, wire topology, and any metadata
    /// derived from the `ConstraintSystem`. Produced deterministically
    /// by `build_circuit`.
    type Circuit;

    /// Wire assignment for witness (private) inputs.
    ///
    /// Maps private input wires in the circuit to concrete values
    /// extracted from the `Witness`. Each `WitnessRef(name)` in the
    /// constraint system corresponds to a private wire that receives
    /// a value from the witness's intermediate states, input sequence,
    /// or auxiliary computation.
    type WireAssignment;

    /// Wire assignment for public inputs.
    ///
    /// Maps public input wires in the circuit to concrete values
    /// extracted from `PublicInputs`. Each `PublicInputRef(name)` in
    /// the constraint system corresponds to a public wire that receives
    /// a value from root_init, root_final, observables, domain, or
    /// version.
    type PublicWireAssignment;

    /// Build a circuit from a VSEL constraint system.
    ///
    /// Translates every `Constraint` in the system into backend-native
    /// gates according to the ConstraintExpr → gate mapping. Also
    /// allocates wires for all witness variables and public inputs
    /// declared in the constraint system.
    ///
    /// # Gate Mapping
    ///
    /// Each `ConstraintExpr` variant maps to a specific gate type:
    ///
    /// - `Constant(v)` → constant wire with value `v`
    /// - `BoolConstant(b)` → constant wire (`0` for false, `1` for true)
    /// - `WitnessRef(name)` → private input wire bound to witness variable `name`
    /// - `PublicInputRef(name)` → public input wire bound to public input `name`
    /// - `Eq(a, b)` → equality gate enforcing `a - b = 0`
    /// - `Neq(a, b)` → non-zero check: introduces auxiliary wire `inv`
    ///   and enforces `(a - b) * inv = 1`
    /// - `Add(a, b)` → arithmetic gate: output wire `c` where `a + b = c`
    /// - `Sub(a, b)` → arithmetic gate: output wire `c` where `a - b = c`
    /// - `Mul(a, b)` → arithmetic gate: output wire `c` where `a * b = c`
    /// - `And(a, b)` → boolean gate: `a * b = c` (inputs constrained to {0, 1})
    /// - `Or(a, b)` → boolean gate: `a + b - a*b = c`
    /// - `Lt(a, b)` → range proof: auxiliary wire `d = b - a - 1`,
    ///   constrained to `d ∈ [0, 2^n)` via bit decomposition
    /// - `Le(a, b)` → range proof: auxiliary wire `d = b - a`,
    ///   constrained to `d ∈ [0, 2^n)`
    /// - `Gt(a, b)` → range proof: auxiliary wire `d = a - b - 1`,
    ///   constrained to `d ∈ [0, 2^n)`
    /// - `Ge(a, b)` → range proof: auxiliary wire `d = a - b`,
    ///   constrained to `d ∈ [0, 2^n)`
    /// - `IfThenElse(c, t, e)` → selector/MUX gate: output wire `r`
    ///   where `c * t + (1 - c) * e = r`, with `c` constrained to {0, 1}
    /// - `FieldAccess(base, field)` → wire indirection resolving
    ///   `base.field` to the appropriate wire in the circuit
    ///
    /// # Arguments
    ///
    /// * `constraints` — The compiled `ConstraintSystem` containing all
    ///   algebraic constraints, witness variable declarations, and public
    ///   input declarations.
    ///
    /// # Returns
    ///
    /// A backend-specific `Circuit` ready for witness and public input
    /// assignment.
    fn build_circuit(&self, constraints: &ConstraintSystem) -> Self::Circuit;

    /// Assign witness values to circuit private input wires.
    ///
    /// Maps each witness variable declared in the constraint system to
    /// a concrete value from the `Witness`:
    ///
    /// - Intermediate states → field elements encoding state data
    /// - Input sequence → field elements encoding input payloads
    /// - Auxiliary computation → field elements for Merkle paths,
    ///   intermediate hashes, etc.
    ///
    /// The assignment must cover every private input wire allocated by
    /// `build_circuit`. Missing assignments indicate a witness that is
    /// incomplete with respect to the constraint system.
    ///
    /// # Arguments
    ///
    /// * `circuit` — The compiled circuit from `build_circuit`.
    /// * `witness` — The execution witness containing intermediate states,
    ///   input sequence, and auxiliary computation data.
    ///
    /// # Returns
    ///
    /// A `WireAssignment` mapping private wires to concrete values.
    fn assign_witness(
        &self,
        circuit: &Self::Circuit,
        witness: &Witness,
    ) -> Self::WireAssignment;

    /// Assign public input values to circuit public wires.
    ///
    /// Maps each public input declared in the constraint system to a
    /// concrete value from `PublicInputs`:
    ///
    /// - `root_init` → field element(s) encoding the initial state commitment
    /// - `root_final` → field element(s) encoding the final state commitment
    /// - `observables` → field elements encoding observable outputs
    /// - `domain` → field element encoding the domain separation tag
    /// - `version` → field element encoding the protocol version
    ///
    /// The assignment must cover every public input wire allocated by
    /// `build_circuit`. Missing assignments indicate public inputs that
    /// are incomplete with respect to the constraint system.
    ///
    /// # Arguments
    ///
    /// * `circuit` — The compiled circuit from `build_circuit`.
    /// * `public_inputs` — The public inputs extracted from the execution
    ///   trace.
    ///
    /// # Returns
    ///
    /// A `PublicWireAssignment` mapping public wires to concrete values.
    fn assign_public_inputs(
        &self,
        circuit: &Self::Circuit,
        public_inputs: &PublicInputs,
    ) -> Self::PublicWireAssignment;
}

// ---------------------------------------------------------------------------
// NoOpCircuitBuilder — trivial implementation for hash-based backends
// ---------------------------------------------------------------------------

/// Trivial circuit builder for backends that do not require circuit
/// compilation (e.g., `HashBackend`).
///
/// All methods return unit types. The hash-based backend generates proofs
/// via SHA3-256 commitments without translating constraints to gates.
/// This implementation exists so that `HashBackend` can satisfy APIs
/// that require a `CircuitBuilder` without introducing dead code.
pub struct NoOpCircuitBuilder;

/// Unit circuit — no gate structure needed for hash-based proofs.
#[derive(Clone, Debug)]
pub struct NoOpCircuit;

/// Unit wire assignment — no private wire values for hash-based proofs.
#[derive(Clone, Debug)]
pub struct NoOpWireAssignment;

/// Unit public wire assignment — no public wire values for hash-based proofs.
#[derive(Clone, Debug)]
pub struct NoOpPublicWireAssignment;

impl CircuitBuilder for NoOpCircuitBuilder {
    type Circuit = NoOpCircuit;
    type WireAssignment = NoOpWireAssignment;
    type PublicWireAssignment = NoOpPublicWireAssignment;

    fn build_circuit(&self, _constraints: &ConstraintSystem) -> Self::Circuit {
        NoOpCircuit
    }

    fn assign_witness(
        &self,
        _circuit: &Self::Circuit,
        _witness: &Witness,
    ) -> Self::WireAssignment {
        NoOpWireAssignment
    }

    fn assign_public_inputs(
        &self,
        _circuit: &Self::Circuit,
        _public_inputs: &PublicInputs,
    ) -> Self::PublicWireAssignment {
        NoOpPublicWireAssignment
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_constraints::compiler::{
        Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, PublicInput,
        WitnessVariable, WitnessVariableKind,
    };

    /// Build a minimal constraint system for testing.
    fn minimal_constraint_system() -> ConstraintSystem {
        let mut cs = ConstraintSystem::new("1.0.0");

        cs.add_witness_variable(WitnessVariable {
            name: "x".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test witness variable".to_string(),
        });

        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state commitment".to_string(),
        });

        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::Constant(42)),
            ),
            category: ConstraintCategory::Structural,
            description: "x = 42".to_string(),
        });

        cs
    }

    #[test]
    fn test_noop_circuit_builder_compiles() {
        let builder = NoOpCircuitBuilder;
        let cs = minimal_constraint_system();

        let circuit = builder.build_circuit(&cs);
        // NoOpCircuit is a unit struct — just verify it was created.
        let _ = circuit.clone();
    }

    #[test]
    fn test_noop_assign_witness() {
        let builder = NoOpCircuitBuilder;
        let cs = minimal_constraint_system();
        let circuit = builder.build_circuit(&cs);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };

        let assignment = builder.assign_witness(&circuit, &witness);
        let _ = assignment.clone();
    }

    #[test]
    fn test_noop_assign_public_inputs() {
        use vsel_core::types::{DomainTag, Hash, ProtocolVersion};

        let builder = NoOpCircuitBuilder;
        let cs = minimal_constraint_system();
        let circuit = builder.build_circuit(&cs);

        let public_inputs = PublicInputs {
            root_init: Hash([1u8; 32]),
            root_final: Hash([2u8; 32]),
            observables: vec![],
            domain: DomainTag(Hash([3u8; 32])),
            version: ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };

        let assignment = builder.assign_public_inputs(&circuit, &public_inputs);
        let _ = assignment.clone();
    }

    #[test]
    fn test_circuit_builder_usable_as_generic_bound() {
        /// Verify the trait works as a generic parameter.
        fn _build_and_assign<B: CircuitBuilder>(
            builder: &B,
            constraints: &ConstraintSystem,
            witness: &Witness,
            public_inputs: &PublicInputs,
        ) -> (B::Circuit, B::WireAssignment, B::PublicWireAssignment) {
            let circuit = builder.build_circuit(constraints);
            let wire_assignment = builder.assign_witness(&circuit, witness);
            let pub_assignment = builder.assign_public_inputs(&circuit, public_inputs);
            (circuit, wire_assignment, pub_assignment)
        }

        let builder = NoOpCircuitBuilder;
        let cs = minimal_constraint_system();
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };
        let public_inputs = PublicInputs {
            root_init: vsel_core::types::Hash([1u8; 32]),
            root_final: vsel_core::types::Hash([2u8; 32]),
            observables: vec![],
            domain: vsel_core::types::DomainTag(vsel_core::types::Hash([3u8; 32])),
            version: vsel_core::types::ProtocolVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        };

        let (circuit, wire, pub_wire) =
            _build_and_assign(&builder, &cs, &witness, &public_inputs);
        let _ = (circuit, wire, pub_wire);
    }

    #[test]
    fn test_noop_builder_with_complex_constraint_system() {
        let mut cs = ConstraintSystem::new("1.0.0");

        // Add multiple witness variables of different kinds.
        cs.add_witness_variable(WitnessVariable {
            name: "state_pre.balance".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "pre-state balance".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "state_post.balance".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "post-state balance".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "transfer_amount".to_string(),
            kind: WitnessVariableKind::Derived,
            description: "derived transfer amount".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "merkle_path".to_string(),
            kind: WitnessVariableKind::Auxiliary,
            description: "Merkle proof path".to_string(),
        });

        // Add multiple public inputs.
        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state root".to_string(),
        });
        cs.add_public_input(PublicInput {
            name: "root_final".to_string(),
            description: "final state root".to_string(),
        });

        // Add constraints covering multiple ConstraintExpr variants.
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::Add(
                    Box::new(ConstraintExpr::WitnessRef(
                        "state_pre.balance".to_string(),
                    )),
                    Box::new(ConstraintExpr::WitnessRef(
                        "transfer_amount".to_string(),
                    )),
                )),
                Box::new(ConstraintExpr::WitnessRef(
                    "state_post.balance".to_string(),
                )),
            ),
            category: ConstraintCategory::Structural,
            description: "balance update: pre + amount = post".to_string(),
        });

        cs.add_constraint(Constraint {
            id: ConstraintId(1),
            expr: ConstraintExpr::Lt(
                Box::new(ConstraintExpr::Constant(0)),
                Box::new(ConstraintExpr::WitnessRef(
                    "transfer_amount".to_string(),
                )),
            ),
            category: ConstraintCategory::Semantic,
            description: "transfer amount must be positive".to_string(),
        });

        cs.add_constraint(Constraint {
            id: ConstraintId(2),
            expr: ConstraintExpr::IfThenElse(
                Box::new(ConstraintExpr::BoolConstant(true)),
                Box::new(ConstraintExpr::WitnessRef(
                    "state_post.balance".to_string(),
                )),
                Box::new(ConstraintExpr::Constant(0)),
            ),
            category: ConstraintCategory::Branch,
            description: "conditional balance check".to_string(),
        });

        let builder = NoOpCircuitBuilder;
        let circuit = builder.build_circuit(&cs);

        // NoOp builder handles any constraint system without error.
        let _ = circuit;
    }
}
