//! Plonky3CircuitBuilder — translates VSEL constraint systems into
//! Plonky3-native circuit gates over the Goldilocks field.
//!
//! Derived from: ZK_BACKEND_INTEGRATION.md, design.md Component 2,
//! Requirements 2.2, 2.3, 2.9.
//!
//! This module implements the `CircuitBuilder` trait for the Plonky3
//! STARK backend. Each `ConstraintExpr` variant from the VSEL constraint
//! system is mapped to a specific gate type in the Plonky3 circuit:
//!
//! | ConstraintExpr variant     | Plonky3Gate                                     |
//! |----------------------------|-------------------------------------------------|
//! | `Constant(v)`              | `Constant` gate with value `v`                  |
//! | `BoolConstant(b)`          | `Constant` gate: `0` for false, `1` for true    |
//! | `WitnessRef(name)`         | Private input wire bound to witness variable     |
//! | `PublicInputRef(name)`     | Public input wire bound to public input variable |
//! | `Eq(a, b)`                 | `Equality` gate: `a - b = 0`                    |
//! | `Neq(a, b)`               | `Arithmetic(Sub)` + `Arithmetic(Mul)` with inv   |
//! | `Add(a, b)`               | `Arithmetic(Add)` gate                           |
//! | `Sub(a, b)`               | `Arithmetic(Sub)` gate                           |
//! | `Mul(a, b)`               | `Arithmetic(Mul)` gate                           |
//! | `And(a, b)`               | `Boolean` constraints + `Arithmetic(Mul)`        |
//! | `Or(a, b)`                | `Boolean` constraints + OR formula               |
//! | `Lt(a, b)`                | `RangeProof` on `b - a - 1`                     |
//! | `Le(a, b)`                | `RangeProof` on `b - a`                          |
//! | `Gt(a, b)`                | `RangeProof` on `a - b - 1`                     |
//! | `Ge(a, b)`                | `RangeProof` on `a - b`                          |
//! | `IfThenElse(c, t, e)`     | `Selector` gate: `c*t + (1-c)*e = r`            |
//! | `FieldAccess(base, field)`| Wire indirection resolving `base.field`          |
//!
//! # Module Gating
//!
//! This entire module is gated behind `#[cfg(feature = "plonky3-backend")]`.

use std::collections::HashMap;

use vsel_constraints::compiler::ConstraintExpr;
use vsel_constraints::ConstraintSystem;
use vsel_crypto::goldilocks::GoldilocksField;

use crate::circuit::CircuitBuilder;
use crate::plonky3_backend::{Plonky3CircuitBuilder, Plonky3Error};
use crate::public_inputs::PublicInputs;
use crate::witness::Witness;

// ---------------------------------------------------------------------------
// Wire identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a wire in the Plonky3 circuit.
pub type WireId = usize;

// ---------------------------------------------------------------------------
// ArithOp — arithmetic operation type
// ---------------------------------------------------------------------------

/// Arithmetic operation for `Plonky3Gate::Arithmetic`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithOp {
    /// Addition: left + right = output.
    Add,
    /// Subtraction: left - right = output.
    Sub,
    /// Multiplication: left * right = output.
    Mul,
}

// ---------------------------------------------------------------------------
// Plonky3Gate — gate types in the Plonky3 circuit
// ---------------------------------------------------------------------------

/// A single gate in the Plonky3 circuit.
///
/// Each gate corresponds to one or more `ConstraintExpr` variants from
/// the VSEL constraint system. Gates are stored in topological order
/// within `Plonky3Circuit::gates`.
#[derive(Clone, Debug, PartialEq)]
pub enum Plonky3Gate {
    /// Constant gate: output wire holds a fixed field element value.
    ///
    /// Maps from: `ConstraintExpr::Constant(v)`, `ConstraintExpr::BoolConstant(b)`.
    Constant {
        /// Output wire receiving the constant value.
        wire: WireId,
        /// The constant field element value.
        value: GoldilocksField,
    },

    /// Arithmetic gate: left ○ right = output, where ○ ∈ {+, -, *}.
    ///
    /// Maps from: `ConstraintExpr::Add`, `Sub`, `Mul`.
    Arithmetic {
        /// Left operand wire.
        left: WireId,
        /// Right operand wire.
        right: WireId,
        /// Output wire.
        output: WireId,
        /// Arithmetic operation.
        op: ArithOp,
    },

    /// Equality gate: enforces `left - right = 0`.
    ///
    /// Maps from: `ConstraintExpr::Eq(a, b)`.
    Equality {
        /// Left operand wire.
        left: WireId,
        /// Right operand wire.
        right: WireId,
    },

    /// Boolean gate: constrains a wire to {0, 1} by enforcing `w * (1 - w) = 0`.
    ///
    /// Used as a sub-constraint for `And`, `Or`, and `IfThenElse` gates
    /// to ensure boolean inputs.
    Boolean {
        /// Wire constrained to be boolean.
        wire: WireId,
    },

    /// Selector/MUX gate: `condition * then_val + (1 - condition) * else_val = output`.
    ///
    /// Maps from: `ConstraintExpr::IfThenElse(c, t, e)`.
    /// The `condition` wire is additionally constrained to be boolean.
    Selector {
        /// Condition wire (must be boolean: 0 or 1).
        condition: WireId,
        /// Wire selected when condition = 1.
        then_val: WireId,
        /// Wire selected when condition = 0.
        else_val: WireId,
        /// Output wire.
        output: WireId,
    },

    /// Range proof gate: constrains `wire ∈ [0, 2^bits)`.
    ///
    /// Maps from: `ConstraintExpr::Lt`, `Le`, `Gt`, `Ge` via auxiliary
    /// difference wires. For example, `Lt(a, b)` creates an auxiliary
    /// wire `d = b - a - 1` and constrains `d ∈ [0, 2^bits)`.
    RangeProof {
        /// Wire whose value must be in range.
        wire: WireId,
        /// Number of bits for the range bound (value < 2^bits).
        bits: u32,
    },
}

// ---------------------------------------------------------------------------
// WireConnection — inter-gate wiring
// ---------------------------------------------------------------------------

/// A connection between two gates in the circuit.
///
/// Represents the flow of a value from one gate's output wire to
/// another gate's input wire.
#[derive(Clone, Debug, PartialEq)]
pub struct WireConnection {
    /// Source gate index in `Plonky3Circuit::gates`.
    pub from_gate: usize,
    /// Source wire identifier.
    pub from_wire: WireId,
    /// Destination gate index in `Plonky3Circuit::gates`.
    pub to_gate: usize,
    /// Destination wire identifier.
    pub to_wire: WireId,
}

// ---------------------------------------------------------------------------
// Plonky3Circuit — compiled circuit representation
// ---------------------------------------------------------------------------

/// A compiled circuit ready for Plonky3 STARK proof generation.
///
/// Contains the gate structure, wire topology, and metadata derived
/// from the VSEL constraint system. Produced deterministically by
/// `Plonky3CircuitBuilder::build_circuit`.
///
/// Design document: Data Models → Plonky3 Circuit Representation.
#[derive(Clone, Debug)]
pub struct Plonky3Circuit {
    /// Number of private input wires (witness variables).
    pub num_private_inputs: usize,
    /// Number of public input wires.
    pub num_public_inputs: usize,
    /// Gate list in topological order.
    pub gates: Vec<Plonky3Gate>,
    /// Wire connections between gates.
    pub wiring: Vec<WireConnection>,
    /// Constraint system version for binding.
    pub constraint_version: String,
    /// Map from witness variable names to their wire IDs.
    pub witness_wire_map: HashMap<String, WireId>,
    /// Map from public input names to their wire IDs.
    pub public_input_wire_map: HashMap<String, WireId>,
}

// ---------------------------------------------------------------------------
// Plonky3WireAssignment — witness wire values
// ---------------------------------------------------------------------------

/// Assignment of witness (private) values to circuit wires.
///
/// Maps each private input wire in the circuit to a concrete
/// `GoldilocksField` element extracted from the `Witness`.
#[derive(Clone, Debug)]
pub struct Plonky3WireAssignment {
    /// Map from wire ID to field element value.
    pub assignments: HashMap<WireId, GoldilocksField>,
}

// ---------------------------------------------------------------------------
// Plonky3PublicWireAssignment — public input wire values
// ---------------------------------------------------------------------------

/// Assignment of public input values to circuit wires.
///
/// Maps each public input wire in the circuit to a concrete
/// `GoldilocksField` element extracted from `PublicInputs`.
#[derive(Clone, Debug)]
pub struct Plonky3PublicWireAssignment {
    /// Map from wire ID to field element value.
    pub assignments: HashMap<WireId, GoldilocksField>,
}

// ---------------------------------------------------------------------------
// CircuitCompilationContext — internal state during circuit building
// ---------------------------------------------------------------------------

/// Internal context used during circuit compilation.
///
/// Tracks wire allocation and name-to-wire mappings as the constraint
/// system is translated into gates.
struct CircuitCompilationContext {
    /// Next available wire ID.
    next_wire: WireId,
    /// All gates accumulated during compilation.
    gates: Vec<Plonky3Gate>,
    /// All wire connections accumulated during compilation.
    wiring: Vec<WireConnection>,
    /// Map from witness variable names to wire IDs.
    witness_wires: HashMap<String, WireId>,
    /// Map from public input names to wire IDs.
    public_input_wires: HashMap<String, WireId>,
    /// Errors encountered during compilation.
    errors: Vec<Plonky3Error>,
    /// Default range proof bit width for comparison gates.
    range_proof_bits: u32,
}

impl CircuitCompilationContext {
    /// Create a new compilation context.
    fn new() -> Self {
        Self {
            next_wire: 0,
            gates: Vec::new(),
            wiring: Vec::new(),
            witness_wires: HashMap::new(),
            public_input_wires: HashMap::new(),
            errors: Vec::new(),
            // Default to 64-bit range proofs (Goldilocks field width).
            range_proof_bits: 64,
        }
    }

    /// Allocate a fresh wire ID.
    fn alloc_wire(&mut self) -> WireId {
        let wire = self.next_wire;
        self.next_wire += 1;
        wire
    }

    /// Get or allocate a wire for a witness variable.
    fn witness_wire(&mut self, name: &str) -> WireId {
        if let Some(&wire) = self.witness_wires.get(name) {
            wire
        } else {
            let wire = self.alloc_wire();
            self.witness_wires.insert(name.to_string(), wire);
            wire
        }
    }

    /// Get or allocate a wire for a public input.
    fn public_input_wire(&mut self, name: &str) -> WireId {
        if let Some(&wire) = self.public_input_wires.get(name) {
            wire
        } else {
            let wire = self.alloc_wire();
            self.public_input_wires.insert(name.to_string(), wire);
            wire
        }
    }

    /// Add a gate and return its index in the gate list.
    fn add_gate(&mut self, gate: Plonky3Gate) -> usize {
        let idx = self.gates.len();
        self.gates.push(gate);
        idx
    }

    /// Record an unsupported expression error (Req 2.9).
    ///
    /// Called when a `ConstraintExpr` variant cannot be mapped to a
    /// Plonky3 gate. Currently all variants are supported, but this
    /// method is retained for forward compatibility when new variants
    /// are added to the constraint language.
    #[allow(dead_code)]
    fn record_unsupported(&mut self, description: &str) {
        self.errors.push(Plonky3Error::UnsupportedGate(
            description.to_string(),
        ));
    }

    /// Compile a single `ConstraintExpr` into gates, returning the
    /// output wire ID for the expression's result.
    ///
    /// This is the core recursive translation from algebraic constraint
    /// expressions to Plonky3 circuit gates.
    fn compile_expr(&mut self, expr: &ConstraintExpr) -> WireId {
        match expr {
            // ----- Leaf nodes -----

            ConstraintExpr::Constant(v) => {
                let wire = self.alloc_wire();
                // Reduce the constant to a Goldilocks field element.
                let field_val = if *v >= 0 {
                    GoldilocksField(*v as u64 % GoldilocksField::MODULUS)
                } else {
                    // Negative constant: compute p - |v| mod p.
                    let abs_val = v.unsigned_abs() % GoldilocksField::MODULUS;
                    if abs_val == 0 {
                        GoldilocksField::ZERO
                    } else {
                        GoldilocksField(GoldilocksField::MODULUS - abs_val)
                    }
                };
                self.add_gate(Plonky3Gate::Constant { wire, value: field_val });
                wire
            }

            ConstraintExpr::BoolConstant(b) => {
                let wire = self.alloc_wire();
                let value = if *b {
                    GoldilocksField::ONE
                } else {
                    GoldilocksField::ZERO
                };
                self.add_gate(Plonky3Gate::Constant { wire, value });
                wire
            }

            ConstraintExpr::WitnessRef(name) => {
                self.witness_wire(name)
            }

            ConstraintExpr::PublicInputRef(name) => {
                self.public_input_wire(name)
            }

            // ----- Equality / Inequality -----

            ConstraintExpr::Eq(a, b) => {
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                self.add_gate(Plonky3Gate::Equality { left, right });
                // Equality gates don't produce an output value wire;
                // return the left wire as the "result" (both are equal).
                left
            }

            ConstraintExpr::Neq(a, b) => {
                // Non-zero check: (a - b) * inv(a - b) = 1
                // 1. Compute diff = a - b
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let diff_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output: diff_wire,
                    op: ArithOp::Sub,
                });
                // 2. Allocate auxiliary wire for inv(diff)
                let inv_wire = self.witness_wire(&format!("__neq_inv_{}", diff_wire));
                // 3. Constrain diff * inv = 1 (via multiplication gate + equality to 1)
                let product_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: diff_wire,
                    right: inv_wire,
                    output: product_wire,
                    op: ArithOp::Mul,
                });
                let one_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Constant {
                    wire: one_wire,
                    value: GoldilocksField::ONE,
                });
                self.add_gate(Plonky3Gate::Equality {
                    left: product_wire,
                    right: one_wire,
                });
                diff_wire
            }

            // ----- Arithmetic -----

            ConstraintExpr::Add(a, b) => {
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output,
                    op: ArithOp::Add,
                });
                output
            }

            ConstraintExpr::Sub(a, b) => {
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output,
                    op: ArithOp::Sub,
                });
                output
            }

            ConstraintExpr::Mul(a, b) => {
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output,
                    op: ArithOp::Mul,
                });
                output
            }

            // ----- Boolean -----

            ConstraintExpr::And(a, b) => {
                // Boolean AND: a * b = c, with both inputs constrained to {0, 1}.
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                // Constrain inputs to boolean.
                self.add_gate(Plonky3Gate::Boolean { wire: left });
                self.add_gate(Plonky3Gate::Boolean { wire: right });
                // AND = multiplication of boolean values.
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output,
                    op: ArithOp::Mul,
                });
                output
            }

            ConstraintExpr::Or(a, b) => {
                // Boolean OR: a + b - a*b = c, with both inputs constrained to {0, 1}.
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                // Constrain inputs to boolean.
                self.add_gate(Plonky3Gate::Boolean { wire: left });
                self.add_gate(Plonky3Gate::Boolean { wire: right });
                // Compute a + b.
                let sum_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output: sum_wire,
                    op: ArithOp::Add,
                });
                // Compute a * b.
                let prod_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output: prod_wire,
                    op: ArithOp::Mul,
                });
                // Compute (a + b) - (a * b) = OR result.
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: sum_wire,
                    right: prod_wire,
                    output,
                    op: ArithOp::Sub,
                });
                output
            }

            // ----- Comparisons (range proofs) -----

            ConstraintExpr::Lt(a, b) => {
                // Lt(a, b): b - a - 1 ∈ [0, 2^n)
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                // diff = b - a
                let diff_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: right,
                    right: left,
                    output: diff_wire,
                    op: ArithOp::Sub,
                });
                // one constant
                let one_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Constant {
                    wire: one_wire,
                    value: GoldilocksField::ONE,
                });
                // result = diff - 1
                let result_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: diff_wire,
                    right: one_wire,
                    output: result_wire,
                    op: ArithOp::Sub,
                });
                self.add_gate(Plonky3Gate::RangeProof {
                    wire: result_wire,
                    bits: self.range_proof_bits,
                });
                result_wire
            }

            ConstraintExpr::Le(a, b) => {
                // Le(a, b): b - a ∈ [0, 2^n)
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let diff_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: right,
                    right: left,
                    output: diff_wire,
                    op: ArithOp::Sub,
                });
                self.add_gate(Plonky3Gate::RangeProof {
                    wire: diff_wire,
                    bits: self.range_proof_bits,
                });
                diff_wire
            }

            ConstraintExpr::Gt(a, b) => {
                // Gt(a, b): a - b - 1 ∈ [0, 2^n)
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let diff_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output: diff_wire,
                    op: ArithOp::Sub,
                });
                let one_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Constant {
                    wire: one_wire,
                    value: GoldilocksField::ONE,
                });
                let result_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left: diff_wire,
                    right: one_wire,
                    output: result_wire,
                    op: ArithOp::Sub,
                });
                self.add_gate(Plonky3Gate::RangeProof {
                    wire: result_wire,
                    bits: self.range_proof_bits,
                });
                result_wire
            }

            ConstraintExpr::Ge(a, b) => {
                // Ge(a, b): a - b ∈ [0, 2^n)
                let left = self.compile_expr(a);
                let right = self.compile_expr(b);
                let diff_wire = self.alloc_wire();
                self.add_gate(Plonky3Gate::Arithmetic {
                    left,
                    right,
                    output: diff_wire,
                    op: ArithOp::Sub,
                });
                self.add_gate(Plonky3Gate::RangeProof {
                    wire: diff_wire,
                    bits: self.range_proof_bits,
                });
                diff_wire
            }

            // ----- Conditional -----

            ConstraintExpr::IfThenElse(cond, then_expr, else_expr) => {
                // Selector/MUX: c*t + (1-c)*e = r, with c ∈ {0, 1}.
                let condition = self.compile_expr(cond);
                let then_val = self.compile_expr(then_expr);
                let else_val = self.compile_expr(else_expr);
                // Constrain condition to boolean.
                self.add_gate(Plonky3Gate::Boolean { wire: condition });
                let output = self.alloc_wire();
                self.add_gate(Plonky3Gate::Selector {
                    condition,
                    then_val,
                    else_val,
                    output,
                });
                output
            }

            // ----- Field access (wire indirection) -----

            ConstraintExpr::FieldAccess(base, field) => {
                // Wire indirection: resolve base.field to a witness wire.
                // The base expression is compiled, and the field access is
                // represented as a derived witness variable name.
                let base_wire = self.compile_expr(base);
                // Create a derived wire name from the base expression and field.
                let derived_name = format!("__field_{}_{}", base_wire, field);
                self.witness_wire(&derived_name)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitBuilder implementation for Plonky3CircuitBuilder
// ---------------------------------------------------------------------------

impl CircuitBuilder for Plonky3CircuitBuilder {
    type Circuit = Plonky3Circuit;
    type WireAssignment = Plonky3WireAssignment;
    type PublicWireAssignment = Plonky3PublicWireAssignment;

    /// Build a Plonky3 circuit from a VSEL constraint system.
    ///
    /// Translates every `Constraint` in the system into Plonky3 gates
    /// according to the ConstraintExpr-to-gate mapping. Also allocates
    /// wires for all witness variables and public inputs declared in
    /// the constraint system.
    ///
    /// # Panics
    ///
    /// Does not panic. Unsupported constraint expressions are recorded
    /// as errors and the first error is logged. The circuit is still
    /// produced (potentially incomplete) so that downstream code can
    /// inspect the partial result.
    ///
    /// Requirements 2.2, 2.3, 2.9.
    fn build_circuit(&self, constraints: &ConstraintSystem) -> Self::Circuit {
        let mut ctx = CircuitCompilationContext::new();

        // 1. Pre-allocate wires for declared witness variables.
        for wv in &constraints.witness_variables {
            ctx.witness_wire(&wv.name);
        }

        // 2. Pre-allocate wires for declared public inputs.
        for pi in &constraints.public_inputs {
            ctx.public_input_wire(&pi.name);
        }

        // 3. Compile each constraint expression into gates.
        for constraint in &constraints.constraints {
            ctx.compile_expr(&constraint.expr);
        }

        // 4. If any unsupported expressions were encountered, log them.
        // The errors are available for inspection but do not prevent
        // circuit construction (the circuit may be incomplete).
        if !ctx.errors.is_empty() {
            // In a production system, these would be propagated to the
            // caller. For now, the errors are stored in the context and
            // the first error is available via the Plonky3Error type.
            eprintln!(
                "plonky3-stark: circuit compilation encountered {} unsupported expression(s)",
                ctx.errors.len()
            );
        }

        Plonky3Circuit {
            num_private_inputs: ctx.witness_wires.len(),
            num_public_inputs: ctx.public_input_wires.len(),
            gates: ctx.gates,
            wiring: ctx.wiring,
            constraint_version: constraints.version.clone(),
            witness_wire_map: ctx.witness_wires,
            public_input_wire_map: ctx.public_input_wires,
        }
    }

    /// Assign witness values to circuit private input wires.
    ///
    /// Maps each witness variable declared in the constraint system to
    /// a concrete `GoldilocksField` value derived from the `Witness`:
    ///
    /// - Intermediate states -> field elements encoding state data
    /// - Input sequence -> field elements encoding input payloads
    /// - Auxiliary computation -> field elements for Merkle paths, etc.
    ///
    /// Requirements 2.2, 2.3.
    fn assign_witness(
        &self,
        circuit: &Self::Circuit,
        witness: &Witness,
    ) -> Self::WireAssignment {
        let mut assignments = HashMap::new();

        // Assign intermediate state data to witness wires.
        for (i, state) in witness.intermediate_states.iter().enumerate() {
            let state_commit = vsel_core::state::commit(&state.canonical);
            // Encode the state commitment as field elements (4 x 8-byte chunks).
            for (chunk_idx, chunk) in state_commit.0.chunks(8).enumerate() {
                let wire_name = format!("state_intermediate_{}_chunk_{}", i, chunk_idx);
                if let Some(&wire_id) = circuit.witness_wire_map.get(&wire_name) {
                    let field_val = GoldilocksField::from_bytes(chunk);
                    assignments.insert(wire_id, field_val);
                }
            }
        }

        // Assign input sequence data to witness wires.
        for (i, input) in witness.input_sequence.iter().enumerate() {
            let wire_name = format!("input_{}", i);
            if let Some(&wire_id) = circuit.witness_wire_map.get(&wire_name) {
                // Encode the input payload as a field element (hash of payload data).
                let payload_hash = {
                    use sha3::{Digest, Sha3_256};
                    let mut hasher = Sha3_256::new();
                    hasher.update(input.payload.payload_type.as_bytes());
                    hasher.update(&input.payload.data);
                    let result = hasher.finalize();
                    GoldilocksField::from_bytes(&result[..8])
                };
                assignments.insert(wire_id, payload_hash);
            }
        }

        // Assign auxiliary computation values to witness wires.
        for (name, value) in &witness.aux_computation.values {
            if let Some(&wire_id) = circuit.witness_wire_map.get(name) {
                let field_val = if value.len() >= 8 {
                    GoldilocksField::from_bytes(&value[..8])
                } else {
                    let mut padded = [0u8; 8];
                    padded[..value.len()].copy_from_slice(value);
                    GoldilocksField::from_bytes(&padded)
                };
                assignments.insert(wire_id, field_val);
            }
        }

        // For any witness wires not yet assigned, default to zero.
        for (_name_ref, &wire_id) in &circuit.witness_wire_map {
            assignments.entry(wire_id).or_insert(GoldilocksField::ZERO);
        }

        Plonky3WireAssignment { assignments }
    }

    /// Assign public input values to circuit public wires.
    ///
    /// Maps each public input declared in the constraint system to a
    /// concrete `GoldilocksField` value from `PublicInputs`:
    ///
    /// - `root_init` -> field element(s) encoding the initial state commitment
    /// - `root_final` -> field element(s) encoding the final state commitment
    /// - `domain` -> field element encoding the domain separation tag
    /// - `version` -> field element encoding the protocol version
    ///
    /// Requirements 2.2, 2.3.
    fn assign_public_inputs(
        &self,
        circuit: &Self::Circuit,
        public_inputs: &PublicInputs,
    ) -> Self::PublicWireAssignment {
        let mut assignments = HashMap::new();

        // Assign root_init.
        if let Some(&wire_id) = circuit.public_input_wire_map.get("root_init") {
            let field_val = GoldilocksField::from_bytes(&public_inputs.root_init.0[..8]);
            assignments.insert(wire_id, field_val);
        }

        // Assign root_final.
        if let Some(&wire_id) = circuit.public_input_wire_map.get("root_final") {
            let field_val = GoldilocksField::from_bytes(&public_inputs.root_final.0[..8]);
            assignments.insert(wire_id, field_val);
        }

        // Assign domain.
        if let Some(&wire_id) = circuit.public_input_wire_map.get("domain") {
            let field_val = GoldilocksField::from_bytes(&(public_inputs.domain.0).0[..8]);
            assignments.insert(wire_id, field_val);
        }

        // Assign version.
        if let Some(&wire_id) = circuit.public_input_wire_map.get("version") {
            let version_val = (public_inputs.version.major as u64) * 1_000_000
                + (public_inputs.version.minor as u64) * 1_000
                + (public_inputs.version.patch as u64);
            assignments.insert(wire_id, GoldilocksField(version_val % GoldilocksField::MODULUS));
        }

        // For any public input wires not yet assigned, default to zero.
        for (_name_ref, &wire_id) in &circuit.public_input_wire_map {
            assignments.entry(wire_id).or_insert(GoldilocksField::ZERO);
        }

        Plonky3PublicWireAssignment { assignments }
    }
}

// ---------------------------------------------------------------------------
// Plonky3CircuitBuilder — error-returning circuit build method
// ---------------------------------------------------------------------------

impl Plonky3CircuitBuilder {
    /// Build a circuit with explicit error reporting for unsupported
    /// constraint expressions.
    ///
    /// Unlike the `CircuitBuilder::build_circuit` trait method (which
    /// always returns a circuit), this method returns `Err` if any
    /// unsupported constraint expression is encountered.
    ///
    /// Requirement 2.9: no silent constraint dropping.
    pub fn try_build_circuit(
        &self,
        constraints: &ConstraintSystem,
    ) -> Result<Plonky3Circuit, Plonky3Error> {
        let mut ctx = CircuitCompilationContext::new();

        // Pre-allocate wires for declared witness variables.
        for wv in &constraints.witness_variables {
            ctx.witness_wire(&wv.name);
        }

        // Pre-allocate wires for declared public inputs.
        for pi in &constraints.public_inputs {
            ctx.public_input_wire(&pi.name);
        }

        // Compile each constraint expression into gates.
        for constraint in &constraints.constraints {
            ctx.compile_expr(&constraint.expr);
        }

        // If any unsupported expressions were encountered, return error.
        if let Some(err) = ctx.errors.into_iter().next() {
            return Err(err);
        }

        Ok(Plonky3Circuit {
            num_private_inputs: ctx.witness_wires.len(),
            num_public_inputs: ctx.public_input_wires.len(),
            gates: ctx.gates,
            wiring: ctx.wiring,
            constraint_version: constraints.version.clone(),
            witness_wire_map: ctx.witness_wires,
            public_input_wire_map: ctx.public_input_wires,
        })
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

    // -----------------------------------------------------------------------
    // build_circuit — basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_circuit_minimal() {
        let builder = Plonky3CircuitBuilder;
        let cs = minimal_constraint_system();
        let circuit = builder.build_circuit(&cs);

        assert_eq!(circuit.num_private_inputs, 1, "one witness variable: x");
        assert_eq!(circuit.num_public_inputs, 1, "one public input: root_init");
        assert!(!circuit.gates.is_empty(), "should have gates for Eq(WitnessRef, Constant)");
        assert_eq!(circuit.constraint_version, "1.0.0");
    }

    #[test]
    fn test_build_circuit_empty_constraint_system() {
        let builder = Plonky3CircuitBuilder;
        let cs = ConstraintSystem::new("1.0.0");
        let circuit = builder.build_circuit(&cs);

        assert_eq!(circuit.num_private_inputs, 0);
        assert_eq!(circuit.num_public_inputs, 0);
        assert!(circuit.gates.is_empty());
    }

    #[test]
    fn test_build_circuit_witness_wire_allocation() {
        let builder = Plonky3CircuitBuilder;
        let cs = minimal_constraint_system();
        let circuit = builder.build_circuit(&cs);

        assert!(circuit.witness_wire_map.contains_key("x"));
        assert!(circuit.public_input_wire_map.contains_key("root_init"));
    }

    // -----------------------------------------------------------------------
    // Gate mapping tests — one per ConstraintExpr variant
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_constant() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Constant(99),
            category: ConstraintCategory::Structural,
            description: "constant 99".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_constant = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Constant { value, .. } if *value == GoldilocksField(99)
        ));
        assert!(has_constant, "should have a Constant gate with value 99");
    }

    #[test]
    fn test_gate_bool_constant_true() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::BoolConstant(true),
            category: ConstraintCategory::Structural,
            description: "true".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_one = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Constant { value, .. } if *value == GoldilocksField::ONE
        ));
        assert!(has_one, "BoolConstant(true) should produce Constant(1)");
    }

    #[test]
    fn test_gate_bool_constant_false() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::BoolConstant(false),
            category: ConstraintCategory::Structural,
            description: "false".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_zero = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Constant { value, .. } if *value == GoldilocksField::ZERO
        ));
        assert!(has_zero, "BoolConstant(false) should produce Constant(0)");
    }

    #[test]
    fn test_gate_equality() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_witness_variable(WitnessVariable {
            name: "a".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "a".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "b".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "b".to_string(),
        });
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("a".to_string())),
                Box::new(ConstraintExpr::WitnessRef("b".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "a = b".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_equality = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Equality { .. }));
        assert!(has_equality, "Eq should produce an Equality gate");
    }

    #[test]
    fn test_gate_add() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Add(
                Box::new(ConstraintExpr::Constant(1)),
                Box::new(ConstraintExpr::Constant(2)),
            ),
            category: ConstraintCategory::Structural,
            description: "1 + 2".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_add = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Add, .. }
        ));
        assert!(has_add, "Add should produce an Arithmetic(Add) gate");
    }

    #[test]
    fn test_gate_sub() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Sub(
                Box::new(ConstraintExpr::Constant(5)),
                Box::new(ConstraintExpr::Constant(3)),
            ),
            category: ConstraintCategory::Structural,
            description: "5 - 3".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_sub = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Sub, .. }
        ));
        assert!(has_sub, "Sub should produce an Arithmetic(Sub) gate");
    }

    #[test]
    fn test_gate_mul() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Mul(
                Box::new(ConstraintExpr::Constant(3)),
                Box::new(ConstraintExpr::Constant(7)),
            ),
            category: ConstraintCategory::Structural,
            description: "3 * 7".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_mul = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Mul, .. }
        ));
        assert!(has_mul, "Mul should produce an Arithmetic(Mul) gate");
    }

    #[test]
    fn test_gate_and() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::And(
                Box::new(ConstraintExpr::BoolConstant(true)),
                Box::new(ConstraintExpr::BoolConstant(false)),
            ),
            category: ConstraintCategory::Structural,
            description: "true AND false".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        // And produces Boolean constraints + Arithmetic(Mul).
        let has_boolean = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Boolean { .. }));
        let has_mul = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Mul, .. }
        ));
        assert!(has_boolean, "And should produce Boolean constraint gates");
        assert!(has_mul, "And should produce Arithmetic(Mul) gate for a*b");
    }

    #[test]
    fn test_gate_or() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Or(
                Box::new(ConstraintExpr::BoolConstant(true)),
                Box::new(ConstraintExpr::BoolConstant(false)),
            ),
            category: ConstraintCategory::Structural,
            description: "true OR false".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        // Or produces Boolean constraints + Add + Mul + Sub.
        let has_boolean = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Boolean { .. }));
        let has_add = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Add, .. }
        ));
        assert!(has_boolean, "Or should produce Boolean constraint gates");
        assert!(has_add, "Or should produce Arithmetic(Add) gate for a+b");
    }

    #[test]
    fn test_gate_lt() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Lt(
                Box::new(ConstraintExpr::Constant(3)),
                Box::new(ConstraintExpr::Constant(10)),
            ),
            category: ConstraintCategory::Structural,
            description: "3 < 10".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_range = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::RangeProof { .. }));
        assert!(has_range, "Lt should produce a RangeProof gate");
    }

    #[test]
    fn test_gate_le() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Le(
                Box::new(ConstraintExpr::Constant(3)),
                Box::new(ConstraintExpr::Constant(10)),
            ),
            category: ConstraintCategory::Structural,
            description: "3 <= 10".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_range = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::RangeProof { .. }));
        assert!(has_range, "Le should produce a RangeProof gate");
    }

    #[test]
    fn test_gate_gt() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Gt(
                Box::new(ConstraintExpr::Constant(10)),
                Box::new(ConstraintExpr::Constant(3)),
            ),
            category: ConstraintCategory::Structural,
            description: "10 > 3".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_range = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::RangeProof { .. }));
        assert!(has_range, "Gt should produce a RangeProof gate");
    }

    #[test]
    fn test_gate_ge() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Ge(
                Box::new(ConstraintExpr::Constant(10)),
                Box::new(ConstraintExpr::Constant(3)),
            ),
            category: ConstraintCategory::Structural,
            description: "10 >= 3".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_range = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::RangeProof { .. }));
        assert!(has_range, "Ge should produce a RangeProof gate");
    }

    #[test]
    fn test_gate_neq() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Neq(
                Box::new(ConstraintExpr::Constant(5)),
                Box::new(ConstraintExpr::Constant(3)),
            ),
            category: ConstraintCategory::Structural,
            description: "5 != 3".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        // Neq produces Sub + Mul + Constant(1) + Equality.
        let has_sub = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Sub, .. }
        ));
        let has_mul = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Arithmetic { op: ArithOp::Mul, .. }
        ));
        let has_equality = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Equality { .. }));
        assert!(has_sub, "Neq should produce Sub gate for a-b");
        assert!(has_mul, "Neq should produce Mul gate for diff*inv");
        assert!(has_equality, "Neq should produce Equality gate for product=1");
    }

    #[test]
    fn test_gate_if_then_else() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::IfThenElse(
                Box::new(ConstraintExpr::BoolConstant(true)),
                Box::new(ConstraintExpr::Constant(10)),
                Box::new(ConstraintExpr::Constant(20)),
            ),
            category: ConstraintCategory::Branch,
            description: "if true then 10 else 20".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        let has_selector = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Selector { .. }));
        let has_boolean = circuit.gates.iter().any(|g| matches!(g, Plonky3Gate::Boolean { .. }));
        assert!(has_selector, "IfThenElse should produce a Selector gate");
        assert!(has_boolean, "IfThenElse should constrain condition to boolean");
    }

    #[test]
    fn test_gate_field_access() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_witness_variable(WitnessVariable {
            name: "state".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "state".to_string(),
        });
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::FieldAccess(
                Box::new(ConstraintExpr::WitnessRef("state".to_string())),
                "balance".to_string(),
            ),
            category: ConstraintCategory::Structural,
            description: "state.balance".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        // FieldAccess creates a derived witness wire.
        assert!(
            circuit.witness_wire_map.len() >= 2,
            "FieldAccess should create a derived witness wire in addition to 'state'"
        );
    }

    // -----------------------------------------------------------------------
    // Complex constraint system tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_complex_constraint_system() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");

        cs.add_witness_variable(WitnessVariable {
            name: "balance_pre".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "pre-state balance".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "balance_post".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "post-state balance".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "amount".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "transfer amount".to_string(),
        });
        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state root".to_string(),
        });
        cs.add_public_input(PublicInput {
            name: "root_final".to_string(),
            description: "final state root".to_string(),
        });

        // balance_pre + amount = balance_post
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::Add(
                    Box::new(ConstraintExpr::WitnessRef("balance_pre".to_string())),
                    Box::new(ConstraintExpr::WitnessRef("amount".to_string())),
                )),
                Box::new(ConstraintExpr::WitnessRef("balance_post".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "balance update".to_string(),
        });

        // amount > 0
        cs.add_constraint(Constraint {
            id: ConstraintId(1),
            expr: ConstraintExpr::Gt(
                Box::new(ConstraintExpr::WitnessRef("amount".to_string())),
                Box::new(ConstraintExpr::Constant(0)),
            ),
            category: ConstraintCategory::Semantic,
            description: "positive amount".to_string(),
        });

        let circuit = builder.build_circuit(&cs);

        assert_eq!(circuit.num_private_inputs, 3);
        assert_eq!(circuit.num_public_inputs, 2);
        assert!(circuit.gates.len() >= 3, "should have multiple gates");

        // Verify wire maps contain all declared variables.
        assert!(circuit.witness_wire_map.contains_key("balance_pre"));
        assert!(circuit.witness_wire_map.contains_key("balance_post"));
        assert!(circuit.witness_wire_map.contains_key("amount"));
        assert!(circuit.public_input_wire_map.contains_key("root_init"));
        assert!(circuit.public_input_wire_map.contains_key("root_final"));
    }

    // -----------------------------------------------------------------------
    // try_build_circuit — error reporting (Req 2.9)
    // -----------------------------------------------------------------------

    #[test]
    fn test_try_build_circuit_success() {
        let builder = Plonky3CircuitBuilder;
        let cs = minimal_constraint_system();
        let result = builder.try_build_circuit(&cs);
        assert!(result.is_ok(), "minimal constraint system should compile successfully");
    }

    #[test]
    fn test_try_build_circuit_empty() {
        let builder = Plonky3CircuitBuilder;
        let cs = ConstraintSystem::new("1.0.0");
        let result = builder.try_build_circuit(&cs);
        assert!(result.is_ok(), "empty constraint system should compile successfully");
    }

    // -----------------------------------------------------------------------
    // Wire assignment tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_assign_witness_empty() {
        let builder = Plonky3CircuitBuilder;
        let cs = ConstraintSystem::new("1.0.0");
        let circuit = builder.build_circuit(&cs);

        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: crate::witness::AuxiliaryComputation::empty(),
        };

        let assignment = builder.assign_witness(&circuit, &witness);
        assert!(assignment.assignments.is_empty());
    }

    #[test]
    fn test_assign_public_inputs_basic() {
        use vsel_core::types::{DomainTag, Hash, ProtocolVersion};

        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state commitment".to_string(),
        });
        cs.add_public_input(PublicInput {
            name: "root_final".to_string(),
            description: "final state commitment".to_string(),
        });
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
        // Should have assignments for root_init and root_final.
        assert_eq!(assignment.assignments.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Determinism test
    // -----------------------------------------------------------------------

    #[test]
    fn test_circuit_build_deterministic() {
        let builder = Plonky3CircuitBuilder;
        let cs = minimal_constraint_system();

        let circuit1 = builder.build_circuit(&cs);
        let circuit2 = builder.build_circuit(&cs);

        assert_eq!(circuit1.gates.len(), circuit2.gates.len());
        assert_eq!(circuit1.num_private_inputs, circuit2.num_private_inputs);
        assert_eq!(circuit1.num_public_inputs, circuit2.num_public_inputs);
        assert_eq!(circuit1.constraint_version, circuit2.constraint_version);

        // Gates should be identical.
        for (g1, g2) in circuit1.gates.iter().zip(circuit2.gates.iter()) {
            assert_eq!(g1, g2, "circuit build must be deterministic");
        }
    }

    // -----------------------------------------------------------------------
    // Negative constant test
    // -----------------------------------------------------------------------

    #[test]
    fn test_negative_constant() {
        let builder = Plonky3CircuitBuilder;
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Constant(-1),
            category: ConstraintCategory::Structural,
            description: "constant -1".to_string(),
        });
        let circuit = builder.build_circuit(&cs);

        // -1 mod p = p - 1
        let has_p_minus_1 = circuit.gates.iter().any(|g| matches!(
            g,
            Plonky3Gate::Constant { value, .. }
                if *value == GoldilocksField(GoldilocksField::MODULUS - 1)
        ));
        assert!(has_p_minus_1, "Constant(-1) should map to p-1 in Goldilocks field");
    }
}
