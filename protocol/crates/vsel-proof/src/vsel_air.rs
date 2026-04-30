//! VselAir — VSEL constraint system encoded as an Algebraic Intermediate
//! Representation (AIR) for Plonky3 STARK proof generation.
//!
//! Derived from: design.md Component 1, ZK_BACKEND_INTEGRATION.md,
//! Requirements 1.2, 1.9.
//!
//! This module defines the `VselAir` struct that encodes the VSEL
//! `ConstraintSystem` as polynomial constraints over the Goldilocks field.
//! It implements Plonky3's `Air<AB>` trait where `AB: AirBuilder`,
//! enabling real STARK proof generation via `p3-uni-stark`.
//!
//! # Execution Trace Layout
//!
//! | Column Range         | Purpose                              | Count |
//! |----------------------|--------------------------------------|-------|
//! | `0..W`               | Witness variables (private inputs)   | W     |
//! | `W..W+P`             | Public input variables               | P     |
//! | `W+P..W+P+A`         | Auxiliary columns (intermediates)     | A     |
//! | `W+P+A..W+P+A+1`     | Constraint satisfaction flag          | 1     |
//!
//! # ConstraintExpr → AIR Polynomial Constraint Mapping
//!
//! Each `ConstraintExpr` variant maps to polynomial constraints:
//!
//! | ConstraintExpr       | AIR Polynomial Constraint                          |
//! |----------------------|----------------------------------------------------|
//! | `Constant(v)`        | `col[i] - v = 0`                                   |
//! | `BoolConstant(b)`    | `col[i] - b = 0` where b ∈ {0, 1}                 |
//! | `WitnessRef(name)`   | Wire binding: `trace[row][col_map[name]]`          |
//! | `PublicInputRef(name)`| Public input binding                               |
//! | `Eq(a, b)`           | `eval(a) - eval(b) = 0`                            |
//! | `Neq(a, b)`          | `(eval(a) - eval(b)) * aux_inv = 1`                |
//! | `Add(a, b)`          | `eval(a) + eval(b) - aux_sum = 0`                  |
//! | `Sub(a, b)`          | `eval(a) - eval(b) - aux_diff = 0`                 |
//! | `Mul(a, b)`          | `eval(a) * eval(b) - aux_prod = 0`                 |
//! | `And(a, b)`          | `a*(1-a)=0, b*(1-b)=0, a*b - aux = 0`             |
//! | `Or(a, b)`           | `a + b - a*b - aux = 0` with boolean constraints   |
//! | `Lt(a, b)`           | Range proof: `b-a-1 = Σ(bit_i*2^i)`, bits boolean  |
//! | `Le(a, b)`           | Range proof: `b-a = Σ(bit_i*2^i)`, bits boolean    |
//! | `Gt(a, b)`           | Range proof: `a-b-1 = Σ(bit_i*2^i)`, bits boolean  |
//! | `Ge(a, b)`           | Range proof: `a-b = Σ(bit_i*2^i)`, bits boolean    |
//! | `IfThenElse(c,t,e)`  | `c*(1-c)=0, c*eval(t)+(1-c)*eval(e) - aux = 0`    |
//! | `FieldAccess(b,f)`   | Wire indirection: resolved at trace generation      |
//!
//! # Module Gating
//!
//! This entire module is gated behind `#[cfg(feature = "plonky3-backend")]`.

use std::collections::HashMap;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use vsel_constraints::compiler::{
    ConstraintCategory, ConstraintExpr, ConstraintSystem,
};

use crate::plonky3_backend::Plonky3Error;

// ---------------------------------------------------------------------------
// Range proof bit width — Goldilocks field is 64-bit
// ---------------------------------------------------------------------------

/// Number of bits for range proof decomposition.
/// Goldilocks field elements fit in 64 bits.
const RANGE_PROOF_BITS: usize = 64;

// ---------------------------------------------------------------------------
// ColumnMap — maps variable names to trace column indices
// ---------------------------------------------------------------------------

/// Maps constraint system variable names to trace column indices.
///
/// The column map is constructed during `VselAir` compilation and
/// determines the execution trace layout. Columns are allocated in
/// order: witness → public input → auxiliary → satisfaction flag.
///
/// Design document: Data Models → VselAir Column Map.
#[derive(Clone, Debug)]
pub struct ColumnMap {
    /// Witness variable name → column index.
    pub witness_cols: HashMap<String, usize>,
    /// Public input name → column index.
    pub public_cols: HashMap<String, usize>,
    /// Auxiliary variable name → column index.
    pub aux_cols: HashMap<String, usize>,
    /// Total number of columns in the trace.
    pub total_cols: usize,
}

impl ColumnMap {
    /// Look up a column index by name, searching witness, public, then aux.
    pub fn get(&self, name: &str) -> Option<usize> {
        self.witness_cols
            .get(name)
            .or_else(|| self.public_cols.get(name))
            .or_else(|| self.aux_cols.get(name))
            .copied()
    }
}

// ---------------------------------------------------------------------------
// CompiledConstraint — a constraint compiled to column references
// ---------------------------------------------------------------------------

/// A constraint compiled to column references for AIR evaluation.
///
/// Each `CompiledConstraint` represents a polynomial identity that
/// must hold on every row of the execution trace. The `poly` field
/// encodes the polynomial expression in terms of column indices.
#[derive(Clone, Debug)]
pub struct CompiledConstraint {
    /// The polynomial identity to enforce (must evaluate to zero).
    pub poly: PolyExpr,
    /// Category for error reporting and traceability.
    pub category: ConstraintCategory,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// PolyExpr — polynomial expression over trace columns
// ---------------------------------------------------------------------------

/// Polynomial expression over trace column values.
///
/// Represents the algebraic structure of a constraint in terms of
/// column indices. Evaluated during `Air::eval` to produce the
/// polynomial identity that `builder.assert_zero()` enforces.
#[derive(Clone, Debug)]
pub enum PolyExpr {
    /// A constant field element value.
    Constant(i64),
    /// Reference to a trace column by index (current row).
    Column(usize),
    /// Reference to a public input by index.
    PublicInput(usize),
    /// Addition: lhs + rhs.
    Add(Box<PolyExpr>, Box<PolyExpr>),
    /// Subtraction: lhs - rhs.
    Sub(Box<PolyExpr>, Box<PolyExpr>),
    /// Multiplication: lhs * rhs.
    Mul(Box<PolyExpr>, Box<PolyExpr>),
    /// Negation: -expr.
    Neg(Box<PolyExpr>),
}

// ---------------------------------------------------------------------------
// VselAir — VSEL constraint system as AIR
// ---------------------------------------------------------------------------

/// VSEL AIR — encodes the VSEL constraint system as polynomial constraints
/// over the Goldilocks field for Plonky3 STARK proof generation.
///
/// The AIR operates over an execution trace matrix where each row
/// represents one constraint evaluation step and columns represent
/// variables (witness, public input, auxiliary, satisfaction flag).
///
/// # Construction
///
/// Use `VselAir::compile()` to build a `VselAir` from a `ConstraintSystem`.
/// The compilation process:
/// 1. Allocates witness columns from `ConstraintSystem::witness_variables`
/// 2. Allocates public input columns from `ConstraintSystem::public_inputs`
/// 3. Compiles each `Constraint` into a `CompiledConstraint` with
///    `PolyExpr` referencing column indices
/// 4. Allocates auxiliary columns for intermediate computations
/// 5. Adds the constraint satisfaction flag column
///
/// # AIR Evaluation
///
/// The `eval` method iterates over `compiled_constraints` and calls
/// `builder.assert_zero(poly)` for each polynomial identity.
///
/// Requirements 1.2, 1.9.
pub struct VselAir {
    /// Number of witness variable columns.
    num_witness_cols: usize,
    /// Number of public input columns.
    num_public_cols: usize,
    /// Number of auxiliary columns (intermediates, range bits).
    num_aux_cols: usize,
    /// Compiled constraint expressions with column mappings.
    compiled_constraints: Vec<CompiledConstraint>,
    /// Column name → column index mapping.
    col_map: ColumnMap,
    /// Number of public values expected by the verifier.
    /// This is set via `set_num_public_values()` after compilation
    /// to match the number of Goldilocks field elements produced by
    /// `Plonky3Backend::encode_public_inputs()`.
    num_public_values: usize,
}

impl VselAir {
    /// Return the column map for trace generation.
    pub fn col_map(&self) -> &ColumnMap {
        &self.col_map
    }

    /// Return the number of witness columns.
    pub fn num_witness_cols(&self) -> usize {
        self.num_witness_cols
    }

    /// Return the number of public input columns.
    pub fn num_public_cols(&self) -> usize {
        self.num_public_cols
    }

    /// Return the number of auxiliary columns.
    pub fn num_aux_cols(&self) -> usize {
        self.num_aux_cols
    }

    /// Return the compiled constraints.
    pub fn compiled_constraints(&self) -> &[CompiledConstraint] {
        &self.compiled_constraints
    }

    /// Total width of the execution trace (all columns).
    pub fn trace_width(&self) -> usize {
        self.col_map.total_cols
    }

    /// Set the number of public values expected by the verifier.
    ///
    /// This must be called after compilation and before proving/verifying
    /// to match the number of Goldilocks field elements produced by
    /// `Plonky3Backend::encode_public_inputs()`.
    pub fn set_num_public_values(&mut self, n: usize) {
        self.num_public_values = n;
    }

    /// Return the number of public values.
    pub fn get_num_public_values(&self) -> usize {
        self.num_public_values
    }

    /// Compile a `ConstraintSystem` into a `VselAir`.
    ///
    /// This is the main entry point for building the AIR from the VSEL
    /// constraint system. The compilation process:
    ///
    /// 1. Allocates witness columns (indices `0..W`)
    /// 2. Allocates public input columns (indices `W..W+P`)
    /// 3. Compiles each constraint into a `CompiledConstraint`
    /// 4. Allocates auxiliary columns for intermediate computations
    /// 5. Adds the constraint satisfaction flag column
    ///
    /// Returns `Err(Plonky3Error::UnsupportedGate)` if any `ConstraintExpr`
    /// variant cannot be encoded as AIR constraints.
    ///
    /// Requirements 1.2, 1.9.
    pub fn compile(cs: &ConstraintSystem) -> Result<Self, Plonky3Error> {
        let mut ctx = CompilationContext::new();

        // Step 1: Allocate witness columns (0..W).
        for wv in &cs.witness_variables {
            ctx.alloc_witness_col(&wv.name);
        }
        let num_witness_cols = ctx.witness_cols.len();

        // Step 2: Allocate public input columns (W..W+P).
        for pi in &cs.public_inputs {
            ctx.alloc_public_col(&pi.name);
        }
        let num_public_cols = ctx.public_cols.len();

        // Step 3: Compile each constraint into a CompiledConstraint.
        for constraint in &cs.constraints {
            let poly = ctx.compile_constraint_expr(&constraint.expr)?;

            // For Eq constraints, the polynomial identity is: eval(a) - eval(b) = 0
            // which is already encoded in the PolyExpr. We assert_zero the result.
            ctx.compiled_constraints.push(CompiledConstraint {
                poly,
                category: constraint.category,
                description: constraint.description.clone(),
            });
        }

        let num_aux_cols = ctx.aux_cols.len();

        // Step 4: Add constraint satisfaction flag column.
        let flag_col_name = "__constraint_satisfaction_flag".to_string();
        let flag_idx = ctx.next_col;
        ctx.aux_cols.insert(flag_col_name, flag_idx);
        ctx.next_col += 1;

        // Build the column map.
        let total_cols = ctx.next_col;

        let col_map = ColumnMap {
            witness_cols: ctx.witness_cols,
            public_cols: ctx.public_cols,
            aux_cols: ctx.aux_cols,
            total_cols,
        };

        Ok(VselAir {
            num_witness_cols,
            num_public_cols,
            num_aux_cols: num_aux_cols + 1, // +1 for satisfaction flag
            compiled_constraints: ctx.compiled_constraints,
            col_map,
            num_public_values: 0, // Set via set_num_public_values() before prove/verify
        })
    }
}

// ---------------------------------------------------------------------------
// BaseAir implementation — trace width
// ---------------------------------------------------------------------------

impl BaseAir<Goldilocks> for VselAir {
    /// Return the total number of columns in the execution trace.
    fn width(&self) -> usize {
        self.col_map.total_cols
    }

    /// Return the number of public values expected by the verifier.
    ///
    /// This must match the number of Goldilocks field elements passed
    /// to `p3_uni_stark::prove()` and `p3_uni_stark::verify()` as
    /// `public_values`. Set via `set_num_public_values()` after
    /// compilation.
    fn num_public_values(&self) -> usize {
        self.num_public_values
    }
}

// ---------------------------------------------------------------------------
// Air implementation — constraint evaluation
// ---------------------------------------------------------------------------

impl<AB> Air<AB> for VselAir
where
    AB: AirBuilder<F = Goldilocks>,
{
    /// Evaluate all VSEL constraints as AIR polynomial identities.
    ///
    /// Iterates over `compiled_constraints` and calls
    /// `builder.assert_zero(poly)` for each polynomial identity.
    /// Each constraint is evaluated on the current row of the trace.
    ///
    /// The `PolyExpr` tree is recursively evaluated into `AB::Expr`
    /// values using the builder's trace access methods.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();

        for compiled in &self.compiled_constraints {
            let expr = eval_poly_expr::<AB>(&compiled.poly, local, builder);
            builder.assert_zero(expr);
        }
    }
}

// ---------------------------------------------------------------------------
// PolyExpr evaluation — recursive evaluation into AB::Expr
// ---------------------------------------------------------------------------

/// Recursively evaluate a `PolyExpr` into an `AB::Expr` value.
///
/// Uses the builder's trace access to resolve column references and
/// constructs the polynomial expression using field arithmetic.
fn eval_poly_expr<AB>(
    poly: &PolyExpr,
    local: &[AB::Var],
    builder: &AB,
) -> AB::Expr
where
    AB: AirBuilder<F = Goldilocks>,
{
    match poly {
        PolyExpr::Constant(v) => {
            // Convert i64 constant to Goldilocks field element using
            // PrimeCharacteristicRing::from_i64 which handles negative
            // values correctly (computes v mod p).
            let field_val = Goldilocks::from_i64(*v);
            // AB::Expr: Algebra<AB::F> which extends From<AB::F>,
            // so we can convert the field constant to an expression.
            AB::Expr::from(field_val)
        }

        PolyExpr::Column(idx) => {
            // Access the column value from the current row of the trace.
            local[*idx].into()
        }

        PolyExpr::PublicInput(idx) => {
            // Access the public input value.
            let public_values = builder.public_values();
            if *idx < public_values.len() {
                public_values[*idx].into()
            } else {
                // Out-of-bounds public input — treat as zero.
                // This should not happen with a correctly compiled AIR.
                AB::Expr::from(Goldilocks::ZERO)
            }
        }

        PolyExpr::Add(lhs, rhs) => {
            let l = eval_poly_expr::<AB>(lhs, local, builder);
            let r = eval_poly_expr::<AB>(rhs, local, builder);
            l + r
        }

        PolyExpr::Sub(lhs, rhs) => {
            let l = eval_poly_expr::<AB>(lhs, local, builder);
            let r = eval_poly_expr::<AB>(rhs, local, builder);
            l - r
        }

        PolyExpr::Mul(lhs, rhs) => {
            let l = eval_poly_expr::<AB>(lhs, local, builder);
            let r = eval_poly_expr::<AB>(rhs, local, builder);
            l * r
        }

        PolyExpr::Neg(inner) => {
            let val = eval_poly_expr::<AB>(inner, local, builder);
            AB::Expr::from(Goldilocks::ZERO) - val
        }
    }
}

// ---------------------------------------------------------------------------
// CompilationContext — internal state during AIR compilation
// ---------------------------------------------------------------------------

/// Internal context used during AIR compilation from `ConstraintSystem`.
///
/// Tracks column allocation and name-to-index mappings as constraints
/// are compiled into `PolyExpr` trees.
struct CompilationContext {
    /// Next available column index.
    next_col: usize,
    /// Witness variable name → column index.
    witness_cols: HashMap<String, usize>,
    /// Public input name → column index.
    public_cols: HashMap<String, usize>,
    /// Auxiliary variable name → column index.
    aux_cols: HashMap<String, usize>,
    /// Compiled constraints accumulated during compilation.
    compiled_constraints: Vec<CompiledConstraint>,
}

impl CompilationContext {
    /// Create a new compilation context.
    fn new() -> Self {
        Self {
            next_col: 0,
            witness_cols: HashMap::new(),
            public_cols: HashMap::new(),
            aux_cols: HashMap::new(),
            compiled_constraints: Vec::new(),
        }
    }

    /// Allocate a witness column, returning its index.
    fn alloc_witness_col(&mut self, name: &str) -> usize {
        if let Some(&idx) = self.witness_cols.get(name) {
            return idx;
        }
        let idx = self.next_col;
        self.witness_cols.insert(name.to_string(), idx);
        self.next_col += 1;
        idx
    }

    /// Allocate a public input column, returning its index.
    fn alloc_public_col(&mut self, name: &str) -> usize {
        if let Some(&idx) = self.public_cols.get(name) {
            return idx;
        }
        let idx = self.next_col;
        self.public_cols.insert(name.to_string(), idx);
        self.next_col += 1;
        idx
    }

    /// Allocate an auxiliary column, returning its index.
    fn alloc_aux_col(&mut self, name: &str) -> usize {
        if let Some(&idx) = self.aux_cols.get(name) {
            return idx;
        }
        let idx = self.next_col;
        self.aux_cols.insert(name.to_string(), idx);
        self.next_col += 1;
        idx
    }

    /// Look up a column index by name (witness, public, or aux).
    fn resolve_col(&self, name: &str) -> Option<usize> {
        self.witness_cols
            .get(name)
            .or_else(|| self.public_cols.get(name))
            .or_else(|| self.aux_cols.get(name))
            .copied()
    }

    /// Get or allocate a column for a variable name.
    /// Witness and public columns are pre-allocated; unknown names
    /// become auxiliary columns.
    fn get_or_alloc_col(&mut self, name: &str) -> usize {
        if let Some(idx) = self.resolve_col(name) {
            idx
        } else {
            self.alloc_aux_col(name)
        }
    }

    // -----------------------------------------------------------------------
    // ConstraintExpr → PolyExpr compilation
    // -----------------------------------------------------------------------

    /// Compile a `ConstraintExpr` into a `PolyExpr` referencing column indices.
    ///
    /// Maps each `ConstraintExpr` variant to AIR polynomial constraints
    /// per the mapping table in design Component 1. Allocates auxiliary
    /// columns as needed for intermediate computations.
    ///
    /// Returns `Err(Plonky3Error::UnsupportedGate)` if a variant cannot
    /// be encoded (Requirement 1.9).
    fn compile_constraint_expr(
        &mut self,
        expr: &ConstraintExpr,
    ) -> Result<PolyExpr, Plonky3Error> {
        match expr {
            // ----- Leaf nodes -----

            ConstraintExpr::Constant(v) => {
                // Constant(v): the constraint is that some column equals v.
                // As a standalone expression, return the constant value.
                Ok(PolyExpr::Constant(*v))
            }

            ConstraintExpr::BoolConstant(b) => {
                // BoolConstant(b): b ∈ {0, 1}.
                Ok(PolyExpr::Constant(if *b { 1 } else { 0 }))
            }

            ConstraintExpr::WitnessRef(name) => {
                // Wire binding: trace[row][col_map[name]].
                let col = self.get_or_alloc_col(name);
                Ok(PolyExpr::Column(col))
            }

            ConstraintExpr::PublicInputRef(name) => {
                // Public input binding.
                // Public inputs in Plonky3 are accessed via builder.public_values().
                // We store the index into the public_cols map.
                let col = self.get_or_alloc_col(name);
                Ok(PolyExpr::Column(col))
            }

            // ----- Equality / Inequality -----

            ConstraintExpr::Eq(a, b) => {
                // Eq(a, b): eval(a) - eval(b) = 0
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;
                Ok(PolyExpr::Sub(Box::new(lhs), Box::new(rhs)))
            }

            ConstraintExpr::Neq(a, b) => {
                // Neq(a, b): (eval(a) - eval(b)) * aux_inv = 1
                // Equivalently: (eval(a) - eval(b)) * aux_inv - 1 = 0
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;
                let diff = PolyExpr::Sub(Box::new(lhs), Box::new(rhs));

                // Allocate auxiliary column for the inverse of the difference.
                let inv_col = self.alloc_aux_col(&format!(
                    "__neq_inv_{}",
                    self.aux_cols.len()
                ));

                // Constraint: diff * inv - 1 = 0
                let product = PolyExpr::Mul(
                    Box::new(diff),
                    Box::new(PolyExpr::Column(inv_col)),
                );
                Ok(PolyExpr::Sub(
                    Box::new(product),
                    Box::new(PolyExpr::Constant(1)),
                ))
            }

            // ----- Arithmetic -----

            ConstraintExpr::Add(a, b) => {
                // Add(a, b): eval(a) + eval(b) - aux_sum = 0
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;
                let sum = PolyExpr::Add(Box::new(lhs), Box::new(rhs));

                let aux_col = self.alloc_aux_col(&format!(
                    "__add_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(sum),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            ConstraintExpr::Sub(a, b) => {
                // Sub(a, b): eval(a) - eval(b) - aux_diff = 0
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;
                let diff = PolyExpr::Sub(Box::new(lhs), Box::new(rhs));

                let aux_col = self.alloc_aux_col(&format!(
                    "__sub_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(diff),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            ConstraintExpr::Mul(a, b) => {
                // Mul(a, b): eval(a) * eval(b) - aux_prod = 0
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;
                let product = PolyExpr::Mul(Box::new(lhs), Box::new(rhs));

                let aux_col = self.alloc_aux_col(&format!(
                    "__mul_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(product),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            // ----- Boolean -----

            ConstraintExpr::And(a, b) => {
                // And(a, b): a*(1-a)=0, b*(1-b)=0, a*b - aux = 0
                // We emit the product constraint: a*b - aux = 0.
                // The boolean constraints on a and b are added as
                // separate compiled constraints.
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;

                // Boolean constraint on a: a*(1-a) = 0
                let bool_a = PolyExpr::Mul(
                    Box::new(lhs.clone()),
                    Box::new(PolyExpr::Sub(
                        Box::new(PolyExpr::Constant(1)),
                        Box::new(lhs.clone()),
                    )),
                );
                self.compiled_constraints.push(CompiledConstraint {
                    poly: bool_a,
                    category: ConstraintCategory::Structural,
                    description: "boolean constraint on AND left operand".to_string(),
                });

                // Boolean constraint on b: b*(1-b) = 0
                let bool_b = PolyExpr::Mul(
                    Box::new(rhs.clone()),
                    Box::new(PolyExpr::Sub(
                        Box::new(PolyExpr::Constant(1)),
                        Box::new(rhs.clone()),
                    )),
                );
                self.compiled_constraints.push(CompiledConstraint {
                    poly: bool_b,
                    category: ConstraintCategory::Structural,
                    description: "boolean constraint on AND right operand".to_string(),
                });

                // Product constraint: a*b - aux = 0
                let product = PolyExpr::Mul(Box::new(lhs), Box::new(rhs));
                let aux_col = self.alloc_aux_col(&format!(
                    "__and_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(product),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            ConstraintExpr::Or(a, b) => {
                // Or(a, b): a + b - a*b - aux = 0, with boolean constraints.
                let lhs = self.compile_constraint_expr(a)?;
                let rhs = self.compile_constraint_expr(b)?;

                // Boolean constraint on a: a*(1-a) = 0
                let bool_a = PolyExpr::Mul(
                    Box::new(lhs.clone()),
                    Box::new(PolyExpr::Sub(
                        Box::new(PolyExpr::Constant(1)),
                        Box::new(lhs.clone()),
                    )),
                );
                self.compiled_constraints.push(CompiledConstraint {
                    poly: bool_a,
                    category: ConstraintCategory::Structural,
                    description: "boolean constraint on OR left operand".to_string(),
                });

                // Boolean constraint on b: b*(1-b) = 0
                let bool_b = PolyExpr::Mul(
                    Box::new(rhs.clone()),
                    Box::new(PolyExpr::Sub(
                        Box::new(PolyExpr::Constant(1)),
                        Box::new(rhs.clone()),
                    )),
                );
                self.compiled_constraints.push(CompiledConstraint {
                    poly: bool_b,
                    category: ConstraintCategory::Structural,
                    description: "boolean constraint on OR right operand".to_string(),
                });

                // OR formula: a + b - a*b - aux = 0
                let sum = PolyExpr::Add(Box::new(lhs.clone()), Box::new(rhs.clone()));
                let product = PolyExpr::Mul(Box::new(lhs), Box::new(rhs));
                let or_expr = PolyExpr::Sub(Box::new(sum), Box::new(product));

                let aux_col = self.alloc_aux_col(&format!(
                    "__or_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(or_expr),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            // ----- Comparisons (range proofs via bit decomposition) -----

            ConstraintExpr::Lt(a, b) => {
                // Lt(a, b): b - a - 1 = Σ(bit_i * 2^i), each bit_i*(1-bit_i) = 0
                self.compile_range_proof(a, b, true, false)
            }

            ConstraintExpr::Le(a, b) => {
                // Le(a, b): b - a = Σ(bit_i * 2^i), each bit_i*(1-bit_i) = 0
                self.compile_range_proof(a, b, false, false)
            }

            ConstraintExpr::Gt(a, b) => {
                // Gt(a, b): a - b - 1 = Σ(bit_i * 2^i)
                self.compile_range_proof(b, a, true, false)
            }

            ConstraintExpr::Ge(a, b) => {
                // Ge(a, b): a - b = Σ(bit_i * 2^i)
                self.compile_range_proof(b, a, false, false)
            }

            // ----- Conditional -----

            ConstraintExpr::IfThenElse(cond, then_expr, else_expr) => {
                // IfThenElse(c, t, e):
                //   c*(1-c) = 0  (boolean constraint on condition)
                //   c*eval(t) + (1-c)*eval(e) - aux = 0
                let c = self.compile_constraint_expr(cond)?;
                let t = self.compile_constraint_expr(then_expr)?;
                let e = self.compile_constraint_expr(else_expr)?;

                // Boolean constraint on condition: c*(1-c) = 0
                let bool_c = PolyExpr::Mul(
                    Box::new(c.clone()),
                    Box::new(PolyExpr::Sub(
                        Box::new(PolyExpr::Constant(1)),
                        Box::new(c.clone()),
                    )),
                );
                self.compiled_constraints.push(CompiledConstraint {
                    poly: bool_c,
                    category: ConstraintCategory::Branch,
                    description: "boolean constraint on IfThenElse condition".to_string(),
                });

                // Selector: c*t + (1-c)*e - aux = 0
                let c_times_t = PolyExpr::Mul(Box::new(c.clone()), Box::new(t));
                let one_minus_c = PolyExpr::Sub(
                    Box::new(PolyExpr::Constant(1)),
                    Box::new(c),
                );
                let one_minus_c_times_e = PolyExpr::Mul(
                    Box::new(one_minus_c),
                    Box::new(e),
                );
                let selector = PolyExpr::Add(
                    Box::new(c_times_t),
                    Box::new(one_minus_c_times_e),
                );

                let aux_col = self.alloc_aux_col(&format!(
                    "__ite_result_{}",
                    self.aux_cols.len()
                ));

                Ok(PolyExpr::Sub(
                    Box::new(selector),
                    Box::new(PolyExpr::Column(aux_col)),
                ))
            }

            // ----- Field access (wire indirection) -----

            ConstraintExpr::FieldAccess(base, field) => {
                // Wire indirection: resolved at trace generation time.
                // Compile the base expression and create a derived column
                // for the field access result.
                let _base_poly = self.compile_constraint_expr(base)?;
                let derived_name = format!("__field_access_{}", field);
                let col = self.get_or_alloc_col(&derived_name);
                Ok(PolyExpr::Column(col))
            }
        }
    }

    /// Compile a range proof constraint for comparison operations.
    ///
    /// For `strict = true`: `rhs - lhs - 1 = Σ(bit_i * 2^i)`
    /// For `strict = false`: `rhs - lhs = Σ(bit_i * 2^i)`
    ///
    /// Each bit column gets a boolean constraint: `bit_i * (1 - bit_i) = 0`.
    /// The number of bits is `RANGE_PROOF_BITS` (64 for Goldilocks).
    ///
    /// Returns the polynomial identity that must equal zero.
    fn compile_range_proof(
        &mut self,
        lhs: &ConstraintExpr,
        rhs: &ConstraintExpr,
        strict: bool,
        _reversed: bool,
    ) -> Result<PolyExpr, Plonky3Error> {
        let lhs_poly = self.compile_constraint_expr(lhs)?;
        let rhs_poly = self.compile_constraint_expr(rhs)?;

        // Compute the difference: rhs - lhs (or rhs - lhs - 1 for strict).
        let diff = if strict {
            PolyExpr::Sub(
                Box::new(PolyExpr::Sub(Box::new(rhs_poly), Box::new(lhs_poly))),
                Box::new(PolyExpr::Constant(1)),
            )
        } else {
            PolyExpr::Sub(Box::new(rhs_poly), Box::new(lhs_poly))
        };

        // Allocate bit columns and build the bit decomposition sum.
        let base_name = format!("__range_bit_{}", self.aux_cols.len());
        let mut bit_sum: PolyExpr = PolyExpr::Constant(0);

        for i in 0..RANGE_PROOF_BITS {
            let bit_col = self.alloc_aux_col(&format!("{}_{}", base_name, i));

            // Boolean constraint on each bit: bit_i * (1 - bit_i) = 0
            let bit_ref = PolyExpr::Column(bit_col);
            let bool_constraint = PolyExpr::Mul(
                Box::new(bit_ref.clone()),
                Box::new(PolyExpr::Sub(
                    Box::new(PolyExpr::Constant(1)),
                    Box::new(bit_ref.clone()),
                )),
            );
            self.compiled_constraints.push(CompiledConstraint {
                poly: bool_constraint,
                category: ConstraintCategory::Structural,
                description: format!("range proof bit {} boolean constraint", i),
            });

            // Accumulate: bit_sum += bit_i * 2^i
            let power_of_two = 1i64 << i;
            let weighted_bit = PolyExpr::Mul(
                Box::new(bit_ref),
                Box::new(PolyExpr::Constant(power_of_two)),
            );
            bit_sum = PolyExpr::Add(Box::new(bit_sum), Box::new(weighted_bit));
        }

        // Final constraint: diff - bit_sum = 0
        Ok(PolyExpr::Sub(Box::new(diff), Box::new(bit_sum)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_constraints::compiler::{
        Constraint, ConstraintCategory, ConstraintExpr, ConstraintId,
        ConstraintSystem, PublicInput, WitnessVariable, WitnessVariableKind,
    };

    /// Build a minimal constraint system for testing.
    fn minimal_constraint_system() -> ConstraintSystem {
        let mut cs = ConstraintSystem::new("1.0.0");

        cs.add_witness_variable(WitnessVariable {
            name: "x".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test witness variable x".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "y".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test witness variable y".to_string(),
        });

        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state commitment".to_string(),
        });

        cs
    }

    #[test]
    fn test_compile_empty_constraint_system() {
        let cs = ConstraintSystem::new("1.0.0");
        let air = VselAir::compile(&cs).expect("compilation should succeed");

        assert_eq!(air.num_witness_cols(), 0);
        assert_eq!(air.num_public_cols(), 0);
        // 1 for the satisfaction flag
        assert_eq!(air.num_aux_cols(), 1);
        assert_eq!(air.compiled_constraints().len(), 0);
        // Total: 0 witness + 0 public + 1 flag
        assert_eq!(air.trace_width(), 1);
    }

    #[test]
    fn test_compile_with_witness_and_public_inputs() {
        let cs = minimal_constraint_system();
        let air = VselAir::compile(&cs).expect("compilation should succeed");

        assert_eq!(air.num_witness_cols(), 2); // x, y
        assert_eq!(air.num_public_cols(), 1); // root_init
        // Satisfaction flag only (no constraints → no aux columns)
        assert_eq!(air.num_aux_cols(), 1);
        // Total: 2 witness + 1 public + 1 flag = 4
        assert_eq!(air.trace_width(), 4);
    }

    #[test]
    fn test_column_map_layout() {
        let cs = minimal_constraint_system();
        let air = VselAir::compile(&cs).expect("compilation should succeed");
        let col_map = air.col_map();

        // Witness columns come first (0, 1).
        let x_col = col_map.witness_cols.get("x").expect("x should exist");
        let y_col = col_map.witness_cols.get("y").expect("y should exist");
        assert!(*x_col < 2);
        assert!(*y_col < 2);
        assert_ne!(x_col, y_col);

        // Public input column comes after witness (index 2).
        let root_col = col_map
            .public_cols
            .get("root_init")
            .expect("root_init should exist");
        assert_eq!(*root_col, 2);
    }

    #[test]
    fn test_compile_eq_constraint() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::Constant(42)),
            ),
            category: ConstraintCategory::Structural,
            description: "x = 42".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        assert_eq!(air.compiled_constraints().len(), 1);
    }

    #[test]
    fn test_compile_neq_constraint() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Neq(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x != y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 1 main constraint (diff * inv - 1 = 0)
        assert_eq!(air.compiled_constraints().len(), 1);
        // Should have allocated an auxiliary column for the inverse.
        assert!(air.num_aux_cols() > 1); // 1 for inv + 1 for flag
    }

    #[test]
    fn test_compile_arithmetic_constraints() {
        let mut cs = minimal_constraint_system();

        // Add: x + y
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Add(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x + y".to_string(),
        });

        // Sub: x - y
        cs.add_constraint(Constraint {
            id: ConstraintId(1),
            expr: ConstraintExpr::Sub(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x - y".to_string(),
        });

        // Mul: x * y
        cs.add_constraint(Constraint {
            id: ConstraintId(2),
            expr: ConstraintExpr::Mul(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x * y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 3 main constraints (one per arithmetic op)
        assert_eq!(air.compiled_constraints().len(), 3);
    }

    #[test]
    fn test_compile_boolean_and() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::And(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x AND y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 1 main constraint (a*b - aux = 0) + 2 boolean constraints
        assert_eq!(air.compiled_constraints().len(), 3);
    }

    #[test]
    fn test_compile_boolean_or() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Or(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Structural,
            description: "x OR y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 1 main constraint (a+b-a*b - aux = 0) + 2 boolean constraints
        assert_eq!(air.compiled_constraints().len(), 3);
    }

    #[test]
    fn test_compile_if_then_else() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::IfThenElse(
                Box::new(ConstraintExpr::BoolConstant(true)),
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Branch,
            description: "if true then x else y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 1 main constraint (selector) + 1 boolean constraint on condition
        assert_eq!(air.compiled_constraints().len(), 2);
    }

    #[test]
    fn test_compile_comparison_lt() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Lt(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::WitnessRef("y".to_string())),
            ),
            category: ConstraintCategory::Semantic,
            description: "x < y".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // 1 main constraint (diff - bit_sum = 0) + 64 boolean constraints
        assert_eq!(air.compiled_constraints().len(), 1 + RANGE_PROOF_BITS);
        // Should have allocated 64 bit columns + 1 flag
        assert!(air.num_aux_cols() > RANGE_PROOF_BITS);
    }

    #[test]
    fn test_compile_field_access() {
        let mut cs = minimal_constraint_system();
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::FieldAccess(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                "balance".to_string(),
            ),
            category: ConstraintCategory::Structural,
            description: "x.balance".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        assert_eq!(air.compiled_constraints().len(), 1);
    }

    #[test]
    fn test_base_air_width() {
        let cs = minimal_constraint_system();
        let air = VselAir::compile(&cs).expect("compilation should succeed");
        assert_eq!(BaseAir::<Goldilocks>::width(&air), air.trace_width());
    }

    #[test]
    fn test_compile_complex_nested_constraint() {
        let mut cs = minimal_constraint_system();

        // Complex: Eq(Add(x, Constant(1)), Mul(y, Constant(2)))
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::Add(
                    Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                    Box::new(ConstraintExpr::Constant(1)),
                )),
                Box::new(ConstraintExpr::Mul(
                    Box::new(ConstraintExpr::WitnessRef("y".to_string())),
                    Box::new(ConstraintExpr::Constant(2)),
                )),
            ),
            category: ConstraintCategory::Structural,
            description: "x + 1 = y * 2".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        // The Eq compiles to a Sub of the two sides.
        // Each side (Add, Mul) introduces an aux column.
        // So we get 1 main constraint.
        assert_eq!(air.compiled_constraints().len(), 1);
    }

    #[test]
    fn test_column_map_get() {
        let cs = minimal_constraint_system();
        let air = VselAir::compile(&cs).expect("compilation should succeed");
        let col_map = air.col_map();

        assert!(col_map.get("x").is_some());
        assert!(col_map.get("y").is_some());
        assert!(col_map.get("root_init").is_some());
        assert!(col_map.get("nonexistent").is_none());
    }
}
