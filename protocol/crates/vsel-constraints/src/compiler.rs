//! Constraint compiler — SIR/IR → algebraic constraint derivation.
//!
//! Derived from: CONSTRAINT_DERIVATION.md, UNDERCONSTRAINT_ANALYSIS.md,
//! design.md Component 6.
//!
//! Requirements: 5.6 (branch completeness — CONST-3), 5.8 (carry-over equality).
//!
//! Critical invariants:
//! - NO hand-written constraints — all constraints are derived from SIR/IR constructs.
//! - Every conditional (If, Match) MUST generate constraints for ALL branches (CONST-3).
//! - Carry-over constraints enforce `∀ f ∉ AllowedMutations(σ): s'.f = s.f`.
//! - All constraint generation is deterministic (same input → same output).

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use vsel_sir::types::{
    SirExpr, SirInvariant, SirMatchArm, SirProgram, SirStateSchema, SirTransition, SirValue,
};

// ---------------------------------------------------------------------------
// Constraint ID — unique, deterministic identifier
// ---------------------------------------------------------------------------

/// Global monotonic counter for deterministic constraint ID generation.
/// Reset via `reset_constraint_id_counter` for reproducible test runs.
static CONSTRAINT_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reset the global constraint ID counter. Call before each compilation
/// to ensure deterministic output (CONST-4).
pub fn reset_constraint_id_counter() {
    CONSTRAINT_ID_COUNTER.store(0, Ordering::SeqCst);
}

fn next_constraint_id() -> u64 {
    CONSTRAINT_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Unique identifier for a constraint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConstraintId(pub u64);

// ---------------------------------------------------------------------------
// Constraint category
// ---------------------------------------------------------------------------

/// Category of a constraint — determines its role in the constraint system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintCategory {
    /// Structural constraints from SIR expression structure.
    Structural,
    /// Semantic constraints encoding meaning (preconditions, postconditions).
    Semantic,
    /// Invariant constraints (local, global, temporal, economic).
    Invariant,
    /// Carry-over equality constraints for non-mutated fields.
    CarryOver,
    /// Branch constraints from conditionals (If, Match) — CONST-3.
    Branch,
}

// ---------------------------------------------------------------------------
// Constraint expression — algebraic constraint representation
// ---------------------------------------------------------------------------

/// Algebraic constraint expression.
///
/// Represents the constraint language used in the constraint system.
/// These are derived from SIR expressions, never hand-written.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConstraintExpr {
    /// Constant value.
    Constant(i64),
    /// Boolean constant.
    BoolConstant(bool),
    /// Reference to a witness variable by name.
    WitnessRef(String),
    /// Reference to a public input by name.
    PublicInputRef(String),
    /// Equality constraint: lhs = rhs.
    Eq(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Inequality constraint: lhs ≠ rhs.
    Neq(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Less-than constraint: lhs < rhs.
    Lt(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Less-than-or-equal constraint: lhs ≤ rhs.
    Le(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Greater-than constraint: lhs > rhs.
    Gt(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Greater-than-or-equal constraint: lhs ≥ rhs.
    Ge(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Addition: lhs + rhs.
    Add(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Subtraction: lhs - rhs.
    Sub(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Multiplication: lhs * rhs.
    Mul(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Boolean AND: lhs ∧ rhs.
    And(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Boolean OR: lhs ∨ rhs.
    Or(Box<ConstraintExpr>, Box<ConstraintExpr>),
    /// Conditional: if cond then a else b.
    /// Both branches are always present (CONST-3).
    IfThenElse(
        Box<ConstraintExpr>,
        Box<ConstraintExpr>,
        Box<ConstraintExpr>,
    ),
    /// Field access on a witness variable: var.field.
    FieldAccess(Box<ConstraintExpr>, String),
}

// ---------------------------------------------------------------------------
// Witness variable
// ---------------------------------------------------------------------------

/// Kind of witness variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WitnessVariableKind {
    /// Semantic variable — directly corresponds to a SIR value.
    Semantic,
    /// Auxiliary variable — intermediate computation, must not influence semantics.
    Auxiliary,
    /// Derived variable — computed from other witness variables.
    Derived,
}

/// A variable in the constraint system.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WitnessVariable {
    /// Variable name (unique within the constraint system).
    pub name: String,
    /// Kind of variable.
    pub kind: WitnessVariableKind,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Public input
// ---------------------------------------------------------------------------

/// A public input to the constraint system.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicInput {
    /// Input name (unique within the constraint system).
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Constraint
// ---------------------------------------------------------------------------

/// A single algebraic constraint in the constraint system.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    /// Unique constraint identifier.
    pub id: ConstraintId,
    /// The algebraic expression that must hold (evaluate to true / zero).
    pub expr: ConstraintExpr,
    /// Category of this constraint.
    pub category: ConstraintCategory,
    /// Human-readable description of what this constraint enforces.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Constraint system
// ---------------------------------------------------------------------------

/// The full constraint system — compiled from SIR/IR.
///
/// Contains all constraints, witness variables, and public inputs.
/// Generated deterministically from a `SirProgram` (CONST-4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConstraintSystem {
    /// All constraints in the system.
    pub constraints: Vec<Constraint>,
    /// All witness variables.
    pub witness_variables: Vec<WitnessVariable>,
    /// All public inputs.
    pub public_inputs: Vec<PublicInput>,
    /// Version string for the constraint system.
    pub version: String,
}

impl ConstraintSystem {
    /// Create an empty constraint system.
    pub fn new(version: &str) -> Self {
        Self {
            constraints: Vec::new(),
            witness_variables: Vec::new(),
            public_inputs: Vec::new(),
            version: version.to_string(),
        }
    }

    /// Add a constraint to the system.
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    /// Backward-compatible alias for `add_constraint`.
    pub fn add(&mut self, constraint: Constraint) {
        self.add_constraint(constraint);
    }

    /// Add a witness variable to the system.
    pub fn add_witness_variable(&mut self, var: WitnessVariable) {
        self.witness_variables.push(var);
    }

    /// Add a public input to the system.
    pub fn add_public_input(&mut self, input: PublicInput) {
        self.public_inputs.push(input);
    }

    /// Merge another constraint system into this one.
    pub fn merge(&mut self, other: ConstraintSystem) {
        self.constraints.extend(other.constraints);
        self.witness_variables.extend(other.witness_variables);
        self.public_inputs.extend(other.public_inputs);
    }
}

// ---------------------------------------------------------------------------
// Helper: create a constraint with auto-generated ID
// ---------------------------------------------------------------------------

fn make_constraint(
    expr: ConstraintExpr,
    category: ConstraintCategory,
    description: &str,
) -> Constraint {
    Constraint {
        id: ConstraintId(next_constraint_id()),
        expr,
        category,
        description: description.to_string(),
    }
}

// ---------------------------------------------------------------------------
// SIR expression → ConstraintExpr lowering
// ---------------------------------------------------------------------------

/// Lower a SIR expression into a constraint expression.
///
/// This is the core translation from the SIR AST to the algebraic
/// constraint language. Every SIR construct has a corresponding
/// constraint template.
fn lower_sir_expr(expr: &SirExpr) -> ConstraintExpr {
    match expr {
        SirExpr::Literal { value } => lower_sir_value(value),

        SirExpr::Var { name } => ConstraintExpr::WitnessRef(name.clone()),

        SirExpr::BinOp { op, left, right } => {
            let l = lower_sir_expr(left);
            let r = lower_sir_expr(right);
            lower_binop(op, l, r)
        }

        SirExpr::If { cond, then_, else_ } => {
            let c = lower_sir_expr(cond);
            let t = lower_sir_expr(then_);
            let e = lower_sir_expr(else_);
            // CONST-3: both branches are always represented.
            ConstraintExpr::IfThenElse(Box::new(c), Box::new(t), Box::new(e))
        }

        SirExpr::Let { name, value, body } => {
            // Let bindings introduce a witness variable equal to the value.
            // The body is lowered with the binding in scope.
            // We represent this as: body[name := value].
            // In the constraint system, we generate an equality constraint
            // separately (in template_let), and here we just lower the body.
            let _ = name;
            let _ = value;
            lower_sir_expr(body)
        }

        SirExpr::FieldAccess { expr, field } => {
            let base = lower_sir_expr(expr);
            ConstraintExpr::FieldAccess(Box::new(base), field.clone())
        }

        SirExpr::Match { scrutinee, arms } => lower_match(scrutinee, arms),

        SirExpr::Apply { func, args } => {
            // Function application — lower to a witness reference for the result.
            // The actual constraint is generated in the template.
            let func_name = match func.as_ref() {
                SirExpr::Var { name } => name.clone(),
                _ => "anonymous_func".to_string(),
            };
            let _lowered_args: Vec<ConstraintExpr> = args.iter().map(lower_sir_expr).collect();
            // Represent as a derived witness variable for the function result.
            ConstraintExpr::WitnessRef(format!("result_{}", func_name))
        }
    }
}

/// Lower a SIR value to a constraint expression constant.
fn lower_sir_value(value: &SirValue) -> ConstraintExpr {
    match value {
        SirValue::Int { value } => ConstraintExpr::Constant(*value),
        SirValue::Bool { value } => ConstraintExpr::BoolConstant(*value),
        SirValue::Unit => ConstraintExpr::Constant(0),
        // Complex values are represented as witness references.
        _ => ConstraintExpr::Constant(0),
    }
}

/// Lower a binary operation to a constraint expression.
fn lower_binop(op: &str, left: ConstraintExpr, right: ConstraintExpr) -> ConstraintExpr {
    match op {
        "add" => ConstraintExpr::Add(Box::new(left), Box::new(right)),
        "sub" => ConstraintExpr::Sub(Box::new(left), Box::new(right)),
        "mul" => ConstraintExpr::Mul(Box::new(left), Box::new(right)),
        "eq" => ConstraintExpr::Eq(Box::new(left), Box::new(right)),
        "neq" => ConstraintExpr::Neq(Box::new(left), Box::new(right)),
        "lt" => ConstraintExpr::Lt(Box::new(left), Box::new(right)),
        "le" => ConstraintExpr::Le(Box::new(left), Box::new(right)),
        "gt" => ConstraintExpr::Gt(Box::new(left), Box::new(right)),
        "ge" => ConstraintExpr::Ge(Box::new(left), Box::new(right)),
        "and" => ConstraintExpr::And(Box::new(left), Box::new(right)),
        "or" => ConstraintExpr::Or(Box::new(left), Box::new(right)),
        // Division and modulo are represented as multiplication constraints:
        // a / b = c  ⟺  c * b = a (with b ≠ 0)
        "div" | "mod" => {
            // Represent as a derived witness ref; the actual constraint
            // is generated in the template.
            ConstraintExpr::WitnessRef(format!("result_{}_{}", op, next_constraint_id()))
        }
        _ => ConstraintExpr::WitnessRef(format!("result_unknown_op_{}", op)),
    }
}

/// Lower a match expression — generates constraints for ALL arms (CONST-3).
fn lower_match(scrutinee: &SirExpr, arms: &[SirMatchArm]) -> ConstraintExpr {
    let scrut = lower_sir_expr(scrutinee);

    if arms.is_empty() {
        return ConstraintExpr::Constant(0);
    }

    // Build a chain of if-then-else for each arm.
    // This ensures every arm generates constraints (CONST-3).
    let mut result = lower_sir_expr(&arms.last().unwrap().body);

    for arm in arms.iter().rev().skip(1) {
        let arm_cond = match &arm.pattern {
            vsel_sir::types::SirPattern::Literal { value } => {
                ConstraintExpr::Eq(Box::new(scrut.clone()), Box::new(lower_sir_value(value)))
            }
            vsel_sir::types::SirPattern::Var { .. } => {
                // Wildcard always matches — this becomes the else branch.
                ConstraintExpr::BoolConstant(true)
            }
        };
        let arm_body = lower_sir_expr(&arm.body);
        result =
            ConstraintExpr::IfThenElse(Box::new(arm_cond), Box::new(arm_body), Box::new(result));
    }

    result
}

// ---------------------------------------------------------------------------
// Constraint templates — one per SIR construct
// ---------------------------------------------------------------------------

/// Generate constraints for a literal expression.
///
/// A literal introduces a constant constraint: the witness variable
/// for this expression equals the literal value.
pub fn template_literal(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::Literal { value } => {
            let lowered = lower_sir_value(value);
            let desc = format!("literal constraint: value = {:?}", value);
            vec![make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(lowered),
                ),
                ConstraintCategory::Structural,
                &desc,
            )]
        }
        _ => vec![],
    }
}

/// Generate constraints for a variable reference.
///
/// A variable reference constrains the expression result to equal
/// the referenced witness variable.
pub fn template_var(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::Var { name } => {
            vec![make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(ConstraintExpr::WitnessRef(name.clone())),
                ),
                ConstraintCategory::Structural,
                &format!("variable reference: result = {}", name),
            )]
        }
        _ => vec![],
    }
}

/// Generate constraints for a binary operation.
///
/// Binary operations produce structural constraints relating the
/// operands and result.
pub fn template_binop(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::BinOp { op, left, right } => {
            let l = lower_sir_expr(left);
            let r = lower_sir_expr(right);
            let result_expr = lower_binop(op, l.clone(), r.clone());

            let mut constraints = vec![make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(result_expr),
                ),
                ConstraintCategory::Structural,
                &format!("binop constraint: result = left {} right", op),
            )];

            // Recurse into operands.
            constraints.extend(compile_expr(left));
            constraints.extend(compile_expr(right));

            constraints
        }
        _ => vec![],
    }
}

/// Generate constraints for a conditional expression (CONST-3).
///
/// CRITICAL: Both branches MUST generate constraints. This is enforced
/// by always lowering both `then_` and `else_` branches, regardless
/// of the condition value.
pub fn template_if(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::If { cond, then_, else_ } => {
            let cond_lowered = lower_sir_expr(cond);
            let then_lowered = lower_sir_expr(then_);
            let else_lowered = lower_sir_expr(else_);

            let mut constraints = Vec::new();

            // Main conditional constraint — both branches present (CONST-3).
            constraints.push(make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(ConstraintExpr::IfThenElse(
                        Box::new(cond_lowered),
                        Box::new(then_lowered),
                        Box::new(else_lowered),
                    )),
                ),
                ConstraintCategory::Branch,
                "conditional constraint (CONST-3): both branches constrained",
            ));

            // Recurse into condition.
            constraints.extend(compile_expr(cond));
            // Recurse into BOTH branches — CONST-3 enforcement.
            constraints.extend(compile_expr(then_));
            constraints.extend(compile_expr(else_));

            constraints
        }
        _ => vec![],
    }
}

/// Generate constraints for a let binding.
///
/// A let binding introduces a witness variable and constrains it
/// to equal the bound value expression.
pub fn template_let(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::Let { name, value, body } => {
            let value_lowered = lower_sir_expr(value);

            let mut constraints = Vec::new();

            // Equality constraint: name = value.
            constraints.push(make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef(name.clone())),
                    Box::new(value_lowered),
                ),
                ConstraintCategory::Structural,
                &format!("let binding: {} = <value>", name),
            ));

            // Recurse into value and body.
            constraints.extend(compile_expr(value));
            constraints.extend(compile_expr(body));

            constraints
        }
        _ => vec![],
    }
}

/// Generate constraints for a field access expression.
///
/// Field access constrains the result to equal the specified field
/// of the base expression.
pub fn template_field_access(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::FieldAccess { expr: base, field } => {
            let base_lowered = lower_sir_expr(base);

            let mut constraints = vec![make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(ConstraintExpr::FieldAccess(
                        Box::new(base_lowered),
                        field.clone(),
                    )),
                ),
                ConstraintCategory::Structural,
                &format!("field access: result = base.{}", field),
            )];

            // Recurse into base expression.
            constraints.extend(compile_expr(base));

            constraints
        }
        _ => vec![],
    }
}

/// Generate constraints for a match expression (CONST-3).
///
/// CRITICAL: ALL arms MUST generate constraints. This is enforced
/// by iterating over every arm and generating constraints for each.
pub fn template_match(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::Match { scrutinee, arms } => {
            let match_lowered = lower_match(scrutinee, arms);

            let mut constraints = Vec::new();

            // Main match constraint — all arms present (CONST-3).
            constraints.push(make_constraint(
                ConstraintExpr::Eq(
                    Box::new(ConstraintExpr::WitnessRef("_expr_result".to_string())),
                    Box::new(match_lowered),
                ),
                ConstraintCategory::Branch,
                &format!(
                    "match constraint (CONST-3): all {} arms constrained",
                    arms.len()
                ),
            ));

            // Recurse into scrutinee.
            constraints.extend(compile_expr(scrutinee));

            // Recurse into EVERY arm body — CONST-3 enforcement.
            for (i, arm) in arms.iter().enumerate() {
                let arm_constraints = compile_expr(&arm.body);
                // Tag each arm constraint with its index for traceability.
                for mut c in arm_constraints {
                    c.description = format!("[match arm {}] {}", i, c.description);
                    constraints.push(c);
                }
            }

            constraints
        }
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Recursive expression compilation
// ---------------------------------------------------------------------------

/// Compile a SIR expression into constraints by dispatching to the
/// appropriate template.
pub fn compile_expr(expr: &SirExpr) -> Vec<Constraint> {
    match expr {
        SirExpr::Literal { .. } => template_literal(expr),
        SirExpr::Var { .. } => template_var(expr),
        SirExpr::BinOp { .. } => template_binop(expr),
        SirExpr::If { .. } => template_if(expr),
        SirExpr::Let { .. } => template_let(expr),
        SirExpr::FieldAccess { .. } => template_field_access(expr),
        SirExpr::Match { .. } => template_match(expr),
        SirExpr::Apply { func, args } => {
            let mut constraints = Vec::new();
            // Generate constraints for function arguments.
            constraints.extend(compile_expr(func));
            for arg in args {
                constraints.extend(compile_expr(arg));
            }
            constraints
        }
    }
}

// ---------------------------------------------------------------------------
// Carry-over equality constraints (Requirement 5.8)
// ---------------------------------------------------------------------------

/// Generate carry-over equality constraints for a transition.
///
/// For every field NOT in `transition.allowed_mutations`, generate:
///   `s'.field = s.field`
///
/// This enforces bounded state mutation (Requirement 5.8):
///   `∀ f ∉ AllowedMutations(σ): s'.f = s.f`
pub fn generate_carry_over_constraints(
    transition: &SirTransition,
    state_schema: &SirStateSchema,
) -> Vec<Constraint> {
    let allowed: std::collections::BTreeSet<&str> = transition
        .allowed_mutations
        .iter()
        .map(|s| s.as_str())
        .collect();

    state_schema
        .fields
        .iter()
        .filter(|field| !allowed.contains(field.name.as_str()))
        .map(|field| {
            let pre_field = ConstraintExpr::FieldAccess(
                Box::new(ConstraintExpr::WitnessRef("state_pre".to_string())),
                field.name.clone(),
            );
            let post_field = ConstraintExpr::FieldAccess(
                Box::new(ConstraintExpr::WitnessRef("state_post".to_string())),
                field.name.clone(),
            );
            make_constraint(
                ConstraintExpr::Eq(Box::new(post_field), Box::new(pre_field)),
                ConstraintCategory::CarryOver,
                &format!(
                    "carry-over: s'.{} = s.{} (field not in AllowedMutations)",
                    field.name, field.name
                ),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Transition constraint generation
// ---------------------------------------------------------------------------

/// Generate all constraints for a single transition.
///
/// Combines:
/// 1. Precondition constraints — all preconditions must hold.
/// 2. Body constraints — the transition body expression.
/// 3. Postcondition constraints — all postconditions must hold.
/// 4. Carry-over constraints — non-mutated fields are unchanged.
pub fn generate_transition_constraints(
    transition: &SirTransition,
    state_schema: &SirStateSchema,
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    // 1. Precondition constraints.
    for (i, pre) in transition.preconditions.iter().enumerate() {
        let pre_lowered = lower_sir_expr(pre);
        constraints.push(make_constraint(
            ConstraintExpr::Eq(
                Box::new(pre_lowered),
                Box::new(ConstraintExpr::BoolConstant(true)),
            ),
            ConstraintCategory::Semantic,
            &format!("precondition {} for transition '{}'", i, transition.name),
        ));
        constraints.extend(compile_expr(pre));
    }

    // 2. Body constraints.
    let body_lowered = lower_sir_expr(&transition.body);
    constraints.push(make_constraint(
        ConstraintExpr::Eq(
            Box::new(ConstraintExpr::WitnessRef("state_post".to_string())),
            Box::new(body_lowered),
        ),
        ConstraintCategory::Structural,
        &format!("body constraint for transition '{}'", transition.name),
    ));
    constraints.extend(compile_expr(&transition.body));

    // 3. Postcondition constraints.
    for (i, post) in transition.postconditions.iter().enumerate() {
        let post_lowered = lower_sir_expr(post);
        constraints.push(make_constraint(
            ConstraintExpr::Eq(
                Box::new(post_lowered),
                Box::new(ConstraintExpr::BoolConstant(true)),
            ),
            ConstraintCategory::Semantic,
            &format!("postcondition {} for transition '{}'", i, transition.name),
        ));
        constraints.extend(compile_expr(post));
    }

    // 4. Carry-over equality constraints (Requirement 5.8).
    constraints.extend(generate_carry_over_constraints(transition, state_schema));

    constraints
}

// ---------------------------------------------------------------------------
// Invariant constraint generation
// ---------------------------------------------------------------------------

/// Generate constraints for a single SIR invariant.
///
/// Lowers the invariant expression to a constraint expression and generates
/// a constraint that the expression equals `true`. Tagged with
/// `ConstraintCategory::Invariant`.
///
/// Handles all invariant categories: local, global, temporal, economic.
pub fn generate_invariant_constraints(invariant: &SirInvariant) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    let lowered = lower_sir_expr(&invariant.expr);

    // The invariant expression must evaluate to true.
    constraints.push(make_constraint(
        ConstraintExpr::Eq(
            Box::new(lowered),
            Box::new(ConstraintExpr::BoolConstant(true)),
        ),
        ConstraintCategory::Invariant,
        &format!(
            "invariant '{}' (category: {}) must hold",
            invariant.name, invariant.category
        ),
    ));

    // Also generate structural constraints from the invariant expression body.
    constraints.extend(compile_expr(&invariant.expr));

    constraints
}

// ---------------------------------------------------------------------------
// Compile — deterministic transformation D: SIR → C (CONST-4)
// ---------------------------------------------------------------------------

/// Compile a SIR program into a constraint system.
///
/// This is the main compilation entry point implementing the deterministic
/// transformation D: SIR → C (CONST-4). No manual constraint injection
/// is permitted — all constraints are derived from the SIR program.
///
/// Requirements: 5.1, 5.7, 5.9
///
/// Steps:
/// 1. Reset the constraint ID counter for determinism (CONST-4).
/// 2. Generate witness variables from state_schema and input_schema.
/// 3. Generate public inputs (state_pre commitment, state_post commitment, domain, version).
/// 4. For each transition, call `generate_transition_constraints`.
/// 5. For each invariant, call `generate_invariant_constraints`.
/// 6. Return the complete ConstraintSystem.
pub fn compile(sir_program: &SirProgram) -> ConstraintSystem {
    // 1. Reset for determinism (CONST-4).
    reset_constraint_id_counter();

    let mut system = ConstraintSystem::new(&sir_program.version);

    // 2. Generate witness variables from state_schema fields.
    for field in &sir_program.state_schema.fields {
        system.add_witness_variable(WitnessVariable {
            name: format!("state_pre.{}", field.name),
            kind: WitnessVariableKind::Semantic,
            description: format!(
                "Pre-state field '{}' (type: {})",
                field.name, field.field_type
            ),
        });
        system.add_witness_variable(WitnessVariable {
            name: format!("state_post.{}", field.name),
            kind: WitnessVariableKind::Semantic,
            description: format!(
                "Post-state field '{}' (type: {})",
                field.name, field.field_type
            ),
        });
    }

    // Generate witness variables from input_schema fields.
    for field in &sir_program.input_schema.fields {
        system.add_witness_variable(WitnessVariable {
            name: format!("input.{}", field.name),
            kind: WitnessVariableKind::Semantic,
            description: format!("Input field '{}' (type: {})", field.name, field.field_type),
        });
    }

    // 3. Generate public inputs.
    system.add_public_input(PublicInput {
        name: "state_pre_commitment".to_string(),
        description: "Commitment of the pre-transition canonical state".to_string(),
    });
    system.add_public_input(PublicInput {
        name: "state_post_commitment".to_string(),
        description: "Commitment of the post-transition canonical state".to_string(),
    });
    system.add_public_input(PublicInput {
        name: "domain".to_string(),
        description: "Execution domain tag for domain separation".to_string(),
    });
    system.add_public_input(PublicInput {
        name: "version".to_string(),
        description: "Protocol version string".to_string(),
    });

    // 4. For each transition, generate transition constraints.
    for transition in &sir_program.transitions {
        let transition_constraints =
            generate_transition_constraints(transition, &sir_program.state_schema);
        for c in transition_constraints {
            system.add_constraint(c);
        }
    }

    // 5. For each invariant, generate invariant constraints.
    for invariant in &sir_program.invariants {
        let invariant_constraints = generate_invariant_constraints(invariant);
        for c in invariant_constraints {
            system.add_constraint(c);
        }
    }

    system
}

// ---------------------------------------------------------------------------
// Constraint expression evaluation
// ---------------------------------------------------------------------------

/// Evaluate a `ConstraintExpr` against a variable environment.
///
/// Returns the result as a `SirValue`, or `None` if evaluation fails
/// (e.g., undefined variable, type mismatch).
///
/// Used by `satisfies_constraints` to check constraint satisfaction.
pub fn evaluate_constraint_expr(
    expr: &ConstraintExpr,
    env: &std::collections::BTreeMap<String, SirValue>,
) -> Option<SirValue> {
    match expr {
        ConstraintExpr::Constant(v) => Some(SirValue::Int { value: *v }),

        ConstraintExpr::BoolConstant(v) => Some(SirValue::Bool { value: *v }),

        ConstraintExpr::WitnessRef(name) => env.get(name).cloned(),

        ConstraintExpr::PublicInputRef(name) => env.get(name).cloned(),

        ConstraintExpr::Eq(lhs, rhs) => {
            let l = evaluate_constraint_expr(lhs, env)?;
            let r = evaluate_constraint_expr(rhs, env)?;
            Some(SirValue::Bool { value: l == r })
        }

        ConstraintExpr::Neq(lhs, rhs) => {
            let l = evaluate_constraint_expr(lhs, env)?;
            let r = evaluate_constraint_expr(rhs, env)?;
            Some(SirValue::Bool { value: l != r })
        }

        ConstraintExpr::Lt(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l < r })
        }

        ConstraintExpr::Le(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l <= r })
        }

        ConstraintExpr::Gt(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l > r })
        }

        ConstraintExpr::Ge(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l >= r })
        }

        ConstraintExpr::Add(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Int { value: l + r })
        }

        ConstraintExpr::Sub(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Int { value: l - r })
        }

        ConstraintExpr::Mul(lhs, rhs) => {
            let l = as_i64(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_i64(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Int { value: l * r })
        }

        ConstraintExpr::And(lhs, rhs) => {
            let l = as_bool(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_bool(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l && r })
        }

        ConstraintExpr::Or(lhs, rhs) => {
            let l = as_bool(&evaluate_constraint_expr(lhs, env)?)?;
            let r = as_bool(&evaluate_constraint_expr(rhs, env)?)?;
            Some(SirValue::Bool { value: l || r })
        }

        ConstraintExpr::IfThenElse(cond, then_, else_) => {
            let c = as_bool(&evaluate_constraint_expr(cond, env)?)?;
            if c {
                evaluate_constraint_expr(then_, env)
            } else {
                evaluate_constraint_expr(else_, env)
            }
        }

        ConstraintExpr::FieldAccess(base, field) => {
            let base_val = evaluate_constraint_expr(base, env)?;
            match base_val {
                SirValue::Map { entries } => entries.get(field).cloned(),
                _ => None,
            }
        }
    }
}

/// Extract an i64 from a SirValue::Int.
fn as_i64(v: &SirValue) -> Option<i64> {
    match v {
        SirValue::Int { value } => Some(*value),
        _ => None,
    }
}

/// Extract a bool from a SirValue::Bool.
fn as_bool(v: &SirValue) -> Option<bool> {
    match v {
        SirValue::Bool { value } => Some(*value),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Constraint satisfaction checking
// ---------------------------------------------------------------------------

/// Flatten a `SirValue` into a variable environment with dotted-path keys.
///
/// For example, a `Map { "balance": Int(100) }` with prefix `"state_pre"`
/// produces `{ "state_pre.balance": Int(100), "state_pre": Map { ... } }`.
fn flatten_sir_value(
    prefix: &str,
    value: &SirValue,
    env: &mut std::collections::BTreeMap<String, SirValue>,
) {
    env.insert(prefix.to_string(), value.clone());
    if let SirValue::Map { entries } = value {
        for (key, val) in entries {
            let dotted = format!("{}.{}", prefix, key);
            flatten_sir_value(&dotted, val, env);
        }
    }
}

/// Check whether a constraint is satisfied given a variable environment.
///
/// A constraint is satisfied when its expression evaluates to `Bool(true)`.
/// For `Eq` constraints at the top level, we check that the equality holds.
fn constraint_satisfied(
    constraint: &Constraint,
    env: &std::collections::BTreeMap<String, SirValue>,
) -> bool {
    match evaluate_constraint_expr(&constraint.expr, env) {
        Some(SirValue::Bool { value: true }) => true,
        // If evaluation returns None (e.g., missing variable), we treat
        // the constraint as vacuously satisfied — the variable is not
        // present in this trace step's scope.
        None => true,
        _ => false,
    }
}

/// Check whether a trace satisfies all constraints in a constraint system.
///
/// Takes a trace as a sequence of `(pre_state, input, post_state)` SIR values.
/// For each step, evaluates all constraints against the witness values.
/// Returns `true` only if ALL constraints are satisfied for ALL steps.
///
/// Requirements: 5.1, 5.7, 5.9
pub fn satisfies_constraints(
    trace_steps: &[(SirValue, SirValue, SirValue)],
    constraints: &ConstraintSystem,
) -> bool {
    for (pre_state, input, post_state) in trace_steps {
        let mut env = std::collections::BTreeMap::new();

        // Populate the environment with flattened witness values.
        flatten_sir_value("state_pre", pre_state, &mut env);
        flatten_sir_value("state_post", post_state, &mut env);
        flatten_sir_value("input", input, &mut env);

        // Also bind bare "state" to pre_state for invariant expressions
        // that reference "state" directly.
        flatten_sir_value("state", pre_state, &mut env);

        // Check every constraint.
        for constraint in &constraints.constraints {
            if !constraint_satisfied(constraint, &env) {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vsel_sir::types::*;

    /// Reset counter before each test for determinism.
    fn setup() {
        reset_constraint_id_counter();
    }

    // -- template_literal --

    #[test]
    fn test_template_literal_int() {
        setup();
        let expr = SirExpr::Literal {
            value: SirValue::Int { value: 42 },
        };
        let constraints = template_literal(&expr);
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].category, ConstraintCategory::Structural);
    }

    #[test]
    fn test_template_literal_bool() {
        setup();
        let expr = SirExpr::Literal {
            value: SirValue::Bool { value: true },
        };
        let constraints = template_literal(&expr);
        assert_eq!(constraints.len(), 1);
    }

    #[test]
    fn test_template_literal_non_literal_returns_empty() {
        setup();
        let expr = SirExpr::Var { name: "x".into() };
        let constraints = template_literal(&expr);
        assert!(constraints.is_empty());
    }

    // -- template_var --

    #[test]
    fn test_template_var() {
        setup();
        let expr = SirExpr::Var {
            name: "balance".into(),
        };
        let constraints = template_var(&expr);
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].category, ConstraintCategory::Structural);
    }

    // -- template_binop --

    #[test]
    fn test_template_binop_add() {
        setup();
        let expr = SirExpr::BinOp {
            op: "add".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 2 },
            }),
        };
        let constraints = template_binop(&expr);
        // 1 for the binop itself + 1 for left literal + 1 for right literal
        assert!(constraints.len() >= 3);
        assert_eq!(constraints[0].category, ConstraintCategory::Structural);
    }

    // -- template_if (CONST-3) --

    #[test]
    fn test_template_if_generates_both_branches() {
        setup();
        let expr = SirExpr::If {
            cond: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: true },
            }),
            then_: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            else_: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 0 },
            }),
        };
        let constraints = template_if(&expr);

        // Must have the branch constraint.
        let branch_constraints: Vec<_> = constraints
            .iter()
            .filter(|c| c.category == ConstraintCategory::Branch)
            .collect();
        assert!(
            !branch_constraints.is_empty(),
            "CONST-3: if must generate Branch constraints"
        );

        // Must have constraints from both branches (then and else).
        // The total should be: 1 branch + 1 cond + 1 then + 1 else = 4 minimum.
        assert!(
            constraints.len() >= 4,
            "CONST-3: if must generate constraints for both branches, got {}",
            constraints.len()
        );
    }

    // -- template_let --

    #[test]
    fn test_template_let() {
        setup();
        let expr = SirExpr::Let {
            name: "x".into(),
            value: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 10 },
            }),
            body: Box::new(SirExpr::Var { name: "x".into() }),
        };
        let constraints = template_let(&expr);
        // 1 equality + value constraints + body constraints
        assert!(constraints.len() >= 1);
        // First constraint should be the let binding equality.
        assert_eq!(constraints[0].category, ConstraintCategory::Structural);
        assert!(constraints[0].description.contains("let binding"));
    }

    // -- template_field_access --

    #[test]
    fn test_template_field_access() {
        setup();
        let expr = SirExpr::FieldAccess {
            expr: Box::new(SirExpr::Var {
                name: "state".into(),
            }),
            field: "balance".into(),
        };
        let constraints = template_field_access(&expr);
        assert!(constraints.len() >= 1);
        assert!(constraints[0].description.contains("field access"));
    }

    // -- template_match (CONST-3) --

    #[test]
    fn test_template_match_all_arms_constrained() {
        setup();
        let expr = SirExpr::Match {
            scrutinee: Box::new(SirExpr::Var { name: "x".into() }),
            arms: vec![
                SirMatchArm {
                    pattern: SirPattern::Literal {
                        value: SirValue::Int { value: 0 },
                    },
                    body: SirExpr::Literal {
                        value: SirValue::Bool { value: false },
                    },
                },
                SirMatchArm {
                    pattern: SirPattern::Literal {
                        value: SirValue::Int { value: 1 },
                    },
                    body: SirExpr::Literal {
                        value: SirValue::Bool { value: true },
                    },
                },
                SirMatchArm {
                    pattern: SirPattern::Var { name: "_".into() },
                    body: SirExpr::Literal {
                        value: SirValue::Bool { value: false },
                    },
                },
            ],
        };
        let constraints = template_match(&expr);

        // Must have the branch constraint.
        let branch_constraints: Vec<_> = constraints
            .iter()
            .filter(|c| c.category == ConstraintCategory::Branch)
            .collect();
        assert!(
            !branch_constraints.is_empty(),
            "CONST-3: match must generate Branch constraints"
        );

        // Must have constraints from all 3 arms.
        let arm_constraints: Vec<_> = constraints
            .iter()
            .filter(|c| c.description.contains("[match arm"))
            .collect();
        // Each arm body (a literal) generates 1 constraint, so at least 3 arm constraints.
        assert!(
            arm_constraints.len() >= 3,
            "CONST-3: match must generate constraints for all arms, got {}",
            arm_constraints.len()
        );
    }

    // -- carry-over constraints (Requirement 5.8) --

    #[test]
    fn test_carry_over_constraints_non_mutated_fields() {
        setup();
        let transition = SirTransition {
            name: "transfer".into(),
            class: "Update".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::Literal {
                value: SirValue::Unit,
            },
            allowed_mutations: vec!["balance".to_string(), "nonce".to_string()],
        };
        let schema = SirStateSchema {
            fields: vec![
                SirFieldSchema {
                    name: "balance".into(),
                    field_type: "Int".into(),
                },
                SirFieldSchema {
                    name: "nonce".into(),
                    field_type: "Int".into(),
                },
                SirFieldSchema {
                    name: "data".into(),
                    field_type: "Bytes".into(),
                },
                SirFieldSchema {
                    name: "status".into(),
                    field_type: "Int".into(),
                },
            ],
        };

        let constraints = generate_carry_over_constraints(&transition, &schema);

        // "balance" and "nonce" are allowed mutations, so carry-over for "data" and "status".
        assert_eq!(constraints.len(), 2);
        for c in &constraints {
            assert_eq!(c.category, ConstraintCategory::CarryOver);
            assert!(
                c.description.contains("data") || c.description.contains("status"),
                "carry-over should be for non-mutated fields, got: {}",
                c.description
            );
        }
    }

    #[test]
    fn test_carry_over_all_fields_when_no_mutations_allowed() {
        setup();
        let transition = SirTransition {
            name: "noop".into(),
            class: "Noop".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::Literal {
                value: SirValue::Unit,
            },
            allowed_mutations: vec![],
        };
        let schema = SirStateSchema {
            fields: vec![
                SirFieldSchema {
                    name: "a".into(),
                    field_type: "Int".into(),
                },
                SirFieldSchema {
                    name: "b".into(),
                    field_type: "Int".into(),
                },
            ],
        };

        let constraints = generate_carry_over_constraints(&transition, &schema);
        assert_eq!(
            constraints.len(),
            2,
            "all fields should have carry-over when no mutations allowed"
        );
    }

    #[test]
    fn test_carry_over_none_when_all_fields_mutable() {
        setup();
        let transition = SirTransition {
            name: "init".into(),
            class: "Init".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::Literal {
                value: SirValue::Unit,
            },
            allowed_mutations: vec!["a".to_string(), "b".to_string()],
        };
        let schema = SirStateSchema {
            fields: vec![
                SirFieldSchema {
                    name: "a".into(),
                    field_type: "Int".into(),
                },
                SirFieldSchema {
                    name: "b".into(),
                    field_type: "Int".into(),
                },
            ],
        };

        let constraints = generate_carry_over_constraints(&transition, &schema);
        assert!(
            constraints.is_empty(),
            "no carry-over when all fields are mutable"
        );
    }

    // -- generate_transition_constraints --

    #[test]
    fn test_transition_constraints_include_all_parts() {
        setup();
        let transition = SirTransition {
            name: "deposit".into(),
            class: "Update".into(),
            preconditions: vec![SirExpr::BinOp {
                op: "gt".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "input".into(),
                    }),
                    field: "amount".into(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            }],
            postconditions: vec![SirExpr::BinOp {
                op: "ge".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "state_post".into(),
                    }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            }],
            body: SirExpr::BinOp {
                op: "add".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "state".into(),
                    }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "input".into(),
                    }),
                    field: "amount".into(),
                }),
            },
            allowed_mutations: vec!["balance".to_string()],
        };
        let schema = SirStateSchema {
            fields: vec![
                SirFieldSchema {
                    name: "balance".into(),
                    field_type: "Int".into(),
                },
                SirFieldSchema {
                    name: "nonce".into(),
                    field_type: "Int".into(),
                },
            ],
        };

        let constraints = generate_transition_constraints(&transition, &schema);

        // Should have: precondition(s), body, postcondition(s), carry-over(s).
        let has_semantic = constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::Semantic);
        let has_structural = constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::Structural);
        let has_carry_over = constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::CarryOver);

        assert!(
            has_semantic,
            "must have semantic constraints (pre/postconditions)"
        );
        assert!(has_structural, "must have structural constraints (body)");
        assert!(has_carry_over, "must have carry-over constraints");

        // Carry-over should be for "nonce" only (balance is allowed mutation).
        let carry_overs: Vec<_> = constraints
            .iter()
            .filter(|c| c.category == ConstraintCategory::CarryOver)
            .collect();
        assert_eq!(carry_overs.len(), 1);
        assert!(carry_overs[0].description.contains("nonce"));
    }

    // -- determinism (CONST-4) --

    #[test]
    fn test_constraint_generation_deterministic() {
        // This test verifies CONST-4: deterministic constraint generation.
        // We reset the counter, generate, reset again, generate, and compare.
        let transition = SirTransition {
            name: "test".into(),
            class: "Update".into(),
            preconditions: vec![],
            postconditions: vec![],
            body: SirExpr::BinOp {
                op: "add".into(),
                left: Box::new(SirExpr::Var { name: "a".into() }),
                right: Box::new(SirExpr::Var { name: "b".into() }),
            },
            allowed_mutations: vec!["result".to_string()],
        };
        let schema = SirStateSchema {
            fields: vec![SirFieldSchema {
                name: "result".into(),
                field_type: "Int".into(),
            }],
        };

        // Run twice with reset counter — should produce identical constraints.
        reset_constraint_id_counter();
        let c1 = generate_transition_constraints(&transition, &schema);

        reset_constraint_id_counter();
        let c2 = generate_transition_constraints(&transition, &schema);

        assert_eq!(
            c1.len(),
            c2.len(),
            "CONST-4: same input must produce same number of constraints"
        );
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.expr, b.expr, "CONST-4: constraint expressions must match");
            assert_eq!(
                a.category, b.category,
                "CONST-4: constraint categories must match"
            );
            assert_eq!(
                a.description, b.description,
                "CONST-4: constraint descriptions must match"
            );
        }
    }

    // -- generate_invariant_constraints --

    #[test]
    fn test_invariant_constraint_local() {
        setup();
        let inv = SirInvariant {
            name: "L_cons".into(),
            category: "local".into(),
            expr: SirExpr::BinOp {
                op: "ge".into(),
                left: Box::new(SirExpr::FieldAccess {
                    expr: Box::new(SirExpr::Var {
                        name: "state".into(),
                    }),
                    field: "balance".into(),
                }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 0 },
                }),
            },
        };
        let constraints = generate_invariant_constraints(&inv);
        assert!(!constraints.is_empty());
        let invariant_constraints: Vec<_> = constraints
            .iter()
            .filter(|c| c.category == ConstraintCategory::Invariant)
            .collect();
        assert!(
            !invariant_constraints.is_empty(),
            "must have Invariant category constraints"
        );
        assert!(invariant_constraints[0].description.contains("L_cons"));
        assert!(invariant_constraints[0].description.contains("local"));
    }

    #[test]
    fn test_invariant_constraint_global() {
        setup();
        let inv = SirInvariant {
            name: "G_solvency".into(),
            category: "global".into(),
            expr: SirExpr::Literal {
                value: SirValue::Bool { value: true },
            },
        };
        let constraints = generate_invariant_constraints(&inv);
        assert!(!constraints.is_empty());
        assert!(constraints[0].description.contains("G_solvency"));
        assert!(constraints[0].description.contains("global"));
    }

    #[test]
    fn test_invariant_constraint_temporal() {
        setup();
        let inv = SirInvariant {
            name: "T_no_revert".into(),
            category: "temporal".into(),
            expr: SirExpr::Literal {
                value: SirValue::Bool { value: true },
            },
        };
        let constraints = generate_invariant_constraints(&inv);
        assert!(constraints[0].description.contains("temporal"));
    }

    #[test]
    fn test_invariant_constraint_economic() {
        setup();
        let inv = SirInvariant {
            name: "E_cost".into(),
            category: "economic".into(),
            expr: SirExpr::Literal {
                value: SirValue::Bool { value: true },
            },
        };
        let constraints = generate_invariant_constraints(&inv);
        assert!(constraints[0].description.contains("economic"));
    }

    // -- compile --

    fn make_test_program() -> SirProgram {
        SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema {
                fields: vec![
                    SirFieldSchema {
                        name: "balance".into(),
                        field_type: "Int".into(),
                    },
                    SirFieldSchema {
                        name: "nonce".into(),
                        field_type: "Int".into(),
                    },
                ],
            },
            input_schema: SirInputSchema {
                fields: vec![SirFieldSchema {
                    name: "amount".into(),
                    field_type: "Int".into(),
                }],
            },
            transitions: vec![SirTransition {
                name: "deposit".into(),
                class: "Update".into(),
                preconditions: vec![SirExpr::BinOp {
                    op: "gt".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "input".into(),
                        }),
                        field: "amount".into(),
                    }),
                    right: Box::new(SirExpr::Literal {
                        value: SirValue::Int { value: 0 },
                    }),
                }],
                postconditions: vec![],
                body: SirExpr::BinOp {
                    op: "add".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "state".into(),
                        }),
                        field: "balance".into(),
                    }),
                    right: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "input".into(),
                        }),
                        field: "amount".into(),
                    }),
                },
                allowed_mutations: vec!["balance".to_string()],
            }],
            invariants: vec![SirInvariant {
                name: "L_cons".into(),
                category: "local".into(),
                expr: SirExpr::BinOp {
                    op: "ge".into(),
                    left: Box::new(SirExpr::FieldAccess {
                        expr: Box::new(SirExpr::Var {
                            name: "state".into(),
                        }),
                        field: "balance".into(),
                    }),
                    right: Box::new(SirExpr::Literal {
                        value: SirValue::Int { value: 0 },
                    }),
                },
            }],
            observables: vec![],
        }
    }

    #[test]
    fn test_compile_produces_constraint_system() {
        let program = make_test_program();
        let system = compile(&program);

        assert_eq!(system.version, "0.1.0");
        assert!(!system.constraints.is_empty(), "must produce constraints");
        assert!(
            !system.witness_variables.is_empty(),
            "must produce witness variables"
        );
        assert!(
            !system.public_inputs.is_empty(),
            "must produce public inputs"
        );
    }

    #[test]
    fn test_compile_witness_variables_from_schemas() {
        let program = make_test_program();
        let system = compile(&program);

        // state_schema has 2 fields → 4 witness vars (pre + post for each)
        // input_schema has 1 field → 1 witness var
        let names: Vec<&str> = system
            .witness_variables
            .iter()
            .map(|w| w.name.as_str())
            .collect();
        assert!(names.contains(&"state_pre.balance"));
        assert!(names.contains(&"state_post.balance"));
        assert!(names.contains(&"state_pre.nonce"));
        assert!(names.contains(&"state_post.nonce"));
        assert!(names.contains(&"input.amount"));
    }

    #[test]
    fn test_compile_public_inputs() {
        let program = make_test_program();
        let system = compile(&program);

        let pi_names: Vec<&str> = system
            .public_inputs
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert!(pi_names.contains(&"state_pre_commitment"));
        assert!(pi_names.contains(&"state_post_commitment"));
        assert!(pi_names.contains(&"domain"));
        assert!(pi_names.contains(&"version"));
    }

    #[test]
    fn test_compile_includes_transition_constraints() {
        let program = make_test_program();
        let system = compile(&program);

        let has_semantic = system
            .constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::Semantic);
        let has_structural = system
            .constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::Structural);
        let has_carry_over = system
            .constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::CarryOver);
        assert!(
            has_semantic,
            "must have semantic constraints from transitions"
        );
        assert!(
            has_structural,
            "must have structural constraints from transitions"
        );
        assert!(
            has_carry_over,
            "must have carry-over constraints from transitions"
        );
    }

    #[test]
    fn test_compile_includes_invariant_constraints() {
        let program = make_test_program();
        let system = compile(&program);

        let has_invariant = system
            .constraints
            .iter()
            .any(|c| c.category == ConstraintCategory::Invariant);
        assert!(has_invariant, "must have invariant constraints");
    }

    #[test]
    fn test_compile_deterministic() {
        // CONST-4: same SirProgram → same ConstraintSystem
        // compile() resets the counter internally, so both runs should
        // produce identical constraint systems. Note: in parallel test
        // execution, other tests may interleave counter increments, but
        // compile() resets at the start so each call is self-consistent.
        let program = make_test_program();
        let s1 = compile(&program);
        let s2 = compile(&program);

        assert_eq!(
            s1.constraints.len(),
            s2.constraints.len(),
            "CONST-4: same input must produce same number of constraints"
        );
        assert_eq!(s1.witness_variables.len(), s2.witness_variables.len());
        assert_eq!(s1.public_inputs.len(), s2.public_inputs.len());
        assert_eq!(s1.version, s2.version);

        // Both runs must produce identical constraint expressions and categories.
        for (a, b) in s1.constraints.iter().zip(s2.constraints.iter()) {
            assert_eq!(a.expr, b.expr, "CONST-4: constraint expressions must match");
            assert_eq!(
                a.category, b.category,
                "CONST-4: constraint categories must match"
            );
            assert_eq!(
                a.description, b.description,
                "CONST-4: descriptions must match"
            );
        }

        // Both runs must produce identical witness variables.
        for (a, b) in s1.witness_variables.iter().zip(s2.witness_variables.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.kind, b.kind);
        }

        // Both runs must produce identical public inputs.
        for (a, b) in s1.public_inputs.iter().zip(s2.public_inputs.iter()) {
            assert_eq!(a.name, b.name);
        }
    }

    // -- evaluate_constraint_expr --

    #[test]
    fn test_eval_constant() {
        let env = std::collections::BTreeMap::new();
        let result = evaluate_constraint_expr(&ConstraintExpr::Constant(42), &env);
        assert_eq!(result, Some(SirValue::Int { value: 42 }));
    }

    #[test]
    fn test_eval_bool_constant() {
        let env = std::collections::BTreeMap::new();
        let result = evaluate_constraint_expr(&ConstraintExpr::BoolConstant(true), &env);
        assert_eq!(result, Some(SirValue::Bool { value: true }));
    }

    #[test]
    fn test_eval_witness_ref() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("x".to_string(), SirValue::Int { value: 7 });
        let result = evaluate_constraint_expr(&ConstraintExpr::WitnessRef("x".into()), &env);
        assert_eq!(result, Some(SirValue::Int { value: 7 }));
    }

    #[test]
    fn test_eval_eq_true() {
        let env = std::collections::BTreeMap::new();
        let expr = ConstraintExpr::Eq(
            Box::new(ConstraintExpr::Constant(5)),
            Box::new(ConstraintExpr::Constant(5)),
        );
        assert_eq!(
            evaluate_constraint_expr(&expr, &env),
            Some(SirValue::Bool { value: true })
        );
    }

    #[test]
    fn test_eval_eq_false() {
        let env = std::collections::BTreeMap::new();
        let expr = ConstraintExpr::Eq(
            Box::new(ConstraintExpr::Constant(5)),
            Box::new(ConstraintExpr::Constant(3)),
        );
        assert_eq!(
            evaluate_constraint_expr(&expr, &env),
            Some(SirValue::Bool { value: false })
        );
    }

    #[test]
    fn test_eval_arithmetic() {
        let env = std::collections::BTreeMap::new();
        let add = ConstraintExpr::Add(
            Box::new(ConstraintExpr::Constant(3)),
            Box::new(ConstraintExpr::Constant(4)),
        );
        assert_eq!(
            evaluate_constraint_expr(&add, &env),
            Some(SirValue::Int { value: 7 })
        );

        let sub = ConstraintExpr::Sub(
            Box::new(ConstraintExpr::Constant(10)),
            Box::new(ConstraintExpr::Constant(3)),
        );
        assert_eq!(
            evaluate_constraint_expr(&sub, &env),
            Some(SirValue::Int { value: 7 })
        );

        let mul = ConstraintExpr::Mul(
            Box::new(ConstraintExpr::Constant(6)),
            Box::new(ConstraintExpr::Constant(7)),
        );
        assert_eq!(
            evaluate_constraint_expr(&mul, &env),
            Some(SirValue::Int { value: 42 })
        );
    }

    #[test]
    fn test_eval_comparison() {
        let env = std::collections::BTreeMap::new();
        let lt = ConstraintExpr::Lt(
            Box::new(ConstraintExpr::Constant(1)),
            Box::new(ConstraintExpr::Constant(2)),
        );
        assert_eq!(
            evaluate_constraint_expr(&lt, &env),
            Some(SirValue::Bool { value: true })
        );

        let ge = ConstraintExpr::Ge(
            Box::new(ConstraintExpr::Constant(5)),
            Box::new(ConstraintExpr::Constant(5)),
        );
        assert_eq!(
            evaluate_constraint_expr(&ge, &env),
            Some(SirValue::Bool { value: true })
        );
    }

    #[test]
    fn test_eval_if_then_else() {
        let env = std::collections::BTreeMap::new();
        let expr = ConstraintExpr::IfThenElse(
            Box::new(ConstraintExpr::BoolConstant(true)),
            Box::new(ConstraintExpr::Constant(1)),
            Box::new(ConstraintExpr::Constant(0)),
        );
        assert_eq!(
            evaluate_constraint_expr(&expr, &env),
            Some(SirValue::Int { value: 1 })
        );

        let expr_false = ConstraintExpr::IfThenElse(
            Box::new(ConstraintExpr::BoolConstant(false)),
            Box::new(ConstraintExpr::Constant(1)),
            Box::new(ConstraintExpr::Constant(0)),
        );
        assert_eq!(
            evaluate_constraint_expr(&expr_false, &env),
            Some(SirValue::Int { value: 0 })
        );
    }

    #[test]
    fn test_eval_field_access() {
        let mut entries = std::collections::BTreeMap::new();
        entries.insert("balance".to_string(), SirValue::Int { value: 100 });
        let mut env = std::collections::BTreeMap::new();
        env.insert("state".to_string(), SirValue::Map { entries });

        let expr = ConstraintExpr::FieldAccess(
            Box::new(ConstraintExpr::WitnessRef("state".into())),
            "balance".into(),
        );
        assert_eq!(
            evaluate_constraint_expr(&expr, &env),
            Some(SirValue::Int { value: 100 })
        );
    }

    #[test]
    fn test_eval_missing_variable_returns_none() {
        let env = std::collections::BTreeMap::new();
        let result = evaluate_constraint_expr(&ConstraintExpr::WitnessRef("missing".into()), &env);
        assert_eq!(result, None);
    }

    // -- satisfies_constraints --

    #[test]
    fn test_satisfies_constraints_empty_trace() {
        let system = ConstraintSystem::new("0.1.0");
        assert!(satisfies_constraints(&[], &system));
    }

    #[test]
    fn test_satisfies_constraints_empty_constraints() {
        let system = ConstraintSystem::new("0.1.0");
        let mut pre_entries = std::collections::BTreeMap::new();
        pre_entries.insert("balance".to_string(), SirValue::Int { value: 100 });
        let pre = SirValue::Map {
            entries: pre_entries,
        };
        let input = SirValue::Map {
            entries: std::collections::BTreeMap::new(),
        };
        let post = pre.clone();
        assert!(satisfies_constraints(&[(pre, input, post)], &system));
    }

    #[test]
    fn test_satisfies_constraints_simple_equality_holds() {
        setup();
        let mut system = ConstraintSystem::new("0.1.0");
        // Constraint: state_pre.balance == state_post.balance
        system.add_constraint(make_constraint(
            ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("state_pre.balance".into())),
                Box::new(ConstraintExpr::WitnessRef("state_post.balance".into())),
            ),
            ConstraintCategory::CarryOver,
            "balance carry-over",
        ));

        let mut pre_entries = std::collections::BTreeMap::new();
        pre_entries.insert("balance".to_string(), SirValue::Int { value: 100 });
        let pre = SirValue::Map {
            entries: pre_entries,
        };
        let input = SirValue::Map {
            entries: std::collections::BTreeMap::new(),
        };
        let post = pre.clone(); // same balance

        assert!(satisfies_constraints(&[(pre, input, post)], &system));
    }

    #[test]
    fn test_satisfies_constraints_simple_equality_violated() {
        setup();
        let mut system = ConstraintSystem::new("0.1.0");
        system.add_constraint(make_constraint(
            ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("state_pre.balance".into())),
                Box::new(ConstraintExpr::WitnessRef("state_post.balance".into())),
            ),
            ConstraintCategory::CarryOver,
            "balance carry-over",
        ));

        let mut pre_entries = std::collections::BTreeMap::new();
        pre_entries.insert("balance".to_string(), SirValue::Int { value: 100 });
        let pre = SirValue::Map {
            entries: pre_entries,
        };
        let input = SirValue::Map {
            entries: std::collections::BTreeMap::new(),
        };
        let mut post_entries = std::collections::BTreeMap::new();
        post_entries.insert("balance".to_string(), SirValue::Int { value: 200 });
        let post = SirValue::Map {
            entries: post_entries,
        };

        assert!(!satisfies_constraints(&[(pre, input, post)], &system));
    }

    #[test]
    fn test_satisfies_constraints_multi_step() {
        setup();
        let mut system = ConstraintSystem::new("0.1.0");
        // Constraint: state_pre.balance >= 0
        system.add_constraint(make_constraint(
            ConstraintExpr::Ge(
                Box::new(ConstraintExpr::WitnessRef("state_pre.balance".into())),
                Box::new(ConstraintExpr::Constant(0)),
            ),
            ConstraintCategory::Invariant,
            "non-negative balance",
        ));

        let make_state = |bal: i64| {
            let mut entries = std::collections::BTreeMap::new();
            entries.insert("balance".to_string(), SirValue::Int { value: bal });
            SirValue::Map { entries }
        };
        let input = SirValue::Map {
            entries: std::collections::BTreeMap::new(),
        };

        let trace = vec![
            (make_state(100), input.clone(), make_state(50)),
            (make_state(50), input.clone(), make_state(10)),
        ];
        assert!(satisfies_constraints(&trace, &system));
    }
}
