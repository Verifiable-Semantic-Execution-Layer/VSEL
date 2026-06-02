//! SIR reference interpreter for differential testing.
//!
//! Derived from: Requirement 9.1, 9.2 — refinement chain and semantic preservation.
//!
//! This interpreter evaluates SIR expressions against a state represented as
//! `SirValue`. It serves as the reference implementation: the Rust concrete
//! execution engine must produce results equivalent to this interpreter for
//! every valid (state, input) pair (THM-1 commutativity).

use crate::types::*;

/// Errors that can occur during SIR interpretation.
#[derive(Debug, thiserror::Error)]
pub enum InterpreterError {
    #[error("undefined variable: {0}")]
    UndefinedVariable(String),

    #[error("type error: {0}")]
    TypeError(String),

    #[error("field not found: {0}")]
    FieldNotFound(String),

    #[error("no matching arm in match expression")]
    NoMatchingArm,

    #[error("unknown builtin function: {0}")]
    UnknownFunction(String),
}

/// Reference SIR interpreter.
///
/// Evaluates SIR expressions in a pure, deterministic manner.
/// Used for differential testing against the Rust concrete execution engine.
pub struct Interpreter;

impl Interpreter {
    pub fn new() -> Self {
        Self
    }

    /// Execute a SIR program: find the named transition, check preconditions,
    /// evaluate the body, and return the resulting state value.
    pub fn execute(
        &self,
        program: &SirProgram,
        transition_name: &str,
        state: &SirValue,
        input: &SirValue,
    ) -> Result<SirValue, InterpreterError> {
        let transition = program
            .transitions
            .iter()
            .find(|t| t.name == transition_name)
            .ok_or_else(|| {
                InterpreterError::UnknownFunction(format!(
                    "transition '{}' not found",
                    transition_name
                ))
            })?;

        let env = SirEnv::new()
            .extend("state".into(), state.clone())
            .extend("input".into(), input.clone());

        // Check all preconditions.
        for pre in &transition.preconditions {
            let result = self.eval(pre, &env)?;
            match result {
                SirValue::Bool { value: true } => {}
                SirValue::Bool { value: false } => {
                    return Err(InterpreterError::TypeError(format!(
                        "precondition failed for transition '{}'",
                        transition_name
                    )));
                }
                _ => {
                    return Err(InterpreterError::TypeError(
                        "precondition must evaluate to Bool".into(),
                    ));
                }
            }
        }

        // Evaluate the transition body.
        self.eval(&transition.body, &env)
    }

    /// Check whether an invariant holds for the given state.
    pub fn check_invariant(
        &self,
        invariant: &SirInvariant,
        state: &SirValue,
    ) -> Result<bool, InterpreterError> {
        let env = SirEnv::new().extend("state".into(), state.clone());
        let result = self.eval(&invariant.expr, &env)?;
        match result {
            SirValue::Bool { value } => Ok(value),
            _ => Err(InterpreterError::TypeError(
                "invariant must evaluate to Bool".into(),
            )),
        }
    }

    /// Evaluate a SIR expression in the given environment.
    pub fn eval(&self, expr: &SirExpr, env: &SirEnv) -> Result<SirValue, InterpreterError> {
        match expr {
            SirExpr::Literal { value } => Ok(value.clone()),

            SirExpr::Var { name } => env
                .get(name)
                .cloned()
                .ok_or_else(|| InterpreterError::UndefinedVariable(name.clone())),

            SirExpr::Let { name, value, body } => {
                let val = self.eval(value, env)?;
                let new_env = env.extend(name.clone(), val);
                self.eval(body, &new_env)
            }

            SirExpr::If { cond, then_, else_ } => {
                let c = self.eval(cond, env)?;
                match c {
                    SirValue::Bool { value: true } => self.eval(then_, env),
                    SirValue::Bool { value: false } => self.eval(else_, env),
                    _ => Err(InterpreterError::TypeError(
                        "if condition must be Bool".into(),
                    )),
                }
            }

            SirExpr::FieldAccess { expr, field } => {
                let val = self.eval(expr, env)?;
                match val {
                    SirValue::Map { entries } => entries
                        .get(field)
                        .cloned()
                        .ok_or_else(|| InterpreterError::FieldNotFound(field.clone())),
                    _ => Err(InterpreterError::TypeError(
                        "field access requires a Map value".into(),
                    )),
                }
            }

            SirExpr::BinOp { op, left, right } => {
                let l = self.eval(left, env)?;
                let r = self.eval(right, env)?;
                self.eval_binop(op, &l, &r)
            }

            SirExpr::Apply { func, args } => {
                // Evaluate function expression — must be a Var naming a builtin.
                let func_name = match func.as_ref() {
                    SirExpr::Var { name } => name.clone(),
                    _ => {
                        return Err(InterpreterError::TypeError(
                            "Apply func must be a Var naming a builtin".into(),
                        ))
                    }
                };
                let evaluated_args: Vec<SirValue> = args
                    .iter()
                    .map(|a| self.eval(a, env))
                    .collect::<Result<_, _>>()?;
                self.eval_builtin(&func_name, &evaluated_args)
            }

            SirExpr::Match { scrutinee, arms } => {
                let val = self.eval(scrutinee, env)?;
                for arm in arms {
                    match &arm.pattern {
                        SirPattern::Literal { value } => {
                            if *value == val {
                                return self.eval(&arm.body, env);
                            }
                        }
                        SirPattern::Var { name } => {
                            let new_env = env.extend(name.clone(), val);
                            return self.eval(&arm.body, &new_env);
                        }
                    }
                }
                Err(InterpreterError::NoMatchingArm)
            }
        }
    }

    /// Evaluate a binary operation on two SIR values.
    fn eval_binop(
        &self,
        op: &str,
        left: &SirValue,
        right: &SirValue,
    ) -> Result<SirValue, InterpreterError> {
        match (op, left, right) {
            // Arithmetic on integers.
            ("add", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Int { value: a + b })
            }
            ("sub", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Int { value: a - b })
            }
            ("mul", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Int { value: a * b })
            }
            ("div", SirValue::Int { value: _ }, SirValue::Int { value: 0 }) => {
                Err(InterpreterError::TypeError("division by zero".into()))
            }
            ("div", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Int { value: a / b })
            }
            ("mod", SirValue::Int { value: _ }, SirValue::Int { value: 0 }) => {
                Err(InterpreterError::TypeError("modulo by zero".into()))
            }
            ("mod", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Int { value: a % b })
            }

            // Comparison on integers.
            ("eq", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a == b })
            }
            ("neq", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a != b })
            }
            ("lt", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a < b })
            }
            ("le", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a <= b })
            }
            ("gt", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a > b })
            }
            ("ge", SirValue::Int { value: a }, SirValue::Int { value: b }) => {
                Ok(SirValue::Bool { value: a >= b })
            }

            // Boolean logic.
            ("and", SirValue::Bool { value: a }, SirValue::Bool { value: b }) => {
                Ok(SirValue::Bool { value: *a && *b })
            }
            ("or", SirValue::Bool { value: a }, SirValue::Bool { value: b }) => {
                Ok(SirValue::Bool { value: *a || *b })
            }

            // Equality on booleans.
            ("eq", SirValue::Bool { value: a }, SirValue::Bool { value: b }) => {
                Ok(SirValue::Bool { value: a == b })
            }
            ("neq", SirValue::Bool { value: a }, SirValue::Bool { value: b }) => {
                Ok(SirValue::Bool { value: a != b })
            }

            _ => Err(InterpreterError::TypeError(format!(
                "unsupported binop '{}' on {:?} and {:?}",
                op, left, right
            ))),
        }
    }

    /// Evaluate a builtin function call.
    fn eval_builtin(&self, name: &str, args: &[SirValue]) -> Result<SirValue, InterpreterError> {
        match name {
            "not" => {
                if args.len() != 1 {
                    return Err(InterpreterError::TypeError(
                        "not expects exactly 1 argument".into(),
                    ));
                }
                match &args[0] {
                    SirValue::Bool { value } => Ok(SirValue::Bool { value: !value }),
                    _ => Err(InterpreterError::TypeError(
                        "not expects a Bool argument".into(),
                    )),
                }
            }
            "len" => {
                if args.len() != 1 {
                    return Err(InterpreterError::TypeError(
                        "len expects exactly 1 argument".into(),
                    ));
                }
                match &args[0] {
                    SirValue::List { elements } => Ok(SirValue::Int {
                        value: elements.len() as i64,
                    }),
                    SirValue::Bytes { value } => Ok(SirValue::Int {
                        value: value.len() as i64,
                    }),
                    SirValue::Map { entries } => Ok(SirValue::Int {
                        value: entries.len() as i64,
                    }),
                    _ => Err(InterpreterError::TypeError(
                        "len expects a List, Bytes, or Map argument".into(),
                    )),
                }
            }
            "abs" => {
                if args.len() != 1 {
                    return Err(InterpreterError::TypeError(
                        "abs expects exactly 1 argument".into(),
                    ));
                }
                match &args[0] {
                    SirValue::Int { value } => Ok(SirValue::Int { value: value.abs() }),
                    _ => Err(InterpreterError::TypeError(
                        "abs expects an Int argument".into(),
                    )),
                }
            }
            _ => Err(InterpreterError::UnknownFunction(name.into())),
        }
    }
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn interp() -> Interpreter {
        Interpreter::new()
    }

    fn env_with(name: &str, val: SirValue) -> SirEnv {
        SirEnv::new().extend(name.into(), val)
    }

    // -- eval: literals and variables --

    #[test]
    fn test_eval_literal() {
        let expr = SirExpr::Literal {
            value: SirValue::Int { value: 42 },
        };
        let result = interp().eval(&expr, &SirEnv::new()).unwrap();
        assert_eq!(result, SirValue::Int { value: 42 });
    }

    #[test]
    fn test_eval_var() {
        let env = env_with("x", SirValue::Int { value: 7 });
        let expr = SirExpr::Var { name: "x".into() };
        let result = interp().eval(&expr, &env).unwrap();
        assert_eq!(result, SirValue::Int { value: 7 });
    }

    #[test]
    fn test_eval_undefined_var() {
        let expr = SirExpr::Var {
            name: "missing".into(),
        };
        let result = interp().eval(&expr, &SirEnv::new());
        assert!(result.is_err());
    }

    // -- eval: let bindings --

    #[test]
    fn test_eval_let() {
        let expr = SirExpr::Let {
            name: "y".into(),
            value: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 10 },
            }),
            body: Box::new(SirExpr::BinOp {
                op: "add".into(),
                left: Box::new(SirExpr::Var { name: "y".into() }),
                right: Box::new(SirExpr::Literal {
                    value: SirValue::Int { value: 5 },
                }),
            }),
        };
        let result = interp().eval(&expr, &SirEnv::new()).unwrap();
        assert_eq!(result, SirValue::Int { value: 15 });
    }

    // -- eval: if --

    #[test]
    fn test_eval_if_true() {
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
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Int { value: 1 }
        );
    }

    #[test]
    fn test_eval_if_false() {
        let expr = SirExpr::If {
            cond: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: false },
            }),
            then_: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            else_: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 0 },
            }),
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Int { value: 0 }
        );
    }

    #[test]
    fn test_eval_if_non_bool_cond() {
        let expr = SirExpr::If {
            cond: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            then_: Box::new(SirExpr::Literal {
                value: SirValue::Unit,
            }),
            else_: Box::new(SirExpr::Literal {
                value: SirValue::Unit,
            }),
        };
        assert!(interp().eval(&expr, &SirEnv::new()).is_err());
    }

    // -- eval: binops --

    #[test]
    fn test_eval_binop_arithmetic() {
        let env = SirEnv::new();
        let i = interp();

        let add = SirExpr::BinOp {
            op: "add".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 3 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 4 },
            }),
        };
        assert_eq!(i.eval(&add, &env).unwrap(), SirValue::Int { value: 7 });

        let sub = SirExpr::BinOp {
            op: "sub".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 10 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 3 },
            }),
        };
        assert_eq!(i.eval(&sub, &env).unwrap(), SirValue::Int { value: 7 });

        let mul = SirExpr::BinOp {
            op: "mul".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 6 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 7 },
            }),
        };
        assert_eq!(i.eval(&mul, &env).unwrap(), SirValue::Int { value: 42 });

        let div = SirExpr::BinOp {
            op: "div".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 10 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 3 },
            }),
        };
        assert_eq!(i.eval(&div, &env).unwrap(), SirValue::Int { value: 3 });
    }

    #[test]
    fn test_eval_binop_div_by_zero() {
        let expr = SirExpr::BinOp {
            op: "div".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 0 },
            }),
        };
        assert!(interp().eval(&expr, &SirEnv::new()).is_err());
    }

    #[test]
    fn test_eval_binop_comparison() {
        let env = SirEnv::new();
        let i = interp();

        let lt = SirExpr::BinOp {
            op: "lt".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 2 },
            }),
        };
        assert_eq!(i.eval(&lt, &env).unwrap(), SirValue::Bool { value: true });

        let gt = SirExpr::BinOp {
            op: "gt".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 2 },
            }),
        };
        assert_eq!(i.eval(&gt, &env).unwrap(), SirValue::Bool { value: false });

        let eq = SirExpr::BinOp {
            op: "eq".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 5 },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 5 },
            }),
        };
        assert_eq!(i.eval(&eq, &env).unwrap(), SirValue::Bool { value: true });
    }

    #[test]
    fn test_eval_binop_boolean_logic() {
        let env = SirEnv::new();
        let i = interp();

        let and_expr = SirExpr::BinOp {
            op: "and".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: true },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: false },
            }),
        };
        assert_eq!(
            i.eval(&and_expr, &env).unwrap(),
            SirValue::Bool { value: false }
        );

        let or_expr = SirExpr::BinOp {
            op: "or".into(),
            left: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: false },
            }),
            right: Box::new(SirExpr::Literal {
                value: SirValue::Bool { value: true },
            }),
        };
        assert_eq!(
            i.eval(&or_expr, &env).unwrap(),
            SirValue::Bool { value: true }
        );
    }

    // -- eval: field access --

    #[test]
    fn test_eval_field_access() {
        let mut entries = BTreeMap::new();
        entries.insert("balance".into(), SirValue::Int { value: 100 });
        let env = env_with("state", SirValue::Map { entries });

        let expr = SirExpr::FieldAccess {
            expr: Box::new(SirExpr::Var {
                name: "state".into(),
            }),
            field: "balance".into(),
        };
        assert_eq!(
            interp().eval(&expr, &env).unwrap(),
            SirValue::Int { value: 100 }
        );
    }

    #[test]
    fn test_eval_field_access_missing() {
        let entries = BTreeMap::new();
        let env = env_with("state", SirValue::Map { entries });

        let expr = SirExpr::FieldAccess {
            expr: Box::new(SirExpr::Var {
                name: "state".into(),
            }),
            field: "missing".into(),
        };
        assert!(interp().eval(&expr, &env).is_err());
    }

    #[test]
    fn test_eval_field_access_non_map() {
        let env = env_with("x", SirValue::Int { value: 1 });
        let expr = SirExpr::FieldAccess {
            expr: Box::new(SirExpr::Var { name: "x".into() }),
            field: "f".into(),
        };
        assert!(interp().eval(&expr, &env).is_err());
    }

    // -- eval: match --

    #[test]
    fn test_eval_match_literal() {
        let expr = SirExpr::Match {
            scrutinee: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 1 },
            }),
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
            ],
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Bool { value: true }
        );
    }

    #[test]
    fn test_eval_match_wildcard() {
        let expr = SirExpr::Match {
            scrutinee: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 99 },
            }),
            arms: vec![SirMatchArm {
                pattern: SirPattern::Var { name: "x".into() },
                body: SirExpr::Var { name: "x".into() },
            }],
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Int { value: 99 }
        );
    }

    #[test]
    fn test_eval_match_no_arm() {
        let expr = SirExpr::Match {
            scrutinee: Box::new(SirExpr::Literal {
                value: SirValue::Int { value: 5 },
            }),
            arms: vec![SirMatchArm {
                pattern: SirPattern::Literal {
                    value: SirValue::Int { value: 0 },
                },
                body: SirExpr::Literal {
                    value: SirValue::Unit,
                },
            }],
        };
        assert!(interp().eval(&expr, &SirEnv::new()).is_err());
    }

    // -- eval: apply (builtins) --

    #[test]
    fn test_eval_builtin_not() {
        let expr = SirExpr::Apply {
            func: Box::new(SirExpr::Var { name: "not".into() }),
            args: vec![SirExpr::Literal {
                value: SirValue::Bool { value: true },
            }],
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Bool { value: false }
        );
    }

    #[test]
    fn test_eval_builtin_len() {
        let expr = SirExpr::Apply {
            func: Box::new(SirExpr::Var { name: "len".into() }),
            args: vec![SirExpr::Literal {
                value: SirValue::List {
                    elements: vec![SirValue::Int { value: 1 }, SirValue::Int { value: 2 }],
                },
            }],
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Int { value: 2 }
        );
    }

    #[test]
    fn test_eval_builtin_abs() {
        let expr = SirExpr::Apply {
            func: Box::new(SirExpr::Var { name: "abs".into() }),
            args: vec![SirExpr::Literal {
                value: SirValue::Int { value: -7 },
            }],
        };
        assert_eq!(
            interp().eval(&expr, &SirEnv::new()).unwrap(),
            SirValue::Int { value: 7 }
        );
    }

    #[test]
    fn test_eval_unknown_builtin() {
        let expr = SirExpr::Apply {
            func: Box::new(SirExpr::Var {
                name: "unknown_fn".into(),
            }),
            args: vec![],
        };
        assert!(interp().eval(&expr, &SirEnv::new()).is_err());
    }

    // -- execute: full transition --

    #[test]
    fn test_execute_transition() {
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: "increment".into(),
                class: "Update".into(),
                preconditions: vec![],
                postconditions: vec![],
                body: SirExpr::BinOp {
                    op: "add".into(),
                    left: Box::new(SirExpr::Var {
                        name: "state".into(),
                    }),
                    right: Box::new(SirExpr::Literal {
                        value: SirValue::Int { value: 1 },
                    }),
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![],
            observables: vec![],
        };

        let result = interp()
            .execute(
                &program,
                "increment",
                &SirValue::Int { value: 10 },
                &SirValue::Unit,
            )
            .unwrap();
        assert_eq!(result, SirValue::Int { value: 11 });
    }

    #[test]
    fn test_execute_transition_not_found() {
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![],
            invariants: vec![],
            observables: vec![],
        };
        let result = interp().execute(&program, "missing", &SirValue::Unit, &SirValue::Unit);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_precondition_failure() {
        let program = SirProgram {
            version: "0.1.0".into(),
            state_schema: SirStateSchema { fields: vec![] },
            input_schema: SirInputSchema { fields: vec![] },
            transitions: vec![SirTransition {
                name: "guarded".into(),
                class: "Update".into(),
                preconditions: vec![SirExpr::Literal {
                    value: SirValue::Bool { value: false },
                }],
                postconditions: vec![],
                body: SirExpr::Literal {
                    value: SirValue::Unit,
                },
                allowed_mutations: vec![],
            }],
            invariants: vec![],
            observables: vec![],
        };
        let result = interp().execute(&program, "guarded", &SirValue::Unit, &SirValue::Unit);
        assert!(result.is_err());
    }

    // -- check_invariant --

    #[test]
    fn test_check_invariant_holds() {
        let inv = SirInvariant {
            name: "always_true".into(),
            category: "local".into(),
            expr: SirExpr::Literal {
                value: SirValue::Bool { value: true },
            },
        };
        assert!(interp().check_invariant(&inv, &SirValue::Unit).unwrap());
    }

    #[test]
    fn test_check_invariant_violated() {
        let inv = SirInvariant {
            name: "always_false".into(),
            category: "local".into(),
            expr: SirExpr::Literal {
                value: SirValue::Bool { value: false },
            },
        };
        assert!(!interp().check_invariant(&inv, &SirValue::Unit).unwrap());
    }

    #[test]
    fn test_check_invariant_with_state() {
        let mut entries = BTreeMap::new();
        entries.insert("balance".into(), SirValue::Int { value: 100 });
        let state = SirValue::Map { entries };

        let inv = SirInvariant {
            name: "positive_balance".into(),
            category: "local".into(),
            expr: SirExpr::BinOp {
                op: "gt".into(),
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
        assert!(interp().check_invariant(&inv, &state).unwrap());
    }
}
