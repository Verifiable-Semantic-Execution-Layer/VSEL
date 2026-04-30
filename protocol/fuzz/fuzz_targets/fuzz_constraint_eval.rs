//! Fuzz target: ConstraintExpr tree construction and evaluation.
//!
//! Accepts arbitrary bytes, constructs ConstraintExpr trees from the byte
//! stream, and evaluates them. Must not panic on any input.
//!
//! Requirements: 6.1(b), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use vsel_constraints::ConstraintExpr;
use vsel_constraints::compiler::evaluate_constraint_expr;
use vsel_sir::types::SirValue;

/// Maximum tree depth to prevent stack overflow from deeply nested expressions.
const MAX_DEPTH: usize = 32;

fuzz_target!(|data: &[u8]| {
    // Build a ConstraintExpr tree from the fuzz input.
    let mut cursor = 0usize;
    let expr = match build_expr(data, &mut cursor, 0) {
        Some(e) => e,
        None => return,
    };

    // Build a minimal environment with some named variables.
    let mut env = BTreeMap::new();
    env.insert("x".to_string(), SirValue::Int { value: 42 });
    env.insert("y".to_string(), SirValue::Int { value: 0 });
    env.insert("z".to_string(), SirValue::Int { value: -1 });
    env.insert("flag".to_string(), SirValue::Bool { value: true });

    // Evaluate — must not panic. Result may be None (unresolvable ref).
    let _ = evaluate_constraint_expr(&expr, &env);
});

/// Read one byte from data, advancing cursor. Returns None if exhausted.
fn read_byte(data: &[u8], cursor: &mut usize) -> Option<u8> {
    if *cursor >= data.len() {
        return None;
    }
    let b = data[*cursor];
    *cursor += 1;
    Some(b)
}

/// Read a u16 LE from data. Returns None if not enough bytes.
fn read_i64(data: &[u8], cursor: &mut usize) -> Option<i64> {
    if *cursor + 8 > data.len() {
        return None;
    }
    let val = i64::from_le_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
        data[*cursor + 4],
        data[*cursor + 5],
        data[*cursor + 6],
        data[*cursor + 7],
    ]);
    *cursor += 8;
    Some(val)
}

/// Build a ConstraintExpr tree from the byte stream.
///
/// Uses the first byte as a tag to select the variant, then recursively
/// builds sub-expressions. Depth-limited to prevent stack overflow.
fn build_expr(data: &[u8], cursor: &mut usize, depth: usize) -> Option<ConstraintExpr> {
    if depth >= MAX_DEPTH {
        // At max depth, emit a leaf node.
        return Some(ConstraintExpr::Constant(0));
    }

    let tag = read_byte(data, cursor)?;

    match tag % 18 {
        // Leaf nodes
        0 => {
            let val = read_i64(data, cursor)?;
            Some(ConstraintExpr::Constant(val))
        }
        1 => {
            let b = read_byte(data, cursor)?;
            Some(ConstraintExpr::BoolConstant(b % 2 == 0))
        }
        2 => {
            // WitnessRef — pick from a small set of known names.
            let idx = read_byte(data, cursor)? % 4;
            let name = match idx {
                0 => "x",
                1 => "y",
                2 => "z",
                _ => "flag",
            };
            Some(ConstraintExpr::WitnessRef(name.to_string()))
        }
        3 => {
            let idx = read_byte(data, cursor)? % 4;
            let name = match idx {
                0 => "x",
                1 => "y",
                2 => "z",
                _ => "flag",
            };
            Some(ConstraintExpr::PublicInputRef(name.to_string()))
        }

        // Binary nodes
        4 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Eq(Box::new(lhs), Box::new(rhs)))
        }
        5 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Neq(Box::new(lhs), Box::new(rhs)))
        }
        6 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Lt(Box::new(lhs), Box::new(rhs)))
        }
        7 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Le(Box::new(lhs), Box::new(rhs)))
        }
        8 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Gt(Box::new(lhs), Box::new(rhs)))
        }
        9 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Ge(Box::new(lhs), Box::new(rhs)))
        }
        10 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Add(Box::new(lhs), Box::new(rhs)))
        }
        11 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Sub(Box::new(lhs), Box::new(rhs)))
        }
        12 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Mul(Box::new(lhs), Box::new(rhs)))
        }
        13 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::And(Box::new(lhs), Box::new(rhs)))
        }
        14 => {
            let lhs = build_expr(data, cursor, depth + 1)?;
            let rhs = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::Or(Box::new(lhs), Box::new(rhs)))
        }

        // Ternary node
        15 => {
            let cond = build_expr(data, cursor, depth + 1)?;
            let then_ = build_expr(data, cursor, depth + 1)?;
            let else_ = build_expr(data, cursor, depth + 1)?;
            Some(ConstraintExpr::IfThenElse(
                Box::new(cond),
                Box::new(then_),
                Box::new(else_),
            ))
        }

        // FieldAccess
        16 => {
            let base = build_expr(data, cursor, depth + 1)?;
            let idx = read_byte(data, cursor)? % 3;
            let field = match idx {
                0 => "balance",
                1 => "nonce",
                _ => "status",
            };
            Some(ConstraintExpr::FieldAccess(
                Box::new(base),
                field.to_string(),
            ))
        }

        // Default: constant leaf
        _ => Some(ConstraintExpr::Constant(0)),
    }
}
