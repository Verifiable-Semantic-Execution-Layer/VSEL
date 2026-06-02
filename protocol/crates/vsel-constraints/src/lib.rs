//! vsel-constraints: Constraint compiler (SIR/IR → constraints), coverage matrix, underconstraint analysis.
//! Derived from CONSTRAINT_DERIVATION.md, UNDERCONSTRAINT_ANALYSIS.md.

pub mod compiler;
pub mod coverage;
pub mod underconstraint;

// Re-export key types for ergonomic use.
pub use compiler::{
    compile, satisfies_constraints, Constraint, ConstraintCategory, ConstraintExpr, ConstraintId,
    ConstraintSystem, PublicInput, WitnessVariable, WitnessVariableKind,
};

pub use coverage::{
    build_coverage_matrix, CoverageCell, CoverageFinding, CoverageLevel, CoverageMatrix,
    FindingType,
};

pub use underconstraint::{
    analyze as analyze_underconstraints, extract_variable_refs, UnderconstraintReport,
};
