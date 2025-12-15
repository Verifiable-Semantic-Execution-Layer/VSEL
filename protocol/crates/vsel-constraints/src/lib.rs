//! vsel-constraints: Constraint compiler (SIR/IR → constraints), coverage matrix, underconstraint analysis.
//! Derived from CONSTRAINT_DERIVATION.md, UNDERCONSTRAINT_ANALYSIS.md.

pub mod compiler;
pub mod coverage;
pub mod underconstraint;

// Re-export key types for ergonomic use.
pub use compiler::{
    Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
    PublicInput, WitnessVariable, WitnessVariableKind,
    compile, satisfies_constraints,
};

pub use coverage::{
    CoverageCell, CoverageFinding, CoverageLevel, CoverageMatrix, FindingType,
    build_coverage_matrix,
};

pub use underconstraint::{
    UnderconstraintReport,
    analyze as analyze_underconstraints,
    extract_variable_refs,
};
