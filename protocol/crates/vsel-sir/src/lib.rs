//! vsel-sir: SIR/IR deserialization and reference interpreter for differential testing.
//! Derived from REFINEMENT_STRATEGY.md, TECH_SPEC.md, Requirements 9.1, 9.2, 9.7.

pub mod deserialize;
pub mod interpreter;
pub mod types;

pub use deserialize::*;
pub use interpreter::*;
pub use types::*;
