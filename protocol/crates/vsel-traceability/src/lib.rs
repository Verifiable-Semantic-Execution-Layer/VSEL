//! vsel-traceability: Full derivation-chain traceability matrix.
//!
//! Maps the complete VSEL derivation chain:
//!   L0 Lean 4 invariants → L1 SIR/IR constructs → L2 Rust state machine
//!   transitions → L3 constraint IDs → L4 proof obligations → NIST controls
//!
//! Derived from: Requirements 16.1, 16.8
//!
//! Key invariant: **no broken traceability links**. Every L0 invariant must
//! trace through all layers to at least one NIST control. Any invariant
//! without a constraint, or constraint without a proof obligation, is flagged
//! as a gap requiring resolution.

pub mod chains;
pub mod compliance;
pub mod dependency;
pub mod evidence;
pub mod matrix;
pub mod nist;
pub mod obligations;
pub mod registry;
pub mod validation;
