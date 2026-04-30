"""
SIR/IR export tooling — Lean 4 → JSON/S-expr IR export.

Derived from: REFINEMENT_STRATEGY.md, TECH_SPEC.md, design.md Component 10.
Requirements: 9.7 — SIR/IR derivation pipeline.

This package implements the export pipeline that reads Lean 4 formal definitions
and produces deterministic JSON IR consumed by the Rust vsel-sir crate.

Key invariant: same Lean 4 definitions always produce the same IR (CONST-4).
"""
