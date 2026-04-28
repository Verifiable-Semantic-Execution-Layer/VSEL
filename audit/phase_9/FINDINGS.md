# Phase 9 — System Hardening Findings

**Phase:** 9 — System Hardening
**Date:** 2026-04-21

---

## Finding F-001: Poseidon Domain Separation Collision

**Severity:** Critical
**Category:** Cryptographic Integrity
**Status:** REMEDIATED
**Discovered By:** Property test `prop_domain_separation_all_algorithms` (Property 46c)

### Description

The `domain_hash_with_algorithm` function in `protocol/crates/vsel-crypto/src/hash.rs` used simple byte concatenation (`domain_bytes || data`) for Poseidon domain separation. This allowed two distinct domain tags to produce identical Poseidon hashes for the same data under adversarial inputs.

### Root Cause

The simplified Poseidon sponge construction uses a 4 × u64 state with wrapping arithmetic (`x^5 mod 2^64` S-box, simplified MDS matrix). When domain and data bytes are concatenated into a single absorption stream, the sponge processes them as a continuous byte sequence. The wrapping arithmetic does not provide the algebraic collision resistance properties of field-native Poseidon implementations, allowing state collisions after the permutation rounds.

### Impact

- **PROOF-3 (Domain Separation):** Proofs from different domains could potentially produce identical Poseidon-based commitments, weakening cross-protocol isolation.
- **Scope:** Limited to the Poseidon hash algorithm path only. SHA3-256 and BLAKE3 domain separation were unaffected and correctly produced distinct hashes for distinct domains.
- **Production Impact:** The Poseidon hash is designated for STARK-internal use (proof circuits). State commitments and trace commitments use SHA3-256/BLAKE3, which were not affected.

### Remediation

Replaced concatenation-based domain separation with a SHA3-256-derived domain IV approach:

```rust
// Before (vulnerable):
let mut input = Vec::with_capacity(32 + data.len());
input.extend_from_slice(&(domain.0).0);
input.extend_from_slice(data);
poseidon_hash(&input)

// After (fixed):
let domain_iv = SHA3_256("VSEL::poseidon::domain_iv::" || domain_tag_bytes);
let mut state = PoseidonState::new();
// Load IV directly into state words
state.state = domain_iv_as_u64_words;
state.permute();  // commit domain IV
state.absorb(data);
state.permute();
Hash(state.squeeze())
```

### Verification

- All 15 crypto property tests pass after remediation
- `prop_domain_separation_all_algorithms`: 100 adversarial cases, all pass
- `prop_domain_separation_sha3`: 100 cases, all pass (unaffected)
- `prop_domain_separation_blake3`: 100 cases, all pass (unaffected)

---

## Finding F-002 (Carried): TLC Model Checker Not Installed

**Severity:** Informational
**Category:** Tooling
**Status:** ACKNOWLEDGED (carried from Phase 0)

### Description

The TLC model checker is not installed in the current development environment. TLA+ models (`tla/StateMachine.tla`, `tla/Invariants.tla`, `tla/TransitionPartitioning.tla`, `tla/TemporalProperties.tla`, `tla/Composition.tla`) have been structurally reviewed but not executed via TLC.

### Mitigation

All properties modeled in TLA+ have equivalent Rust property-based tests with ≥100 cases each, providing runtime verification of the same properties. TLC execution is recommended for CI integration in Phase 10.

---

## Finding F-003: Python Static Analysis Model Granularity

**Severity:** Informational
**Category:** Tooling
**Status:** ACKNOWLEDGED

### Description

The Python static analysis tool (`tools/analysis/static_analysis.py`) reports 23 "orphan constraints" and 28 connected components in the constraint graph. This is an artifact of the simplified Python model where invariant constraints reference parent variable names (`state_pre`, `state_post`) rather than dotted field names (`state_pre.balance`, etc.), creating apparent disconnections in the bipartite graph.

### Mitigation

The actual Rust constraint system enforces these constraints correctly through the invariant checks. CONST-1 (zero free variables) passes. The Python model should be refined to match the Rust constraint system's variable naming granularity for more accurate static analysis.

---

## Summary

| ID | Severity | Category | Status |
|----|----------|----------|--------|
| F-001 | Critical | Cryptographic Integrity | **REMEDIATED** |
| F-002 | Informational | Tooling | ACKNOWLEDGED (carried) |
| F-003 | Informational | Tooling | ACKNOWLEDGED |

**Unresolved findings (severity ≥ Serious): 0**
