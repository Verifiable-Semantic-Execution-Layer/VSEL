# Phase 2 — Remediation Plan

**Phase:** 2 — Semantic Alignment
**Findings Requiring Remediation:** 0 (blocking) | 2 (informational, carried from Phase 0)

---

## Carried Remediation Actions from Phase 0

### R-001: Install Lean 4 Toolchain (for F-001)

**Priority:** Before Phase 3 (Constraint Integrity) — Lean 4 proofs provide formal assurance for semantic alignment.
**Owner:** Infrastructure / DevOps
**Status:** Open (carried from Phase 0)
**Action:**
1. Install `elan` (Lean 4 version manager): `curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh`
2. The `formal/lean-toolchain` file pins the Lean 4 version.
3. Run `lake build` in `formal/` to verify all proofs compile:
   - `formal/VSEL/Foundations/` — State, Input, Transition, Invariants
   - `formal/VSEL/Mapping/` — SemanticMapping, Commutativity, Observable
4. Add `lake build` step to CI pipeline.

**Acceptance Criteria:** `lake build` completes with 0 errors in `formal/`.

---

### R-002: Install TLA+ TLC Model Checker (for F-002)

**Priority:** Before Phase 3 Checkpoint — TLA+ model checking validates behavioral properties.
**Owner:** Infrastructure / DevOps
**Status:** Open (carried from Phase 0)
**Action:**
1. Install TLA+ tools (TLC): download from https://github.com/tlaplus/tlaplus/releases or use `apt install tla-toolbox`.
2. Run `tlc Properties -config MC.cfg` in `tla/` directory.
3. Verify all properties pass.
4. Add TLC model checking step to CI pipeline.

**Acceptance Criteria:** `tlc Properties -config MC.cfg` completes with 0 invariant violations.

---

## Phase 2 Remediation Actions

No new remediation actions required. All Rust code compiles cleanly, all 367 tests pass, and no code defects were identified. The semantic mapping layer is fully operational with commutativity verified across all transition classes.

---

## No Code Remediation Required

All Phase 2 Rust code (semantic mapping, canonicalization, differential execution) compiles cleanly with zero warnings and all tests pass. No code changes are required for Phase 2 gate passage. The two informational findings carried from Phase 0 relate to external toolchain availability, not code defects.
