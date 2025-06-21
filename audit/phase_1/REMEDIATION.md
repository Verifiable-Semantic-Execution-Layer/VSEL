# Phase 1 — Remediation Plan

**Phase:** 1 — Execution Ground Truth
**Findings Requiring Remediation:** 0 (blocking) | 2 (informational, carried from Phase 0)

---

## Carried Remediation Actions from Phase 0

### R-001: Install Lean 4 Toolchain (for F-001)

**Priority:** Before Phase 2 (Semantic Alignment) — Lean 4 proofs become critical at Phase 2.
**Owner:** Infrastructure / DevOps
**Status:** Open (carried from Phase 0)
**Action:**
1. Install `elan` (Lean 4 version manager): `curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh`
2. The `formal/lean-toolchain` file pins the Lean 4 version.
3. Run `lake build` in `formal/` to verify all foundation proofs compile.
4. Add `lake build` step to CI pipeline.

**Acceptance Criteria:** `lake build` completes with 0 errors in `formal/`.

---

### R-002: Install TLA+ TLC Model Checker (for F-002)

**Priority:** Before Phase 2 Checkpoint — TLA+ model checking validates behavioral properties.
**Owner:** Infrastructure / DevOps
**Status:** Open (carried from Phase 0)
**Action:**
1. Install TLA+ tools (TLC): download from https://github.com/tlaplus/tlaplus/releases or use `apt install tla-toolbox`.
2. Run `tlc Properties -config MC.cfg` in `tla/` directory.
3. Verify all properties pass.
4. Add TLC model checking step to CI pipeline.

**Acceptance Criteria:** `tlc Properties -config MC.cfg` completes with 0 invariant violations.

---

## Phase 1 Remediation Actions

No new remediation actions required. All Rust code compiles cleanly, all 284 tests pass, and no code defects were identified.

---

## No Code Remediation Required

All Phase 1 Rust code (execution engine, trace engine) compiles cleanly with zero warnings and all tests pass. No code changes are required for Phase 1 gate passage. The two informational findings carried from Phase 0 relate to external toolchain availability, not code defects.
