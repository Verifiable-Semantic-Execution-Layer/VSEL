# Phase 0 — Remediation Plan

**Phase:** 0 — Foundations
**Findings Requiring Remediation:** 0 (blocking) | 2 (informational)

---

## Remediation Actions

### R-001: Install Lean 4 Toolchain (for F-001)

**Priority:** Before Phase 2 (Semantic Alignment) — Lean 4 proofs become critical at Phase 2.
**Owner:** Infrastructure / DevOps
**Action:**
1. Install `elan` (Lean 4 version manager): `curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh`
2. The `formal/lean-toolchain` file pins the Lean 4 version.
3. Run `lake build` in `formal/` to verify all foundation proofs compile.
4. Add `lake build` step to CI pipeline.

**Acceptance Criteria:** `lake build` completes with 0 errors in `formal/`.

---

### R-002: Install TLA+ TLC Model Checker (for F-002)

**Priority:** Before Phase 1 Checkpoint — TLA+ model checking validates behavioral properties.
**Owner:** Infrastructure / DevOps
**Action:**
1. Install TLA+ tools (TLC): download from https://github.com/tlaplus/tlaplus/releases or use `apt install tla-toolbox`.
2. Run `tlc Properties -config MC.cfg` in `tla/` directory.
3. Verify all 6 core properties and supporting invariants pass.
4. Add TLC model checking step to CI pipeline.

**Acceptance Criteria:** `tlc Properties -config MC.cfg` completes with 0 invariant violations.

---

## No Code Remediation Required

All Rust code compiles cleanly and all tests pass. No code changes are required for Phase 0 gate passage. The two informational findings relate to external toolchain availability, not code defects.
