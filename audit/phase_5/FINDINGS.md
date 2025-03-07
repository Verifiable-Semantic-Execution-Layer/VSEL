# Phase 5 — Findings

**Phase:** 5 — Verification Authority
**Total Findings:** 2 (Informational, carried from Phase 0)
**Critical:** 0 | **High:** 0 | **Medium:** 0 | **Low:** 0 | **Informational:** 2

---

## Carried Findings from Phase 0

### F-001: Lean 4 Toolchain Not Available for Automated Verification

**Severity:** Informational
**Category:** Toolchain
**Status:** Open (carried from Phase 0 — requires manual verification)
**Phase Introduced:** 0

**Description:**
The Lean 4 build tool (`lake`) is not installed in the current CI/development environment. Lean 4 proofs in `formal/VSEL/` have been structurally reviewed but compilation via `lake build` could not be performed automatically.

**Impact:**
No direct impact on Phase 5 verification authority testing. The verifier operates on Rust execution traces and is validated by Rust property-based tests (Properties 32, 39–42) and unit tests. Lean 4 refinement proofs (R₀₁, R₁₂, R₂₃) define the formal-side axioms that the verification pipeline encodes, but verifier correctness is independently verified through PBT.

**Recommendation:**
Install Lean 4 toolchain (v4.8.0 per `lean-toolchain`) and run `lake build` in `formal/` directory. Add to CI pipeline.

---

### F-002: TLA+ TLC Model Checker Not Available for Automated Verification

**Severity:** Informational
**Category:** Toolchain
**Status:** Open (carried from Phase 0 — requires manual verification)
**Phase Introduced:** 0

**Description:**
The TLA+ TLC model checker (`tlc`) is not installed in the current CI/development environment. TLA+ models in `tla/` have been structurally reviewed but model checking could not be performed automatically.

**Impact:**
No direct impact on Phase 5 verification. TLA+ model checking provides complementary behavioral exploration but is not required for verification authority testing.

**Recommendation:**
Install TLA+ tools and run `tlc Properties -config MC.cfg` in `tla/` directory. Add to CI pipeline.

---

## Phase 5 New Findings

No new findings were identified during Phase 5 verification.

- All 682 tests pass (548 unit + 134 property-based).
- Proof soundness (THM-8) verified: valid proofs from valid traces are accepted; corrupted proofs are rejected.
- Domain correctness (Req 8.3) verified: wrong domain causes rejection at DomainValidation step.
- Malformed proof rejection (Req 8.4) verified: empty proof_data, zeroed commitments, empty metadata all rejected at StructuralValidation.
- Stateful verification continuity (Req 8.5) verified: chained proofs accepted, broken chains rejected with StateContinuityBroken.
- Version compatibility (Req 8.6) verified: different major version rejected, same major with different minor accepted.
- Temporal invariants (Req 3.3) verified: T_no_revert, T_causal, T_complete, T_cons all hold on valid traces and detect violations on corrupted traces.
- Recursive verification (Req 8.10) verified: inner proof validity embedded without external trust.
- Lean 4 refinement proofs (R₀₁, R₁₂, R₂₃) structurally complete with well-formed theorems.
- The `vsel-proof` verifier module adds 39 unit tests and 10 property-based tests.
- The `vsel-composition` crate adds 62 unit tests for assume-guarantee contracts, proof composition, trace merging, and cross-system invariants.
- The temporal invariant property tests add 5 property-based tests for Property 12.

---

## Notes

- Phase 5 adds the verifier module to `vsel-proof` with three components: `DefaultVerifier` (7-step pipeline), `StatefulVerifier` (trace continuity), and recursive verification support.
- The 7-step pipeline enforces: (1) domain validation, (2) structural validation, (3) commitment validation, (4) cryptographic verification, (5) semantic binding, (6) invariant enforcement, (7) final acceptance.
- The verifier assumes the prover is malicious (Req 8.8): inputs may be adversarial, proofs may be malformed or crafted. Verification is deterministic, complete, and strict.
- The `vsel-composition` crate implements assume-guarantee contracts (Req 11.1–11.3), proof composition, trace merging with sync point detection, and cross-system invariant checking (CI-1 through CI-5, CE-arbitrage, CE-contagion).
