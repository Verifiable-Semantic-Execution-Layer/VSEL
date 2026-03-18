# Phase 7 — Findings

**Phase:** 7 — Cryptographic Resilience
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
No direct impact on Phase 7 cryptographic resilience testing. The cryptographic module is a Rust-only component validated by 97 unit tests and 15 property-based tests (Properties 44–47). No Lean 4 proofs were added in Phase 7.

**Recommendation:**
Install Lean 4 toolchain (v4.8.0 per `lean-toolchain`) and run `lake build` in `formal/` directory. Add to CI pipeline.

---

### F-002: TLA+ TLC Model Checker Not Available for Automated Verification

**Severity:** Informational
**Category:** Toolchain
**Status:** Open (carried from Phase 0 — requires manual verification)
**Phase Introduced:** 0

**Description:**
The TLA+ TLC model checker (`tlc`) is not installed in the current CI/development environment. TLA+ models have been structurally reviewed but model checking could not be performed automatically.

**Impact:**
No direct impact on Phase 7 cryptographic resilience. No TLA+ models were added in Phase 7. The cryptographic module is validated entirely through Rust tests.

**Recommendation:**
Install TLA+ tools and run `tlc` in `tla/` directory. Add to CI pipeline.

---

## Phase 7 New Findings

No new findings were identified during Phase 7 verification.

- All 806 tests pass (645 unit + 161 property-based).
- Hybrid signatures correctly implement `Sig = (Sig_classical, Sig_PQC)` where both must verify for acceptance. Corrupting either component independently causes rejection.
- Hybrid key exchange correctly implements `K = SHA3-256(domain || K_classical || K_PQC)`. Changing either component changes the shared secret, ensuring compromise of a single component is insufficient.
- All three hash algorithms (SHA3-256, BLAKE3, Poseidon) produce correct, deterministic, collision-resistant output with proper domain separation.
- All 6 well-known domain tags are pairwise distinct. Cross-domain signature verification fails (replay prevention).
- Key lifecycle management correctly enforces secure generation (OS entropy), domain-separated generation, traceable rotation with successor chaining, observable revocation, and temporal expiration (T1=1hr, T2=24hr, T3=365d, T4=permanent).
- Commitment migration produces valid commitments under both source and target algorithms, with verification detecting tampered data and wrong domains.
- Signature migration re-signs correctly with new keys, preserving key ID in migration records.
- Proof migration archives witness data with no expiry (lifetime of proof relevance) and produces commitments under both algorithms.
- Cryptographic agility manager correctly tracks supported algorithms, defaults, and migration policies.
- PQC backend is a placeholder (HMAC-SHA3) with `PqcSigner` trait enabling future replacement with ML-DSA/Falcon when stable crates are available. This is by design and documented in the code.
