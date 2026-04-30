# Phase 11 — Post-Audit Hardening Findings

**Phase:** 11 — Post-Audit Hardening
**Date:** 2026-04-28

---

## New Findings

### F-002: Poseidon Domain Separation Regression

**Severity:** Medium (discovered and remediated in-phase)
**Component:** vsel-crypto (hash.rs) — `domain_hash_with_algorithm()` Poseidon branch
**Dimension:** 11 (Cryptographic Failure)

**Description:**
The simplified Poseidon domain separation implementation was vulnerable to hash collisions across distinct domains. The implementation loaded a SHA3-256-derived domain IV into the Poseidon state words, permuted, then absorbed data and permuted again. For certain data/domain combinations, the wrapping u64 arithmetic in the simplified Poseidon permutation produced identical outputs despite distinct domain IVs.

**Root Cause:**
The Poseidon permutation operates over `[u64; 4]` with wrapping arithmetic. The S-box (`x^5 mod 2^64`) and MDS mixing layer do not provide sufficient diffusion over the wrapping field to guarantee that distinct initial states (from distinct domain IVs) produce distinct outputs after absorbing the same data. Specifically, the XOR-based absorption can cancel out IV differences when data chunks align with the IV differences modulo the permutation's mixing properties.

**Detection Method:**
Proptest regression case in `prop_domain_separation_all_algorithms` (P46c). Two regression seeds in `crypto_tests.proptest-regressions` triggered the failure with data lengths of 185 and 224 bytes respectively.

**Mathematical Condition:**
`∃ data, domain_a, domain_b: domain_a ≠ domain_b ∧ Poseidon_domain(domain_a, data) = Poseidon_domain(domain_b, data)`

**Fix Applied:**
Replaced the state-initialization approach with a domain-keyed hash construction:
```
domain_key = SHA3-256("VSEL::poseidon::domain_key::" || domain_tag)
H(domain, data) = Poseidon(data) ⊕ domain_key
```

**Correctness Argument:**
- SHA3-256 is collision-resistant: distinct domains produce distinct 32-byte keys
- XOR with distinct keys produces distinct outputs: if `key_a ≠ key_b`, then `∀ h: h ⊕ key_a ≠ h ⊕ key_b`
- Therefore: distinct domains always produce distinct domain-separated hashes

**Verification:**
- All 15 crypto property tests pass (including both regression cases)
- P46c validates with 100 random cases across SHA3, BLAKE3, and Poseidon

**Note:** When a production STARK-native Poseidon implementation is integrated (operating over a prime field rather than wrapping u64), this construction should be replaced with proper field-native domain separation (capacity initialization or domain-tagged absorption in the sponge).

**Status:** REMEDIATED

---

## Remediated Findings from Ultra Adversarial Audit

All findings from the Ultra Adversarial Audit have been verified as remediated:

| ID | Severity | Title | Remediation Task | Status |
|----|----------|-------|-----------------|--------|
| M-001 | Medium | Mapping layer stubs | 25.2 | **REMEDIATED** |
| M-002 | Medium | Constraint soundness axiomatized | 25.1 | **REMEDIATED** |
| M-003 | Medium | Proof system placeholder | 25.3 | **REMEDIATED** |
| L-001 | Low | Bounded model checking | 25.5 | **REMEDIATED** |
| L-002 | Low | Trace merge temporal ordering | 25.4 | **REMEDIATED** |
| L-003 | Low | Crypto migration untested E2E | 25.6 | **REMEDIATED** |
| L-004 | Low | Counter overflow untested | 25.7 | **REMEDIATED** |
| L-005 | Low | Batch policy undocumented | 25.8 | **REMEDIATED** |
| I-001/I-006 | Info | Axiom traceability | 25.9 | **REMEDIATED** |
| I-002 | Info | sorry in Uniqueness.lean | 25.10 | **REMEDIATED** |

---

## Finding Summary

| Severity | New | Remediated (from prior) | Open |
|----------|-----|------------------------|------|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Medium | 1 (F-002, fixed in-phase) | 3 (M-001, M-002, M-003) | 0 |
| Low | 0 | 5 (L-001 through L-005) | 0 |
| Informational | 0 | 3 (I-001, I-002, I-006) | 0 |
| **Total** | **1** | **11** | **0** |
