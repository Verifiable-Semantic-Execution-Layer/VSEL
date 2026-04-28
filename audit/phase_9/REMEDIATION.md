# Phase 9 — System Hardening Remediation Log

**Phase:** 9 — System Hardening
**Date:** 2026-04-21

---

## Remediation R-001: Poseidon Domain Separation Fix

**Finding:** F-001 (Poseidon Domain Separation Collision)
**Severity:** Critical
**Status:** COMPLETE

### Action Taken

1. **Identified root cause:** The `domain_hash_with_algorithm` Poseidon branch in `protocol/crates/vsel-crypto/src/hash.rs` used simple byte concatenation (`domain_bytes || data`) before feeding into the Poseidon sponge. The simplified Poseidon permutation over wrapping u64 arithmetic did not provide sufficient diffusion to guarantee collision resistance across different domain tags.

2. **Implemented fix:** Replaced concatenation with a SHA3-256-derived domain initialization vector (IV) approach:
   - Compute `IV = SHA3-256("VSEL::poseidon::domain_iv::" || domain_tag_bytes)` — leverages SHA3's proven collision resistance
   - Load IV directly into Poseidon state words (bypassing the absorb path)
   - Apply permutation barrier to irreversibly commit the domain into the internal state
   - Absorb data normally and squeeze the final hash

3. **Verified fix:**
   - `cargo check` — 0 errors, 0 warnings
   - `cargo test -p vsel-crypto --test property_crypto_tests` — 15/15 pass
   - `prop_domain_separation_all_algorithms` — 100 adversarial cases, all pass
   - Full test suite — 1,062 tests pass, 0 failures

### File Modified

- `protocol/crates/vsel-crypto/src/hash.rs` — `domain_hash_with_algorithm` function, Poseidon branch

### Regression Risk

Low. The change only affects the Poseidon hash algorithm path within `domain_hash_with_algorithm`. SHA3-256 and BLAKE3 paths are unchanged. State commitments and trace commitments use SHA3-256/BLAKE3 and are unaffected.

---

## Summary

| ID | Finding | Action | Status |
|----|---------|--------|--------|
| R-001 | F-001 (Poseidon domain separation) | SHA3-derived domain IV | **COMPLETE** |

**All remediations complete. No outstanding actions.**
