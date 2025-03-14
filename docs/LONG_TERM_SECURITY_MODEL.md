**Verifiable Semantic Execution Layer (VSEL)**

# LONG-TERM SECURITY MODEL

## 1. Purpose

This document classifies every cryptographic artifact in VSEL by temporal sensitivity and defines the security strategy required to maintain validity across time horizons.

"Hybrid classical + PQC" is a posture, not a plan. This document turns it into a plan.

> The question is not "are we post-quantum ready?" The question is "which artifacts become worthless first, and what breaks when they do?"

---

## 2. Temporal Sensitivity Classification

Every cryptographic artifact is classified into one of four temporal horizons:

### Horizon T1: Ephemeral (seconds to minutes)
- Validity required only during active execution
- Can be regenerated at will
- Compromise after use has no impact

### Horizon T2: Session (hours to days)
- Validity required during a session or batch
- Compromise after session close has limited impact
- Must resist real-time attacks

### Horizon T3: Archival (months to years)
- Validity required for audit, compliance, dispute resolution
- Must resist "harvest now, decrypt later" attacks
- Compromise enables retroactive falsification

### Horizon T4: Permanent (decades+)
- Validity required indefinitely
- Must resist future adversarial capabilities including quantum
- Compromise invalidates historical trust

---

## 3. Artifact Classification

### 3.1 State Commitments

```
Artifact: Commit(s) = Hash(Encode(s))
Horizon: T3-T4
```

State commitments are referenced by proofs, traces, and verification records. If a commitment can be forged retroactively, historical proofs become meaningless.

Requirements:
- Hash function must be collision-resistant under quantum adversary (T4)
- Use quantum-resistant hash (SHA-3, BLAKE3) for long-term commitments
- STARK-friendly hashes (Poseidon) acceptable for T1-T2 if wrapped in quantum-resistant outer commitment for T3-T4

Migration strategy: Re-commit historical states under new hash if current hash is threatened.

### 3.2 Trace Commitments

```
Artifact: trace_root = Hash(chain of entries)
Horizon: T3-T4
```

Trace commitments are the ground truth of execution history.

Requirements:
- Same as state commitments
- Chain structure must be preserved under re-commitment
- Historical trace roots must be re-signable under new primitives

### 3.3 Digital Signatures (Input Authorization)

```
Artifact: Sig(sk, payload)
Horizon: T2-T3
```

Signatures authorize inputs. Their validity horizon depends on use case:
- T2: Real-time transaction authorization (valid during processing)
- T3: Audit trail (must prove who authorized what, months/years later)

Requirements:
- Hybrid signatures: Sig = (Sig_classical, Sig_PQC)
- Both must verify for acceptance
- Classical component provides current performance
- PQC component provides future resistance

Migration strategy:
- Re-sign historical authorization records under PQC when classical scheme is threatened
- Maintain signature validity chain: original sig → re-signing attestation → new sig

### 3.4 Proof Artifacts

```
Artifact: π = Proof(τ, C)
Horizon: T3-T4
```

Proofs must remain verifiable for as long as the execution they attest to matters.

Requirements:
- STARK-based proofs: hash-based security, naturally quantum-resistant (T4)
- SNARK-based proofs: pairing-based, quantum-vulnerable (T2 without mitigation)
- Hybrid strategy: STARK for base proofs (T4), SNARK for recursion/compression (T2, re-provable)

Migration strategy:
- Re-prove historical executions under new proof system if current system is threatened
- Maintain proof validity chain: original proof → re-proof attestation → new proof
- Archive witness data to enable re-proving

### 3.5 Verification Transcripts

```
Artifact: Record of Verify(π) = true
Horizon: T3
```

Verification transcripts prove that a proof was accepted at a specific time.

Requirements:
- Timestamped and signed
- Signature must be hybrid (classical + PQC)
- Transcript must reference specific proof and public inputs

### 3.6 Key Material

```
Artifact: Private keys, public keys
Horizon: Varies
```

| Key Type | Horizon | Quantum Risk |
|----------|---------|-------------|
| Signing keys (ECDSA/Ed25519) | T2 | HIGH — quantum breaks ECC |
| Signing keys (ML-DSA/Falcon) | T3-T4 | LOW — designed for PQC |
| Key exchange (ECDH) | T1-T2 | HIGH — quantum breaks DH |
| Key exchange (ML-KEM) | T2-T3 | LOW — designed for PQC |
| Commitment randomness | T1 | LOW — used once |

Migration strategy:
- Rotate classical keys frequently (T2 horizon)
- PQC keys can have longer rotation periods
- Revocation must propagate across all systems
- Key compromise recovery protocol must be defined

### 3.7 Domain Separation Tags

```
Artifact: Domain = Hash(context)
Horizon: T4
```

Domain tags must remain unique and unforgeable permanently.

Requirements:
- Quantum-resistant hash
- Context must include version, system ID, epoch
- Historical domain tags must remain valid under new hash functions

---

## 4. Threat Timeline

### Phase 1: Present (2024-2030)
- Classical cryptography holds
- Quantum computers not yet cryptographically relevant
- Primary threat: classical attacks, implementation bugs

Strategy: Deploy hybrid cryptography now. Classical for performance, PQC for future-proofing.

### Phase 2: Transition (2030-2035, estimated)
- Early quantum computers may threaten ECC/RSA
- "Harvest now, decrypt later" attacks become real concern
- Classical-only signatures become suspect

Strategy: Complete migration to hybrid. Begin re-signing historical artifacts. Archive witness data for re-proving.

### Phase 3: Post-Quantum (2035+, estimated)
- Quantum computers can break classical public-key cryptography
- All classical-only artifacts are compromised
- PQC primitives are the baseline

Strategy: Full PQC operation. Classical components retained only for backward compatibility verification.

---

## 5. Migration Protocols

### 5.1 Commitment Migration

```
When hash function H₁ is threatened:
1. For each historical commitment c = H₁(data):
   a. Retrieve original data (from trace archive)
   b. Compute c' = H₂(data) under new hash
   c. Create migration attestation: MigrationAttest(c, c', H₁, H₂, timestamp)
   d. Sign attestation with hybrid signature
2. Update all references from c to c'
3. Maintain mapping table: c → c' for backward compatibility
```

### 5.2 Signature Migration

```
When signature scheme S₁ is threatened:
1. For each historical signature sig₁ = Sign_S₁(sk₁, payload):
   a. Verify sig₁ is still valid (before compromise)
   b. Create re-signing: sig₂ = Sign_S₂(sk₂, payload)
   c. Create migration attestation: MigrationAttest(sig₁, sig₂, S₁, S₂, timestamp)
   d. Sign attestation with hybrid signature
2. Archive original signatures for audit trail
```

### 5.3 Proof Migration

```
When proof system P₁ is threatened:
1. For each historical proof π₁:
   a. Retrieve witness W from archive
   b. Regenerate constraints C under current SIR
   c. Generate new proof: π₂ = Prove_P₂(W, C)
   d. Create migration attestation: MigrationAttest(π₁, π₂, P₁, P₂, timestamp)
2. Verify π₂ under new verifier
3. Archive π₁ for audit trail
```

**Critical requirement**: Witness data must be archived for the lifetime of the proof's relevance. Without witness data, re-proving is impossible.

---

## 6. Archive Requirements

### 6.1 What Must Be Archived

| Artifact | Archive Duration | Purpose |
|----------|-----------------|---------|
| Witness data | T4 (permanent) | Enable re-proving |
| Original state data | T4 | Enable re-commitment |
| Original signatures | T3 | Audit trail |
| Original proofs | T3 | Audit trail |
| Migration attestations | T4 | Chain of trust |
| Constraint system versions | T4 | Enable re-proving |
| SIR versions | T4 | Enable constraint regeneration |

### 6.2 Archive Integrity

Archives must be:
- Committed with quantum-resistant hash
- Signed with hybrid signature
- Replicated across independent storage
- Periodically verified for integrity

---

## 7. Degradation Model

If a cryptographic primitive is broken, what degrades?

### Hash Function Break (e.g., SHA-3 collision found)

| Artifact | Impact | Recovery |
|----------|--------|----------|
| State commitments | Forgeable | Re-commit under new hash |
| Trace commitments | Forgeable | Re-commit under new hash |
| Domain tags | Collision possible | Regenerate with new hash |
| Merkle proofs | Invalid | Rebuild trees |

### Signature Scheme Break (e.g., ECDSA broken by quantum)

| Artifact | Impact | Recovery |
|----------|--------|----------|
| Input authorization | Forgeable | Re-sign under PQC |
| Verification transcripts | Forgeable | Re-sign under PQC |
| Key material | Compromised | Rotate to PQC keys |

### Proof System Break (e.g., pairing assumption broken)

| Artifact | Impact | Recovery |
|----------|--------|----------|
| SNARK proofs | Invalid | Re-prove under STARK |
| Recursive proofs | Invalid | Re-prove recursion |
| STARK proofs | Unaffected | N/A |

---

## 8. Hybrid Strategy Details

### 8.1 Hybrid Commitment

```
Commit_hybrid(data) = (H_classical(data), H_PQC(data))
```

Both commitments must match for acceptance. If either hash is broken, the other provides security.

### 8.2 Hybrid Signature

```
Sig_hybrid(sk, data) = (Sign_classical(sk_c, data), Sign_PQC(sk_pq, data))
```

Both signatures must verify. Verification:
```
Verify_hybrid(sig, pk, data) = Verify_classical(sig.c, pk.c, data) ∧ Verify_PQC(sig.pq, pk.pq, data)
```

### 8.3 Hybrid Proof Strategy

```
Base proof: STARK (quantum-resistant, transparent)
Compression: SNARK (succinct, may need re-proving)
```

If SNARK compression is broken:
- Base STARK proof remains valid
- Re-compress under new scheme or accept larger proof

---

## 9. Compliance Evidence Lifecycle

For regulatory and audit purposes:

```
Evidence Chain:
  Execution → Trace → Proof → Verification → Attestation
  
Each link must be:
  - Timestamped (trusted time source)
  - Signed (hybrid signature)
  - Committed (quantum-resistant hash)
  - Archived (with migration capability)
```

Evidence validity period must exceed regulatory retention requirements.

---

## 10. Closing Statement

Long-term security is not about choosing the right algorithm today.

It is about building a system that can survive being wrong about which algorithm was right.

VSEL's cryptographic model must be designed for migration, not for permanence, because permanence in cryptography is an illusion that history has repeatedly and enthusiastically destroyed.
