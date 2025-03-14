**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This document defines the cryptographic foundations of VSEL.

It specifies:

* primitives used
* security assumptions
* threat models (classical and post-quantum)
* key lifecycle
* proof system cryptographic dependencies

The objective is:

> Ensure that semantic correctness guarantees are not invalidated by cryptographic failure, both in the present and under future adversarial capabilities.

---

## 2. Security Model

VSEL operates under a **hybrid adversarial model**:

* classical adversaries (current capabilities)
* quantum-capable adversaries (future capabilities)

The system must remain secure against:

* immediate exploitation
* delayed exploitation (“harvest now, decrypt later”)

---

## 3. Cryptographic Objectives

The cryptographic layer must provide:

* **Integrity**: state and proofs cannot be forged
* **Authenticity**: inputs are authorized
* **Binding**: commitments uniquely bind to data
* **Soundness support**: proof systems rely on secure primitives
* **Forward security**: past proofs remain valid under future attacks

---

## 4. Primitive Categories

VSEL uses the following classes of primitives:

### 4.1 Hash Functions

Used for:

* state commitments
* Merkle structures
* domain separation

Requirements:

* collision resistance
* preimage resistance
* quantum resistance (where applicable)

Candidates:

* SHA-3 / Keccak
* BLAKE3
* STARK-friendly hashes (Poseidon, Rescue)

---

### 4.2 Commitment Schemes

Used for:

* state commitments
* trace commitments
* polynomial commitments

Properties:

* binding
* hiding (if required)

Examples:

* Merkle commitments
* polynomial commitments (FRI, KZG)

---

### 4.3 Digital Signatures

Used for:

* input authorization
* identity binding

Requirements:

* unforgeability
* resistance to adaptive attacks
* post-quantum security for long-term validity

Candidates:

* Classical: ECDSA, Ed25519
* Post-Quantum: ML-DSA (Dilithium), Falcon

---

### 4.4 Key Exchange / Encryption

Used for:

* secure communication
* witness privacy (if needed)

Requirements:

* forward secrecy
* post-quantum resistance

Candidates:

* Classical: ECDH
* Post-Quantum: ML-KEM (Kyber)

---

### 4.5 Proof System Primitives

Depends on proof system:

* STARKs: hash-based security
* SNARKs: pairing-based assumptions

Requirements:

* soundness under chosen model
* compatibility with semantic constraints

---

## 5. Hybrid Cryptographic Strategy

To mitigate long-term risk, VSEL adopts a hybrid model:

[
Security = Classical \land PostQuantum
]

### 5.1 Hybrid Signatures

[
Sig = (Sig_{classical}, Sig_{PQC})
]

Both must verify.

---

### 5.2 Hybrid Key Exchange

[
K = Combine(K_{classical}, K_{PQC})
]

Ensures:

* current performance
* future security

---

## 6. State Commitment Model

State commitments must satisfy:

[
Commit(C) = Hash(Encode(C))
]

Properties:

* deterministic
* collision-resistant
* stable across time

---

### 6.1 Merkle Structures

Used for:

* efficient inclusion proofs
* partial state verification

Requirements:

* canonical tree structure
* deterministic ordering

---

## 7. Proof System Assumptions

### 7.1 STARK-Based Systems

Assumptions:

* hash function security
* low-degree testing soundness

Advantages:

* transparent setup
* post-quantum friendly

---

### 7.2 SNARK-Based Systems

Assumptions:

* elliptic curve hardness
* pairing security

Risks:

* quantum vulnerability
* trusted setup (in some cases)

---

### 7.3 Hybrid Proof Strategy

Optional:

* STARK for base proofs
* SNARK for recursion/compression

---

## 8. Key Management Model

### 8.1 Key Generation

Keys must be:

* securely generated
* entropy-backed
* domain-separated

---

### 8.2 Key Storage

Keys must be:

* protected against extraction
* optionally hardware-backed

---

### 8.3 Key Rotation

Rotation must be:

* explicit
* traceable
* non-breaking

---

### 8.4 Key Revocation

Revocation must be:

* enforceable
* observable
* propagated across system

---

## 9. Domain Separation

All cryptographic operations must include domain separation:

[
Hash(domain | data)
]

Prevents:

* cross-protocol attacks
* replay across contexts

---

## 10. Randomness Model

Randomness must be:

* explicit
* verifiable or auditable

Sources:

* deterministic derivation
* verifiable randomness (VRF)
* external randomness (modeled in ( E ))

No implicit randomness allowed.

---

## 11. Post-Quantum Threat Model

Assumes adversary can:

* break ECC and RSA
* recover private keys from public data
* forge classical signatures

System must remain secure by:

* hybrid cryptography
* PQC primitives
* forward-secure design

---

## 12. Long-Term Validity

Proofs must remain valid under:

* future cryptographic assumptions
* evolving threat models

Strategies:

* re-signing
* proof migration
* hybrid verification

---

## 13. Failure Modes

### 13.1 Collision Attack

State commitments collide.

---

### 13.2 Signature Forgery

Unauthorized inputs accepted.

---

### 13.3 Key Compromise

Adversary gains control of keys.

---

### 13.4 Proof System Break

Cryptographic assumptions fail.

---

### 13.5 Domain Confusion

Proofs reused across contexts.

---

### 13.6 Randomness Manipulation

Entropy source compromised.

---

## 14. Minimal Security Assumptions

The system assumes:

* hash functions remain collision-resistant
* signature schemes remain unforgeable
* proof systems remain sound

If these fail, security degrades.

---

## 15. Defense Strategy

* hybrid cryptography
* explicit assumptions
* minimal reliance on fragile primitives
* ability to upgrade cryptographic components

---

## 16. Cryptographic Agility

System must support:

* primitive replacement
* parameter updates
* migration strategies

Without breaking:

* state validity
* proof correctness

---

## 17. Closing Statement

Cryptography does not make a system correct.

It makes it hard to cheat.

VSEL ensures that:

> what is hard to cheat is also worth trusting.
