# VSEL for Cairo/STARK Semantic Assurance Toolkit — Starknet Seed Grant

**Applicant**: Mayckon Giovani / Stigning  
**Grant Program**: Starknet Foundation Seed Grant  
**Funding Request**: 25,000 STRK  
**Timeline**: 12 weeks (3 milestones)  
**License**: Apache-2.0

---

## Executive Pitch

### The Problem

In proof-bearing systems like Starknet, a valid STARK proof guarantees that a computation satisfied a constraint system. But it does not guarantee that the constraint system faithfully represents the intended application semantics.

This gap — between *verified execution* and *semantically correct execution* — is where real-world exploits live. A Cairo contract can produce a valid proof for a computation that violates the developer's intended invariants, state transitions, or economic properties. The proof is correct. The application is broken.

No tool in the Starknet ecosystem currently addresses this layer.

### The Solution

VSEL for Cairo/STARK is an open-source semantic assurance toolkit that helps Starknet developers and auditors answer one question:

> **What exactly does the proof prove, and does that statement preserve the intended application semantics?**

The toolkit provides reusable methodology, templates, and a reference Cairo implementation covering:

1. **Semantic gap analysis** — systematic identification of mismatches between intended behavior and what the proof actually attests
2. **Proof obligation schemas** — formal documentation of what each proof must guarantee
3. **Trace sufficiency models** — ensuring execution traces are complete and reconstructible
4. **Constraint coverage matrices** — mapping every semantic requirement to its constraint enforcement
5. **Witness uniqueness analysis** — detecting ambiguous or malleable witnesses
6. **Verifier binding checklists** — confirming that verifier acceptance implies semantic correctness
7. **Minimal Cairo reference state machine** — a working example showing the methodology applied to a real Cairo contract

### Why This Matters for Starknet

Starknet is built on provable computation. As the ecosystem grows into DeFi, autonomous worlds, account abstraction, and complex protocol-level state machines, the semantic correctness gap becomes a systemic risk.

VSEL doesn't replace Cairo tooling or Starknet infrastructure. It adds a complementary assurance layer that sits alongside development and helps teams prepare for audits, reason about correctness, and document what their proofs actually mean.

### What Already Exists

VSEL is not a concept. It's a working protocol in v1.0 production release with:

- **Real STARK proofs** via Plonky3 FRI over the Goldilocks field (soundness ≤ 2^(−100))
- **1,497+ passing tests** including property-based tests (100K+ iterations), integration tests, and differential tests
- **Formal specification** in Lean 4 (zero `sorry`) with TLA+ model checking
- **~64.8M fuzzing executions** across 7 targets, 0 critical findings
- **Empirical benchmarks** — Plonky3 STARK verification at 812 µs, 123× below DoS threshold
- **Ultra-adversarial audit** — 5 findings, all remediated, 14 attack domains passed
- **Comprehensive documentation corpus**: whitepaper, threat model, proof obligations, semantic mapping, refinement strategy, trace sufficiency, underconstraint analysis, witness uniqueness model, verification layer model, and more

The Seed Grant turns this existing formal corpus into a Starknet-specific, practical, open-source toolkit for Cairo/STARK builders.

---

## Grant Roadmap

### Milestone 1: Starknet/Cairo Adaptation and Public Research Package
**Budget**: 8,000 STRK  
**Deadline**: June 15, 2026

| Deliverable | Description |
|---|---|
| Project page | VSEL for Cairo/STARK published with Starknet-oriented scope |
| Starknet overview | Document mapping VSEL layers to Cairo/STARK development concepts |
| Semantic assurance checklist | Initial Cairo/STARK semantic assurance checklist for developers |
| Documentation structure | Public documentation structure for the Starknet toolkit |
| Website update | Updated VSEL website with Seed Grant scope and Starknet roadmap |
| Milestone update | Public milestone update shared with Starknet community |

### Milestone 2: Proof Obligations, Semantic Gap, and Trace Sufficiency Toolkit
**Budget**: 8,500 STRK  
**Deadline**: July 31, 2026

| Deliverable | Description |
|---|---|
| Proof obligation schema | Cairo-oriented proof obligation schema with examples |
| Semantic gap analysis template | Reusable template for identifying semantic gaps in Cairo/STARK systems |
| Trace sufficiency template | Template for verifying execution trace completeness and reconstructibility |
| Witness uniqueness model | Witness uniqueness and non-malleability analysis template |
| Verifier binding checklist | Checklist confirming verifier acceptance implies semantic correctness |
| Constraint coverage matrix | Template mapping semantic requirements to constraint enforcement |
| Technical write-up | Public technical write-up for Starknet developers |

### Milestone 3: Minimal Cairo Reference Example and Final Package
**Budget**: 8,500 STRK  
**Deadline**: September 15, 2026

| Deliverable | Description |
|---|---|
| Cairo reference state machine | Minimal Cairo contract with defined state, inputs, transitions, observables, and invariants |
| Semantic mapping document | Example showing how VSEL methodology maps to the Cairo reference |
| Proof obligation matrix | Example proof obligation matrix for the reference state machine |
| Constraint coverage matrix | Example constraint coverage matrix for the reference |
| Sepolia deployment | Reference state machine deployed to Starknet Sepolia testnet |
| GitHub repository | Public open-source repository with all artifacts |
| Final documentation | Complete documentation package |
| Grant report | Final Seed Grant report |
| Tutorial article | Tutorial-style article for Starknet builders |
| Future roadmap | Roadmap for integration with Cairo tooling and Starknet developer workflows |

---

## Deployment Plan

1. **Local development** — Cairo reference state machine implemented and tested locally with Scarb + Starknet Foundry
2. **Starknet Sepolia** — Deployed to testnet as a public, inspectable example linked to VSEL assurance artifacts
3. **Mainnet** — Only considered after testnet reference is complete, reviewed, and shown useful to builders. Not required for Seed Grant scope.

---

## Technical Differentiation

| Aspect | Existing Starknet Tools | VSEL for Cairo/STARK |
|---|---|---|
| Focus | Code correctness, testing, deployment | Semantic correctness of proof statements |
| Question answered | "Does the code compile and pass tests?" | "Does the proof prove what we intend?" |
| Artifact type | Test results, coverage reports | Proof obligations, semantic gap analysis, constraint coverage |
| Audit preparation | Code review, fuzzing | Formal semantic assurance documentation |
| Composability analysis | Interface testing | Cross-system invariant and state chain analysis |

---

## Team

**Mayckon Giovani** — Principal Systems Engineer, Stigning

Background in security-critical distributed systems, post-quantum cryptographic infrastructure, formal methods, protocol engineering, Rust backends, blockchain systems, and adversarial verification methodology.

Built the entire VSEL protocol from formal specification through production release, including:
- Lean 4 formal proofs (zero `sorry`)
- TLA+ model checking
- Real Plonky3 STARK integration
- Ultra-adversarial audit methodology
- 1,497+ test suite with property-based testing and fuzzing

---

## Links

- **VSEL Website**: https://vsel-ten.vercel.app
- **GitHub**: https://github.com/doomhammerhell
- **Stigning**: https://www.stigning.com/en
- **Personal**: https://mayckongiovani.xyz
