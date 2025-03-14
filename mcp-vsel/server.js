import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_DIR = join(__dirname, "..", "docs");

const server = new McpServer({
  name: "vsel-knowledge",
  version: "2.0.0",
});

const KNOWLEDGE = {
  architecture: {
    title: "VSEL Architecture",
    summary: `VSEL has 6 layers:
1. Formal Specification Layer (FSL) — TLA+/Coq/Isabelle state machine definition
2. Semantic Intermediate Representation (SIR) — canonical bridge
3. Execution Layer (EL) — deterministic runtime
4. Constraint Derivation Layer (CDL) — auto-derives constraints from SIR
5. Proof Layer (PL) — STARKs/SNARKs/hybrid proofs
6. Verification Layer (VL) — validates proofs + semantic correctness

Core modules: FSE, SIR, EE, TE, CE, PR, VR, CL. Each must be deterministic, isolated, auditable.`,
    docs: ["WHITEPAPER.md", "TECH_SPEC.md"],
  },
  formal_spec: {
    title: "Formal Specification",
    summary: `System modeled as LTS: M = (S, I, T, O)
State s = (C, D, E, τ). Deterministic: Apply(s, σ) = s' unique.
Closed under transitions. Safety: no invariant violation reachable.
Liveness: no deadlock. Error handling: Apply(s, σ_invalid) = s_error ∈ S.
Completeness: every implementation execution maps to valid trace.`,
    docs: ["FORMAL_SPECIFICATION.md"],
  },
  state_machine: {
    title: "State Machine",
    summary: `Concrete operational state machine. State s = (C, D, E, τ).
C (Canonical): balances, ownership, storage. D (Derived): D = Derive(C).
E (Environment): explicit. τ (Metadata): sequence, commitment, epoch.
Transition classes: Init, Update, No-Op, Error, Batch.
Pipeline: canonicalize → auth → preconditions → apply → postconditions → derive → commit.
Encoding: Hash(Encode(s)) = Commitment(s). Replay: deterministic always.`,
    docs: ["STATE_MACHINE.md"],
  },
  invariants: {
    title: "Invariant System",
    summary: `LOCAL: L_valid, L_state, L_cons (resource conservation), L_bounded, L_det.
GLOBAL: G_valid, G_struct, G_commit, G_mono, G_env.
TEMPORAL: T_valid, T_no_revert, T_cons, T_causal, T_complete.
CROSS-LAYER: X_exec (impl=spec), X_constraint (valid⟺satisfies), X_proof (verify⟹valid).
COMPOSITION: shared state integrity, cross-system conservation, boundary validity.`,
    docs: ["INVARIANTS.md"],
  },
  semantic_mapping: {
    title: "Semantic Mapping",
    summary: `Maps concrete→formal: μ_S, μ_Σ, μ_T, μ_Tr.
Binding: μ_S(Apply_c(s_c, σ_c)) = Apply_f(μ_S(s_c), μ_Σ(σ_c)).
Principles: totality, determinism, canonicalization before interpretation, no hidden meaning.
Soundness: accepted concrete → valid formal. Completeness: realizable formal → exists concrete.`,
    docs: ["SEMANTIC_MAPPING.md"],
  },
  traces: {
    title: "Execution Trace Model",
    summary: `Trace: τ = (s_0, σ_0, s_1, ..., s_n). Entry: (id, pre_state, input, post_state, observable, metadata).
Commitment chain: h_{i+1} = Hash(h_i | Commit(e_i)). Replay: deterministic.
Reconstruction: Reconstruct(s_0, σ_0...σ_{n-1}) = τ.
Supports partial verification via Merkle proofs. Compression if semantics preserved.`,
    docs: ["EXECUTION_TRACE_MODEL.md"],
  },
  constraints: {
    title: "Constraint Derivation",
    summary: `D: SIR → C (deterministic, verifiable). Soundness + Completeness.
Domains: state vars, inputs, transitions, invariants, trace structure.
Rules: SIR→constraint templates. FORBIDDEN: manual injection, unconstrained vars, free witness.
Prevention: every variable constrained, witness uniquely determined, all branches constrained.`,
    docs: ["CONSTRAINT_DERIVATION.md"],
  },
  proofs: {
    title: "Proof Layer",
    summary: `π = Proof(τ, C) where Verify(π) ⟹ ValidTrace(τ). Object: (Com, W, Aux, Meta).
Public inputs: (root_init, root_final, inputs, outputs, domain).
Witness → single valid trace. STARKs, SNARKs, hybrid, recursion.
Domain separation mandatory. Knowledge soundness required. ZK optional.`,
    docs: ["PROOF_LAYER.md"],
  },
  verification: {
    title: "Verification Layer",
    summary: `Pipeline: domain→structural→commitment→crypto→semantic binding→invariant→accept/reject.
Modes: Full, Light, Recursive. Stateless vs Stateful.
Assumes malicious prover, adversarial inputs, crafted proofs.`,
    docs: ["VERIFICATION_LAYER.md"],
  },
  composition: {
    title: "Composition Model",
    summary: `Types: Parallel, Sequential, Shared-State, Cross-Triggered.
State: s_AB = (s_A, s_B, S_shared). Cross-transitions: T_cross.
Cross-invariants: resource conservation, state sync, causal consistency.
Proof: π_AB = Combine(π_A, π_B, π_cross).`,
    docs: ["COMPOSITION_MODEL.md"],
  },
  cryptography: {
    title: "Cryptographic Model",
    summary: `Hybrid: classical + quantum. Hash: SHA-3, BLAKE3, Poseidon.
Signatures: ECDSA/Ed25519 + ML-DSA/Falcon (both must verify).
Key exchange: ECDH + ML-KEM. Commitments: Merkle, FRI, KZG.
Domain separation everywhere. Cryptographic agility for migration.`,
    docs: ["CRYPTOGRAPHIC_MODEL.md"],
  },
  threats: {
    title: "Threat Model",
    summary: `Adversaries: Malicious Prover, Executor, Spec Manipulator, Constraint Attacker, Verifier-Limited, Economic.
Surfaces: Semantic Gap, Underconstrained, State Encoding Mismatch, Trace Incompleteness, Non-Determinism, Composition, Temporal.
Primary risk: "incorrect or incomplete definition of correctness itself."`,
    docs: ["THREAT_MODEL.md"],
  },
  audit: {
    title: "Self-Audit",
    summary: `Surfaces: semantic underspecification, invariant incompleteness, mapping drift, constraint under-specification, trace incompleteness, cross-layer drift, composition failure, temporal exploits, crypto fragility.
Strategies: Differential Execution, Invariant Fuzzing, Constraint Fuzzing, Trace Mutation, Witness Manipulation, Composition Stress.`,
    docs: ["SELF_AUDIT.md"],
  },
  roadmap: {
    title: "Roadmap",
    summary: `11 phases (0-10). Phase 0: Foundations. Phase 1: Execution. Phase 2: Semantic Alignment.
Phase 3: Constraints. Phase 4: Proof Binding. Phase 5: Verification. Phase 6: Composition.
Phase 7: Crypto Resilience. Phase 8: Temporal. Phase 9: Hardening. Phase 10: Pre-Production.
No phase advances without 100% compliance. Failure = rollback + fix + re-audit.`,
    docs: ["ROADMAP.MD"],
  },
  proof_obligations: {
    title: "Proof Obligations",
    summary: `Complete enumeration of propositions that must be demonstrably true.
Categories: Axioms (AX-1..6), Definitions (DEF-1..6), Semantic Lemmas (LEM-1..10),
Safety (SAFE-1..6), Liveness (LIVE-1..2), Composition (COMP-1..3),
Constraints (CONST-1..4), Proofs (PROOF-1..4).
Each has: category, layer, dependencies, falsification target, discharge method.
Dependency graph tracks what breaks if any obligation is unresolved.`,
    docs: ["PROOF_OBLIGATIONS.md"],
  },
  counterexamples: {
    title: "Counterexample Catalog",
    summary: `Explicit space of expected failures. Families: State (CEX-S1..4), Transition (CEX-T1..6),
Invariant (CEX-I1..3), Mapping (CEX-M1..4), Constraint (CEX-C1..5), Proof (CEX-P1..4),
Composition (CEX-COMP1..3), Trace (CEX-TR1..4), Temporal (CEX-TEMP1..3), Crypto (CEX-CRYPTO1..2).
Each has: target property, shape, construction strategy, detection method, severity.
"A property without a counterexample target is a prayer, not a guarantee."`,
    docs: ["COUNTEREXAMPLE_CATALOG.md"],
  },
  semantic_theorems: {
    title: "Semantic Preservation Theorems",
    summary: `17 commutativity theorems that must hold. THM-1: Execution-Mapping (fundamental).
THM-2: Observable. THM-3: Canonicalization. THM-4: Auxiliary exclusion. THM-5: Derived state.
THM-6: Trace validity. THM-7: Constraint semantics. THM-8: Proof binding (end-to-end).
THM-9..10: Composition. THM-11..13: Compression, batching, recursion.
THM-14..15: Error, no-op. THM-16..17: Temporal, monotonicity.
Each is a diagram that must commute. Non-commutativity = semantic drift.`,
    docs: ["SEMANTIC_PRESERVATION_THEOREMS.md"],
  },
  transition_partitioning: {
    title: "Transition Partitioning",
    summary: `Proves transition classes are exhaustive and disjoint.
Classes: Init, Update, No-Op, Error, Batch, Reject.
Priority: Reject > Init > Error > Batch > Update > No-Op.
Reachability regions: S_init, S_valid, S_error, S_syntactic (unreachable), S_invalid (empty).
Edge cases: empty input, auth without payload, batch of zero/one, recursive batch.
Guard overlap analysis with formal disjointness proofs.`,
    docs: ["TRANSITION_PARTITIONING.md"],
  },
  underconstraint: {
    title: "Underconstraint Analysis",
    summary: `8 types: U1 free variable, U2 weakly constrained, U3 missing branch, U4 structural-only,
U5 orphan, U6 range cosmetic, U7 temporal, U8 composition.
Dangerous patterns: carry-over assumption, range illusion, branch blindspot,
commitment shortcut, temporal gap, authorization disconnect.
Per-template threat analysis. Witness freedom analysis. Constraint coupling analysis.`,
    docs: ["UNDERCONSTRAINT_ANALYSIS.md"],
  },
  coverage_matrix: {
    title: "Constraint Coverage Matrix",
    summary: `Traceability: semantic properties × transition classes × constraint IDs.
Includes: invariant×transition, field×transition, carry-over table, proof obligation mapping.
Every cell must be "Full". Every gap is a finding.
"A constraint without traceability is noise. A property without traceability is a wish."`,
    docs: ["CONSTRAINT_COVERAGE_MATRIX.md"],
  },
  witness_uniqueness: {
    title: "Witness Uniqueness & Non-Malleability",
    summary: `3 levels: semantic (required), structural (desired), computational (ideal).
6 malleability classes: state substitution, input substitution, observable manipulation,
authorization rebinding, temporal reordering, cross-proof sharing.
4 formal conditions: transition determinism, input commitment, observable determination, auxiliary independence.
"A malleable witness is a proof that says 'something happened' without committing to what."`,
    docs: ["WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md"],
  },
  assume_guarantee: {
    title: "Assume-Guarantee Composition",
    summary: `Contract per subsystem: Assumes, Guarantees, Exports, Effects, Forbids, Temporal.
Composition rule: G(A)⊇A(B) ∧ G(B)⊇A(A) ∧ Eff∩F=∅ ∧ temporal compatible ∧ no escape.
Cross-invariants: CI-1..5. Upgrade: A(v2)⊆A(v1), G(v2)⊇G(v1).
"Compatible is not a feeling. It is a theorem."`,
    docs: ["ASSUME_GUARANTEE_MODEL.md"],
  },
  long_term_security: {
    title: "Long-Term Security Model",
    summary: `4 horizons: T1 ephemeral, T2 session, T3 archival, T4 permanent.
Artifacts classified: commitments (T3-T4), signatures (T2-T3), proofs (T3-T4), keys (varies).
Migration protocols: commitment, signature, proof migration with attestation chains.
Degradation model per primitive break. Archive requirements for re-proving.
"Long-term security is about surviving being wrong about which algorithm was right."`,
    docs: ["LONG_TERM_SECURITY_MODEL.md"],
  },
  trace_sufficiency: {
    title: "Trace Sufficiency",
    summary: `6 conditions: state determinism, input completeness, observable completeness,
ordering completeness, environment completeness, no hidden transitions.
Theorems: trace determines execution, commitment determines trace, sufficiency for reconstruction.
3 verification levels: commitment-only, transition, full reconstruction.
Insufficiency scenarios: commitment-only trace, summarized inputs, missing environment.`,
    docs: ["TRACE_SUFFICIENCY.md"],
  },
  refinement: {
    title: "Refinement Strategy",
    summary: `5 levels: Abstract Spec → SIR → Concrete → Constraints → Proof.
Each refinement: simulation condition + invariant preservation + observable preservation.
End-to-end: Verify(π) ⟹ ValidFormalTrace(τ_f).
Methods: Lean 4/Coq for proofs, TLA+ for model checking, differential testing.
"VSEL without refinement proofs is documents that agree in spirit. With them, a chain of mathematical guarantees."`,
    docs: ["REFINEMENT_STRATEGY.md"],
  },
  edge_cases: {
    title: "Edge Case Atlas",
    summary: `9 families: canonical/derived boundary, input payload vs auth, error/no-op transitions,
batching (order-dependent, intermediate violation, batch-of-one, max size, duplicates, atomicity),
trace compression, composition/cross-version, temporal/replay,
economically absurd (zero-value, self-transfer, dust, fee>value, max values), cryptographic.
Each with scenario, impact, trigger, test strategy.`,
    docs: ["EDGE_CASE_ATLAS.md"],
  },
  model_checking: {
    title: "Model Checking Plan",
    summary: `TLA+ with TLC. Abstraction: 5-value balance, 3 accounts, 2 keys, bounded traces.
Properties: safety invariants, temporal LTL, transition partitioning, composition.
Fairness: weak (liveness), strong (composition), none (adversarial).
Phases aligned with roadmap. Counterexample preservation protocol.
"Model checking searches for counterexamples. Value is in what it fails to find."`,
    docs: ["MODEL_CHECKING_PLAN.md"],
  },
  theorem_proving: {
    title: "Theorem Proving Plan",
    summary: `Lean 4 (primary) + Coq (highest assurance). 16 theorems P0-P2.
P0: refinement (TP-1..3), invariant preservation (TP-4..6).
P1: mapping (TP-7..10), structural (TP-11..13).
P2: composition (TP-14..15), witness (TP-16).
Proof library structure. 6-9 month estimate.
"Theorem proving establishes universal truths. Model checking finds counterexamples. Both required."`,
    docs: ["THEOREM_PROVING_PLAN.md"],
  },
  invalid_witnesses: {
    title: "Invalid Execution Witness Suite",
    summary: `8 families: W1 state violation (negative balance, inconsistent derived, invalid env, metadata regression, unreachable state),
W2 transition violation (arbitrary jump, hidden mutation, resource creation/destruction, unauthorized, precondition-violating),
W3 trace structure (broken chain, missing transition, reordered, duplicate, invalid initial),
W4 observable manipulation, W5 authorization manipulation, W6 batch manipulation,
W7 commitment manipulation, W8 cross-system.
Protocol: construct → verify rejection → identify constraint → remove → confirm necessity.`,
    docs: ["INVALID_EXECUTION_WITNESS_SUITE.md"],
  },
  audit_evidence: {
    title: "Audit Evidence Model",
    summary: `Schema: id, phase, category, hypothesis, method, artifact, failure class, result, severity, remediation, evidence, reproducibility.
6 categories: formal verification, differential testing, constraint analysis, adversarial testing, code review, compliance.
Lifecycle: discovery → documentation → triage → remediation → verification → closure.
Evidence must be committed, timestamped, signed, immutable, reproducible.
"An audit without reproducible evidence is a conversation."`,
    docs: ["AUDIT_EVIDENCE_MODEL.md"],
  },
  economic_invariants: {
    title: "Economic Invariants",
    summary: `Economic semantics as first-class invariant domain. State extended: s = (C, D, E, Ω, τ) where Ω = DeriveEconomic(C, E).
Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s).

LOCAL: E_cost (non-zero acquisition), E_leverage (bounded), E_proportionality (fee), E_slippage (price impact), E_collateral.
GLOBAL: G_solvency, G_concentration, G_liquidity, G_dust.
TEMPORAL: TE_extraction (bounded epoch extraction), TE_flash (flash collateral), TE_sandwich (anti-sandwich),
TE_manipulation (price manipulation resistance), TE_velocity (wash trading bounds).
COMPOSITIONAL: CE_arbitrage, CE_contagion.

Domain expert integration: semi-formal expression → formal translation → integration → validation.
"Economic semantics is not a soft requirement. It is a formal requirement that was previously missing."`,
    docs: ["ECONOMIC_INVARIANTS.md"],
  },
};

const VALID_TOPICS = Object.keys(KNOWLEDGE);

server.tool(
  "vsel_query",
  "Query VSEL knowledge base by topic. Returns structured knowledge about a specific aspect of the VSEL architecture.",
  { topic: z.enum(VALID_TOPICS).describe("Topic to query") },
  async ({ topic }) => {
    const entry = KNOWLEDGE[topic];
    return {
      content: [{ type: "text", text: `# ${entry.title}\n\n${entry.summary}\n\nRelated docs: ${entry.docs.join(", ")}` }],
    };
  }
);

server.tool(
  "vsel_topics",
  "List all available VSEL knowledge topics",
  {},
  async () => {
    const topics = VALID_TOPICS.map((k) => `- ${k}: ${KNOWLEDGE[k].title}`).join("\n");
    return { content: [{ type: "text", text: `# VSEL Knowledge Topics\n\n${topics}` }] };
  }
);

server.tool(
  "vsel_read_doc",
  "Read a raw VSEL documentation file",
  { filename: z.string().describe("Filename from docs/ directory, e.g. WHITEPAPER.md") },
  async ({ filename }) => {
    try {
      const content = readFileSync(join(DOCS_DIR, filename), "utf-8");
      return { content: [{ type: "text", text: content }] };
    } catch {
      return { content: [{ type: "text", text: `Error: file '${filename}' not found in docs/` }], isError: true };
    }
  }
);

server.tool(
  "vsel_list_docs",
  "List all VSEL documentation files",
  {},
  async () => {
    try {
      const files = readdirSync(DOCS_DIR).filter((f) => f.endsWith(".md") || f.endsWith(".MD"));
      return { content: [{ type: "text", text: `# VSEL Documentation Files\n\n${files.map((f) => `- ${f}`).join("\n")}` }] };
    } catch {
      return { content: [{ type: "text", text: "Error: could not read docs directory" }], isError: true };
    }
  }
);

server.tool(
  "vsel_search",
  "Search across all VSEL knowledge for a keyword or concept",
  { query: z.string().describe("Search term or concept") },
  async ({ query }) => {
    const q = query.toLowerCase();
    const results = [];
    for (const [key, entry] of Object.entries(KNOWLEDGE)) {
      if (entry.title.toLowerCase().includes(q) || entry.summary.toLowerCase().includes(q)) {
        results.push({ topic: key, title: entry.title, match: entry.summary.substring(0, 200) + "..." });
      }
    }
    if (results.length === 0) {
      return { content: [{ type: "text", text: `No results for "${query}"` }] };
    }
    const text = results.map((r) => `## ${r.title} (topic: ${r.topic})\n${r.match}`).join("\n\n");
    return { content: [{ type: "text", text }] };
  }
);


const PHASES = {
  0: {
    name: "Foundations of Truth",
    objective: "Define what 'correct' means",
    microphases: [
      "0.1 Formal Specification Completion — finalize S, Σ, T, O",
      "0.2 Invariant System Definition — define all G, classify, prove non-contradiction",
      "0.3 Semantic Mapping Definition — define μ_S, μ_Σ, ensure totality/determinism",
      "0.4 State Machine Finalization — transition graph, reachability, eliminate undefined states",
    ],
    audit: "Find undefined behavior, contradictory invariants, incomplete mappings",
    new_artifacts: "PROOF_OBLIGATIONS.md, COUNTEREXAMPLE_CATALOG.md, TRANSITION_PARTITIONING.md, EDGE_CASE_ATLAS.md",
  },
  1: {
    name: "Execution Ground Truth",
    objective: "Ensure execution matches semantics exactly",
    microphases: [
      "1.1 Execution Engine — deterministic execution, strict pipeline",
      "1.2 Trace Model — full capture, canonical encoding, hash chaining",
      "1.3 Replay System — reconstruct from trace, enforce determinism",
    ],
    audit: "Find non-determinism, hidden state mutation, incomplete trace. If replay fails once, phase fails.",
    new_artifacts: "TRACE_SUFFICIENCY.md validation",
  },
  2: {
    name: "Semantic Alignment",
    objective: "Ensure implementation equals formal model",
    microphases: [
      "2.1 Mapping Enforcement Layer — implement μ_S, μ_Σ",
      "2.2 Differential Execution Framework — impl vs formal model",
      "2.3 Canonicalization Enforcement — normalize all inputs/states",
    ],
    audit: "Find semantic drift, mapping ambiguity, inconsistent outputs",
    new_artifacts: "SEMANTIC_PRESERVATION_THEOREMS.md validation, REFINEMENT_STRATEGY.md R₁₂ discharge",
  },
  3: {
    name: "Constraint Integrity",
    objective: "Encode semantics into constraints without loss",
    microphases: [
      "3.1 Constraint Generator — derive from SIR, eliminate manual",
      "3.2 Constraint Coverage Validation — full transition coverage",
      "3.3 Constraint Soundness Testing — no invalid execution satisfies constraints",
    ],
    audit: "Find underconstrained vars, missing constraints, satisfiable invalid traces",
    new_artifacts: "UNDERCONSTRAINT_ANALYSIS.md, CONSTRAINT_COVERAGE_MATRIX.md, INVALID_EXECUTION_WITNESS_SUITE.md",
  },
  4: {
    name: "Proof System Binding",
    objective: "Bind execution truth to cryptographic proof",
    microphases: [
      "4.1 Proof Construction — bind to full trace, witness uniqueness",
      "4.2 Public Input Definition — minimal, sufficient",
      "4.3 Domain Separation Enforcement — prevent cross-proof reuse",
    ],
    audit: "Find proof reuse, ambiguous witness, partial trace proof",
    new_artifacts: "WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md validation",
  },
  5: {
    name: "Verification Authority",
    objective: "Ensure verifier enforces correctness completely",
    microphases: [
      "5.1 Verifier Implementation — strict validation pipeline",
      "5.2 Verification Completeness — all constraints, commitments, invariants",
      "5.3 Failure Handling — reject invalid proofs deterministically",
    ],
    audit: "Find verifier shortcuts, partial validation, acceptance of invalid proofs",
    new_artifacts: "End-to-end refinement chain (REFINEMENT_STRATEGY.md) validation",
  },
  6: {
    name: "Composition Survival",
    objective: "Ensure correctness survives interaction",
    microphases: [
      "6.1 Cross-System State Model — define shared state",
      "6.2 Cross-Invariant Definition — enforce global constraints",
      "6.3 Cross-Trace Composition — merge traces correctly",
    ],
    audit: "Find cross-system inconsistency, invariant break across boundaries, ordering mismatch",
    new_artifacts: "ASSUME_GUARANTEE_MODEL.md validation",
  },
  7: {
    name: "Cryptographic Resilience",
    objective: "Ensure long-term security",
    microphases: [
      "7.1 Hybrid Cryptography Integration — classical + PQC",
      "7.2 Key Lifecycle Implementation — generation, rotation, revocation",
      "7.3 Commitment Integrity — enforce collision resistance",
    ],
    audit: "Find key compromise, signature forgery, proof forgery under PQC",
    new_artifacts: "LONG_TERM_SECURITY_MODEL.md validation",
  },
  8: {
    name: "Temporal Robustness",
    objective: "Ensure correctness holds over time",
    microphases: [
      "8.1 Long Trace Simulation — extended execution",
      "8.2 Temporal Invariant Enforcement — sequence-based constraints",
      "8.3 Replay Resistance — prevent reuse attacks",
    ],
    audit: "Find delayed invariant failure, replay exploits, time-based inconsistencies",
    new_artifacts: "Temporal counterexamples (CEX-TEMP) validation",
  },
  9: {
    name: "System Hardening",
    objective: "Prepare for hostile environment",
    microphases: [
      "9.1 Full-System Fuzzing — all inputs, all states",
      "9.2 Adversarial Scenario Simulation — worst-case execution",
      "9.3 Failure Recovery Testing — deterministic recovery",
    ],
    audit: "Find emergent failures, undefined behavior, cascading errors",
    new_artifacts: "Full INVALID_EXECUTION_WITNESS_SUITE.md execution",
  },
  10: {
    name: "Pre-Production Gate",
    objective: "Final validation",
    microphases: [
      "All phases passed",
      "All audits resolved",
      "Zero unresolved findings",
      "Full-system adversarial audit",
    ],
    audit: "Complete adversarial audit: semantic + crypto + composition + temporal",
    new_artifacts: "AUDIT_EVIDENCE_MODEL.md — complete evidence trail",
  },
};

server.tool(
  "vsel_phase",
  "Get detailed information about a specific VSEL roadmap phase (0-10)",
  { phase: z.number().min(0).max(10).describe("Phase number (0-10)") },
  async ({ phase }) => {
    const p = PHASES[phase];
    const text = `# Phase ${phase}: ${p.name}\n\nObjective: ${p.objective}\n\nMicrophases:\n${p.microphases.map((m) => `- ${m}`).join("\n")}\n\nAudit focus: ${p.audit}\n\nKey artifacts: ${p.new_artifacts}`;
    return { content: [{ type: "text", text }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
