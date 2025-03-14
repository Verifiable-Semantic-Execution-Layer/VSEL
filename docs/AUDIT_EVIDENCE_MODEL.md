**Verifiable Semantic Execution Layer (VSEL)**

# AUDIT EVIDENCE MODEL

## 1. Purpose

This document defines how every audit finding, verification result, and compliance artifact must be captured, structured, and preserved.

Without this model, audits produce opinions. With it, they produce evidence.

> An audit without reproducible evidence is a conversation. An audit with reproducible evidence is a proof of diligence.

---

## 2. Evidence Structure

Every audit artifact follows this schema:

```
AuditEvidence {
  id: String,                    // Unique identifier (AE-PHASE-NUMBER)
  phase: UInt,                   // Roadmap phase (0-10)
  category: EvidenceCategory,    // Type of evidence
  hypothesis: String,            // What was being tested/verified
  method: VerificationMethod,    // How it was tested
  artifact_evaluated: String,    // Which document/code/component
  failure_class_sought: String,  // What class of failure was targeted
  result: Result,                // Pass / Fail / Inconclusive
  finding: String?,              // Description if Fail
  severity: Severity?,           // If finding exists
  remediation: String?,          // Fix applied
  remediation_verified: Boolean, // Was the fix re-audited?
  evidence_artifact: String,     // Reference to reproducible evidence
  reproducibility: String,       // How to reproduce the result
  auditor: String,               // Who performed the audit
  date: Date,                    // When
  status: Status                 // Open / Remediated / Verified / Accepted-Risk
}
```

---

## 3. Evidence Categories

### CAT-1: Formal Verification Evidence

Evidence from model checking or theorem proving.

```
{
  tool: "TLA+ / Coq / Lean / Isabelle",
  property_checked: String,
  model_version: String,
  state_space_size: UInt?,
  counterexample: Trace?,       // If found
  proof_artifact: String?,      // If proven
  runtime: Duration,
  configuration: String         // Parameters, bounds, fairness assumptions
}
```

### CAT-2: Differential Testing Evidence

Evidence from comparing implementation against specification.

```
{
  implementation_version: String,
  specification_version: String,
  test_cases: UInt,
  mismatches_found: UInt,
  mismatch_details: [MismatchRecord],
  coverage: CoverageReport
}
```

### CAT-3: Constraint Analysis Evidence

Evidence from constraint system analysis.

```
{
  constraint_system_version: String,
  analysis_type: "static / symbolic / fuzzing",
  variables_analyzed: UInt,
  free_variables_found: UInt,
  underconstrained_fields: [String],
  invalid_witnesses_tested: UInt,
  invalid_witnesses_rejected: UInt,
  invalid_witnesses_accepted: UInt  // MUST BE ZERO
}
```

### CAT-4: Adversarial Testing Evidence

Evidence from adversarial attack simulation.

```
{
  attack_class: String,
  attack_description: String,
  target_property: String,
  attack_successful: Boolean,
  exploit_trace: Trace?,
  mitigation_applied: String?,
  mitigation_verified: Boolean
}
```

### CAT-5: Code Review Evidence

Evidence from manual or automated code review.

```
{
  component_reviewed: String,
  reviewer: String,
  findings: [Finding],
  coverage: String,
  methodology: String
}
```

### CAT-6: Compliance Evidence

Evidence of compliance with specification requirements.

```
{
  requirement_id: String,
  requirement_text: String,
  compliance_status: "compliant / non-compliant / partial / N/A",
  evidence_reference: String,
  gap_description: String?
}
```

---

## 4. Severity Classification

| Severity | Definition | Required Response |
|----------|-----------|-------------------|
| Catastrophic | System correctness guarantee is broken | Immediate halt. Full remediation. Re-audit. |
| Critical | Significant semantic gap exploitable by adversary | Block phase progression. Remediate. Re-audit. |
| Serious | Weakness that could lead to failure under specific conditions | Remediate before phase completion. |
| Moderate | Improvement needed but no immediate exploit path | Track. Remediate within next phase. |
| Informational | Observation for future consideration | Document. No immediate action required. |

---

## 5. Evidence Lifecycle

```
Discovery → Documentation → Triage → Remediation → Verification → Closure
```

### Stage 1: Discovery
Finding is identified during audit activity.
Evidence artifact is created immediately.

### Stage 2: Documentation
Full AuditEvidence record is created.
Reproducibility instructions are written.

### Stage 3: Triage
Severity is assigned.
Responsible party is identified.
Timeline is set.

### Stage 4: Remediation
Fix is implemented.
Fix is documented with reference to original finding.

### Stage 5: Verification
Fix is independently verified.
Original test/check is re-run.
New evidence artifact is created.

### Stage 6: Closure
Status is set to Verified.
Evidence chain is complete.

---

## 6. Phase Audit Requirements

Each roadmap phase must produce:

```
PHASE_X_AUDIT_REPORT.md
  - Summary of audit scope
  - Methods used
  - Findings (with severity)
  - Evidence references

PHASE_X_FINDINGS.md
  - Detailed finding descriptions
  - Counterexample traces (if any)
  - Proof artifacts (if any)

PHASE_X_REMEDIATION.md
  - Fix descriptions
  - Verification results
  - Re-audit evidence

PHASE_X_COMPLIANCE.md
  - Per-requirement compliance status
  - Evidence references
  - Gap analysis
```

Phase progression requires:
```
∀ findings with severity ≥ Serious: status = Verified
∀ requirements: compliance_status = compliant
```

---

## 7. Evidence Integrity

All evidence artifacts must be:

### 7.1 Committed
```
Commit(evidence) = Hash(evidence_content)
```

Evidence commitments are stored in the audit trail.

### 7.2 Timestamped
```
Timestamp(evidence) = trusted_time_source
```

### 7.3 Signed
```
Sign(evidence, auditor_key)
```

### 7.4 Immutable
Once created, evidence artifacts cannot be modified. Corrections create new artifacts referencing the original.

### 7.5 Reproducible
Every evidence artifact must include sufficient information to reproduce the result independently.

---

## 8. Audit Trail Structure

```
audit/
├── phase_0/
│   ├── AUDIT_REPORT.md
│   ├── FINDINGS.md
│   ├── REMEDIATION.md
│   ├── COMPLIANCE.md
│   └── evidence/
│       ├── AE-0-001.json      // Model checking result
│       ├── AE-0-002.json      // Invariant analysis
│       ├── AE-0-003.json      // Counterexample trace
│       └── ...
├── phase_1/
│   └── ...
└── ...
```

---

## 9. Continuous Audit Integration

Audit is not a phase-end activity. It is continuous.

### 9.1 Automated Checks
- Model checking runs on every specification change
- Constraint analysis runs on every constraint change
- Differential testing runs on every implementation change

### 9.2 Regression Evidence
Every fix must include a regression test that:
- Reproduces the original finding
- Verifies the fix prevents it
- Is added to the continuous test suite

### 9.3 Evidence Freshness
Evidence older than the last relevant change is stale and must be refreshed.

```
∀ evidence E referencing artifact A:
  E.date > A.last_modified
  OR E is marked stale and must be refreshed
```

---

## 10. Audit Independence

### 10.1 Self-Audit
Performed by the development team.
Produces evidence but with inherent bias.

### 10.2 Independent Audit
Performed by external party.
Required for Phase 10 (Pre-Production Gate).

### 10.3 Adversarial Audit
Performed by party incentivized to find failures.
Highest value evidence.

All three types must be represented in the evidence trail.

---

## 11. Non-Negotiable Rules

1. No finding may be closed without verified remediation evidence
2. No phase may progress with open Catastrophic or Critical findings
3. No evidence may be modified after creation
4. No audit may be performed by the author of the audited component (for independent audit)
5. No "accepted risk" classification for Catastrophic findings

---

## 12. Closing Statement

This model exists to make accountability concrete.

Every claim about the system's correctness must be backed by evidence. Every evidence artifact must be reproducible. Every finding must be resolved.

The alternative is trust. And trust, in adversarial systems, is the first thing that fails.
