**Verifiable Semantic Execution Layer (VSEL)**

## 1. Purpose

This document defines the semantic binding between the formal specification of VSEL and its concrete execution artifacts.

Its purpose is to eliminate ambiguity between:

* the formal state machine defined in `FORMAL_SPECIFICATION.md`
* the invariant system defined in `INVARIANTS.md`
* the concrete execution layer
* the constraint and proof layers derived from execution

The core objective is simple and unforgiving:

> Every concrete execution accepted by the system must map to a valid formal execution trace, and every formally valid execution intended to be realizable must have a corresponding concrete representation.

This document therefore defines the mapping between:

* concrete state and formal state
* concrete inputs and formal inputs
* concrete transitions and formal transitions
* concrete observables and formal observables
* concrete traces and formal traces

If any behavior exists in the implementation but is not represented here, it is outside the trusted semantics of the system and must be treated as invalid.

---

## 2. Semantic Mapping Objective

Let:

* ( S_c ) be the set of concrete states
* ( \Sigma_c ) be the set of concrete inputs
* ( Tr_c ) be the set of concrete execution traces

And let:

* ( S_f ) be the formal state space
* ( \Sigma_f ) be the formal input space
* ( Tr_f ) be the formal trace language

We define semantic mapping functions:

[
\mu_S : S_c \rightarrow S_f
]

[
\mu_\Sigma : \Sigma_c \rightarrow \Sigma_f
]

[
\mu_T : (S_c, \Sigma_c, S_c) \rightarrow (S_f, \Sigma_f, S_f)
]

[
\mu_{Tr} : Tr_c \rightarrow Tr_f
]

The correctness requirement is:

[
ValidConcreteTrace(\tau_c) \Rightarrow ValidTrace(\mu_{Tr}(\tau_c))
]

This means that concrete execution has no independent authority. Its meaning exists only through the formal model.

---

## 3. Mapping Principles

The semantic mapping layer obeys the following principles.

### 3.1 Totality Over Accepted Execution

For any concrete artifact accepted by the trusted execution pipeline, the mapping must be defined.

[
\forall x \in AcceptedConcreteArtifacts : \mu(x) \text{ is defined}
]

No accepted execution may fall into a semantic gray zone.

### 3.2 Determinism

The mapping must be deterministic.

[
\forall x : \mu(x) = y \Rightarrow \nexists y' \neq y
]

A concrete artifact may not have multiple formal interpretations.

### 3.3 Canonicalization Before Interpretation

All concrete inputs and states must be canonicalized before semantic interpretation.

This prevents semantically equivalent but structurally distinct representations from being interpreted inconsistently.

### 3.4 No Hidden Meaning

No semantic fact may depend on data that is not either:

* represented in the formal model, or
* explicitly marked as non-semantic auxiliary data

### 3.5 Closed Semantic Domain

If a concrete behavior cannot be mapped into the formal model, it is invalid by definition.

This is not a limitation. It is the only way to avoid semantic drift.

---

## 4. Concrete-to-Formal State Mapping

A concrete state ( s_c \in S_c ) may contain:

* raw storage layout
* runtime memory
* commitments
* caches
* metadata
* logs
* auxiliary execution artifacts

The formal state ( s_f = \mu_S(s_c) \in S_f ) contains only semantically relevant information.

We define:

[
s_c = (C_{raw}, D_{aux}, E_{ctx}, M_{meta})
]

[
s_f = (C, D, E, \tau)
]

Where:

* ( C ) is canonical semantic state
* ( D ) is derived semantic state
* ( E ) is modeled environment
* ( \tau ) is formal trace metadata

The mapping function must specify, field by field:

[
\mu_S(s_c) = \big(\mu_C(C_{raw}), \mu_D(D_{aux}), \mu_E(E_{ctx}), \mu_\tau(M_{meta})\big)
]

### 4.1 Canonical State Extraction

The canonical portion of state must be extracted from raw storage without interpretation ambiguity.

Examples include:

* balances extracted from fixed slots
* account sets extracted from indexed structures
* commitment roots recomputed from canonical state rather than trusted from cache

If the same semantic state can be produced from multiple incompatible raw encodings, the raw state model is underspecified.

### 4.2 Derived State Mapping

Derived state may include:

* Merkle roots
* aggregate counters
* cached commitments
* indexing structures

Derived state is semantically valid only if it is functionally determined by canonical state:

[
D = Derive(C)
]

Thus:

[
\mu_D(D_{aux}) = D \iff D = Derive(\mu_C(C_{raw}))
]

Any derived field that cannot be recomputed from canonical semantics must not be trusted as semantic input.

### 4.3 Environment Mapping

Environmental inputs such as timestamps, block height, or domain parameters must be explicitly modeled.

[
\mu_E(E_{ctx}) = E
]

No external dependency may influence semantics unless it appears in ( E ).

This includes randomness. If randomness exists, it must be reified as input or environment state. Human beings love pretending entropy is magic. It is not.

### 4.4 Metadata Mapping

Trace metadata must be mapped to formal metadata only insofar as it is semantically relevant.

Examples:

* sequence index
* prior commitment root
* execution epoch
* replay domain

Auxiliary metadata such as debug counters or instrumentation tags must be excluded from semantic state.

---

## 5. Concrete-to-Formal Input Mapping

Let ( \sigma_c \in \Sigma_c ) be a concrete input.

This may include:

* encoded transaction bytes
* calldata
* signed messages
* command packets
* auxiliary witness hints

The formal input is:

[
\sigma_f = \mu_\Sigma(\sigma_c)
]

### 5.1 Input Canonicalization

Before semantic interpretation, concrete input must be normalized into a canonical form.

This includes:

* field normalization
* ordering normalization
* removal of redundant encoding differences
* strict decoding rules

Equivalent semantic intent must produce identical formal input.

### 5.2 Signature and Authentication Separation

Authentication artifacts such as signatures are not themselves semantic transitions. They are admission conditions on inputs.

Therefore, input mapping separates:

* semantic command payload
* authorization evidence

Formally:

[
\sigma_c = (\sigma_{payload}, \sigma_{auth}, \sigma_{aux})
]

[
\mu_\Sigma(\sigma_c) = Interpret(\sigma_{payload})
]

Subject to:

[
AuthValid(\sigma_{auth}, \sigma_{payload}) = true
]

If authentication affects semantics, that effect must be explicitly modeled, not smuggled in through parsing logic.

### 5.3 Auxiliary Input Exclusion

Inputs used only to assist proving, indexing, or optimization must not affect semantic interpretation.

If a proving hint changes the meaning of execution, the system is already compromised.

---

## 6. Transition Mapping

A concrete transition is represented as:

[
t_c = (s_c, \sigma_c, s'_c)
]

Its formal image is:

[
\mu_T(t_c) = (\mu_S(s_c), \mu_\Sigma(\sigma_c), \mu_S(s'_c))
]

The mapping is valid only if:

[
Apply(\mu_S(s_c), \mu_\Sigma(\sigma_c)) = \mu_S(s'_c)
]

This is the semantic binding condition.

### 6.1 Transition Preservation Condition

For every accepted concrete transition:

[
AcceptedConcreteTransition(t_c) \Rightarrow ValidTransition(\mu_T(t_c))
]

If this implication fails, the implementation and the specification are not aligned.

### 6.2 No Transition Inflation

A single concrete transition may not implicitly encode multiple formal transitions unless that bundling is explicitly modeled.

If batching exists, then batching is a first-class semantic construct.

### 6.3 No Transition Elision

Every semantically relevant state change must correspond to a formal transition.

Logging it later does not count. Human systems adore retroactive honesty. Formal systems do not.

---

## 7. Observable Mapping

Formal observables are the externally meaningful outputs of execution.

Let:

[
Obs_c : (s_c, \sigma_c, s'_c) \rightarrow O_c
]

[
Obs_f : (s_f, \sigma_f, s'_f) \rightarrow O_f
]

We require a mapping:

[
\mu_O : O_c \rightarrow O_f
]

Such that:

[
\mu_O(Obs_c(s_c, \sigma_c, s'_c)) = Obs_f(\mu_T(s_c, \sigma_c, s'_c))
]

This ensures that external behavior is semantically faithful.

### 7.1 Observable Completeness

Every semantically relevant external effect must appear in the formal observable set.

Examples include:

* state commitments
* emitted events with semantic value
* output messages
* settlement effects
* externally consumable attestations

### 7.2 Observable Exclusion

Operational artifacts that do not affect semantics may be excluded, including:

* profiling output
* debug logs
* internal counters with no semantic role

The criterion is simple: if a consumer could rely on it for correctness, it belongs in the formal observable space.

---

## 8. Trace Mapping

A concrete trace is a sequence:

[
\tau_c = (s_{c,0}, \sigma_{c,0}, s_{c,1}, \sigma_{c,1}, ..., s_{c,n})
]

The corresponding formal trace is:

[
\mu_{Tr}(\tau_c) = (\mu_S(s_{c,0}), \mu_\Sigma(\sigma_{c,0}), \mu_S(s_{c,1}), ..., \mu_S(s_{c,n}))
]

The trace mapping is valid only if:

[
ValidTrace(\mu_{Tr}(\tau_c))
]

### 8.1 Trace Completeness

Every semantically relevant transition must appear in the concrete trace prior to mapping.

No hidden transitions may exist between recorded steps.

### 8.2 Trace Order Preservation

The ordering relation in concrete traces must be preserved semantically.

[
Order_c(i,j) \Rightarrow Order_f(i,j)
]

Unless the formal model explicitly defines commutative equivalence classes.

### 8.3 Replay Stability

The mapped formal trace must be stable under replay of the same canonical concrete trace.

This prevents interpretation from depending on ephemeral runtime details.

---

## 9. Semantic Admissibility Conditions

A concrete artifact is semantically admissible if and only if:

1. it is canonicalizable
2. its mapping is defined
3. its mapped form satisfies the formal model
4. all required observables are preserved
5. no excluded auxiliary data influences meaning

Formally, for a concrete transition ( t_c ):

[
Admissible(t_c) \equiv Canonical(t_c) \land Defined(\mu_T(t_c)) \land ValidTransition(\mu_T(t_c))
]

Anything else is rejected.

---

## 10. Semantic Non-Equivalence Cases

Two concrete artifacts that appear operationally similar may still be semantically distinct.

The mapping layer must explicitly distinguish cases where differences affect:

* authorization domain
* ordering semantics
* commitment roots
* replay scope
* environment assumptions
* boundary visibility

Likewise, two structurally distinct concrete artifacts may map to the same formal semantics after canonicalization.

This is allowed only if their semantic effect is identical.

---

## 11. Mapping Soundness and Completeness

The semantic mapping must satisfy two core properties.

### 11.1 Soundness

If a concrete artifact is accepted, its formal image is valid.

[
AcceptedConcreteArtifact(x) \Rightarrow ValidFormalArtifact(\mu(x))
]

### 11.2 Completeness

If a formal execution is intended to be realizable by the system, there exists at least one admissible concrete realization.

[
RealizableFormalArtifact(y) \Rightarrow \exists x : \mu(x) = y
]

If soundness fails, invalid executions slip through.
If completeness fails, the formal model describes fantasies instead of the system.

Both failures are common. People still act surprised.

---

## 12. Cross-Layer Mapping Obligations

The mapping layer defines obligations for downstream components.

### 12.1 Execution Layer Obligation

Execution must emit enough concrete state and trace material for semantic reconstruction.

### 12.2 Constraint Layer Obligation

Constraints must encode validity over mapped formal artifacts, not over ad hoc concrete structure unless explicitly justified.

### 12.3 Proof Layer Obligation

Proof statements must quantify over semantically mapped executions.

### 12.4 Verification Layer Obligation

Verification must validate that the proof corresponds to the mapped formal meaning, not merely to syntactic witness satisfaction.

---

## 13. Failure Modes

The semantic mapping layer is considered broken if any of the following occur.

### 13.1 Ambiguous State Interpretation

A concrete state maps to multiple formal states.

### 13.2 Missing Semantic Coverage

A concrete execution path exists that cannot be mapped.

### 13.3 Hidden Semantic Dependency

Meaning depends on auxiliary data excluded from the model.

### 13.4 Invalid Observable Projection

External effects cannot be reconstructed from formal transitions.

### 13.5 Non-Canonical Acceptance

Two non-canonical concrete artifacts with different structural properties are accepted as if equivalent without formal justification.

### 13.6 Drift Between Implementation and Model

The implementation evolves, but mapping rules do not.

This one is especially popular. Teams call it “shipping fast” right before disaster becomes a roadmap item.

---

## 14. Minimal Validation Procedures

The semantic mapping layer must be validated through:

* differential execution against the formal model
* canonicalization tests
* ambiguity detection tests
* round-trip mapping checks where applicable
* adversarial malformed input testing
* trace completeness audits
* witness independence testing for semantic interpretation

A useful validation property is the following commutativity condition:

[
\mu_S(Apply_c(s_c, \sigma_c)) = Apply_f(\mu_S(s_c), \mu_\Sigma(\sigma_c))
]

For all admissible ( s_c, \sigma_c ).

If this fails, the mapping is not semantics-preserving.

---

## 15. Closing Statement

The semantic mapping layer is where VSEL either becomes a system of meaning or remains a system of artifacts.

The formal model does not protect the implementation unless the implementation is bound to it with deterministic, explicit, adversarially testable semantics.

If the mapping is loose, the proof is theater.
If the mapping is strict, the proof starts to mean something.
