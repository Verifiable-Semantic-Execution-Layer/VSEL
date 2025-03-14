**Verifiable Semantic Execution Layer (VSEL)**

# ECONOMIC INVARIANTS

## 1. Purpose

This document formalizes economic semantics as a first-class invariant domain within VSEL.

Economic correctness is not an annotation, a guideline, or a domain expert's intuition. It is a set of formally defined predicates over states and traces that must be enforced with the same rigor as structural invariants.

The principle is unchanged:

> If it is not in the specification, it is invalid.

This applies to economic intent exactly as it applies to state validity, resource conservation, and transition determinism. A state that satisfies all structural invariants but represents an economically absurd or exploitable configuration is not "an edge case." It is a specification failure.

---

## 2. The Economic Semantics Gap

Current formal systems capture:

- Structural correctness: states are well-formed
- Computational correctness: transitions are deterministic and produce valid states
- Resource conservation: aggregate quantities are preserved

They do not capture:

- Whether a valid state is economically exploitable
- Whether a valid trace represents an extraction attack
- Whether a sequence of individually valid transitions constitutes economic manipulation
- Whether the cost of an operation is proportional to its economic effect
- Whether resource distribution is within acceptable bounds

This gap exists because economic properties are treated as "domain knowledge" external to the formal model. VSEL eliminates this gap by absorbing economic semantics into the invariant system.

---

## 3. Economic State Extension

The formal state is extended with an explicit economic context component.

### 3.1 Extended State Definition

The state tuple becomes:

```
s = (C, D, E, Ω, τ)
```

Where Ω is the **economic context**:

```
Ω = {
  price_oracle: Map<AssetPair, Price>,
  exposure_limits: Map<EntityID, ExposureLimit>,
  liquidity_thresholds: Map<PoolID, LiquidityThreshold>,
  fee_schedule: FeeSchedule,
  epoch_accounting: EpochAccounting,
  collateral_requirements: Map<PositionType, CollateralRatio>,
  economic_parameters: EconomicParameters
}
```

### 3.2 Economic Context Properties

The economic context Ω must satisfy:

**Explicitness**: Every economic parameter that influences admissibility must be represented in Ω. No implicit economic assumptions.

**Determinism**: Ω is deterministically derived from canonical state C and environment E:

```
Ω = DeriveEconomic(C, E)
```

**Observability**: Ω is part of the formal state and therefore part of the trace, the constraint system, and the proof.

### 3.3 Economic Validity Predicate

A new predicate is introduced:

```
EconomicallyValid(s) ≡ P_Ω(C, Ω) ∧ WithinLimits(Ω) ∧ NoExploitableConfiguration(s)
```

This predicate is orthogonal to ValidState but equally mandatory:

```
Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s)
```

A state that is structurally valid but economically inadmissible is rejected.

---

## 4. Economic Invariant Taxonomy

Economic invariants are classified into four categories, mirroring the structural invariant taxonomy.

### 4.1 Local Economic Invariants (per transition)

These constrain individual transitions for economic admissibility.

#### E_cost: Non-Zero Acquisition Cost

```
∀ (s, σ, s') ∈ T:
  ResourceAcquired(s, s') > 0 ⟹ Cost(σ) > 0
```

No resource may be acquired at zero cost when the resource has positive value. This prevents free minting, zero-cost arbitrage, and costless resource extraction.

Falsification target: Construct transition where an entity gains resources without paying anything.

#### E_leverage: Bounded Leverage

```
∀ (s, σ, s') ∈ T:
  EffectiveLeverage(s', entity) ≤ MaxLeverage(Ω)
```

No single transition may result in effective leverage exceeding the system-defined maximum. Effective leverage is the ratio of exposure to collateral.

Falsification target: Construct transition where leverage exceeds bound via rounding, fee manipulation, or multi-asset interaction.

#### E_proportionality: Fee Proportionality

```
∀ (s, σ, s') ∈ T:
  Fee(σ) ≥ MinFee(OperationType(σ), EconomicImpact(s, σ, s'))
```

The fee for an operation must be proportional to its economic impact. This prevents dust attacks, state bloat via micro-transactions, and fee-free economic manipulation.

Falsification target: Construct transition with large economic impact but negligible fee.

#### E_slippage: Bounded Price Impact

```
∀ (s, σ, s') ∈ T where σ is a trade:
  |PriceImpact(s, σ)| ≤ MaxSlippage(Ω, σ)
```

No single trade may move the price beyond acceptable bounds relative to its size.

Falsification target: Construct trade that moves price disproportionately to its size.

#### E_collateral: Collateral Sufficiency

```
∀ (s, σ, s') ∈ T where σ creates or modifies a position:
  Collateral(s', position) ≥ RequiredCollateral(s', position, Ω)
```

Every position must maintain sufficient collateral after any transition.

Falsification target: Construct transition that reduces collateral below requirement without liquidation.

### 4.2 Global Economic Invariants (per state)

These constrain every reachable state for economic soundness.

#### G_econ_valid: Economic State Validity

```
∀ s ∈ Reachable(I, T): EconomicallyValid(s)
```

No reachable state may be economically inadmissible.

#### G_concentration: Bounded Concentration

```
∀ s ∈ Reachable(I, T), ∀ entity:
  Holdings(s, entity) / TotalSupply(s) ≤ MaxConcentration(Ω)
```

No single entity may hold a disproportionate share of any resource, preventing monopolistic control.

Falsification target: Construct state where one entity controls majority of resource via sequence of valid transitions.

#### G_liquidity: Minimum Liquidity

```
∀ s ∈ Reachable(I, T), ∀ pool:
  Liquidity(s, pool) ≥ MinLiquidity(Ω, pool)
```

Liquidity pools must maintain minimum depth. States where liquidity is drained below threshold are economically inadmissible.

#### G_solvency: System Solvency

```
∀ s ∈ Reachable(I, T):
  TotalAssets(s) ≥ TotalLiabilities(s)
```

The system must be solvent at every reachable state. This is stronger than resource conservation (which only tracks flows); solvency tracks the relationship between assets and obligations.

#### G_dust: Bounded Minimum Balance

```
∀ s ∈ Reachable(I, T), ∀ account with balance > 0:
  Balance(s, account) ≥ MinBalance(Ω)
```

No account may hold a positive balance below the dust threshold. This prevents state bloat attacks via micro-balances.

### 4.3 Temporal Economic Invariants (per trace)

These constrain execution sequences for economic safety over time.

#### TE_extraction: Bounded Epoch Extraction

```
∀ τ_epoch (trace segment within one epoch):
  NetExtraction(τ_epoch, entity) ≤ MaxExtraction(Ω, entity)
```

No entity may extract more value than a defined threshold within a single epoch. This captures flash loan attacks, MEV extraction, and rapid arbitrage exploitation.

NetExtraction is defined as:

```
NetExtraction(τ, entity) = Σ Outflows(entity, τ) - Σ Inflows(entity, τ)
```

Falsification target: Construct trace where entity deposits, manipulates, extracts, and withdraws within one epoch, netting more than threshold.

#### TE_flash: Flash Operation Collateral

```
∀ τ_atomic (atomic transaction sequence):
  ∀ intermediate state s_i in τ_atomic:
    UncollateralizedExposure(s_i) ≤ FlashLimit(Ω)
  OR
  ∀ intermediate state s_i: Collateral(s_i) ≥ RequiredCollateral(s_i)
```

Flash operations (borrow-use-repay within atomic sequence) must either be bounded in uncollateralized exposure or maintain collateral at every intermediate step.

Falsification target: Construct atomic sequence with unbounded uncollateralized exposure at intermediate state.

#### TE_sandwich: Anti-Sandwich

```
∀ τ, ∀ subsequence (σ_front, σ_victim, σ_back) in τ:
  ¬(Beneficiary(σ_front) = Beneficiary(σ_back) ∧
    ProfitFrom(σ_front, σ_back) > 0 ∧
    LossTo(σ_victim) > 0 ∧
    CausallyDependent(σ_front, σ_victim, σ_back))
```

No trace may contain a sandwich pattern where one entity profits by surrounding another entity's transaction.

This is the most complex temporal economic invariant. It requires defining causal dependency between transactions and profit/loss attribution.

Falsification target: Construct trace containing classic sandwich attack pattern.

#### TE_manipulation: Price Manipulation Resistance

```
∀ τ_window (sliding window of N transitions):
  PriceDeviation(τ_window) ≤ MaxDeviation(Ω)
  OR
  PriceDeviation is justified by ExternalPriceMovement(E)
```

Price cannot deviate beyond threshold within a window unless justified by external market movement.

#### TE_velocity: Economic Velocity Bounds

```
∀ τ_epoch, ∀ resource:
  Turnover(τ_epoch, resource) ≤ MaxVelocity(Ω, resource)
```

The rate at which resources change hands within an epoch is bounded. Unbounded velocity indicates wash trading or circular manipulation.

### 4.4 Compositional Economic Invariants

These apply when systems are composed.

#### CE_arbitrage: Cross-System Arbitrage Bounds

```
∀ composed (A, B), ∀ cross-transition:
  ArbitrageProfit(A, B, cross_transition) ≤ MaxArbitrage(Ω_cross)
```

Cross-system interactions must not enable unbounded arbitrage.

#### CE_contagion: Economic Contagion Isolation

```
∀ composed (A, B):
  EconomicFailure(A) ⟹ BoundedImpact(B, MaxContagion(Ω_cross))
```

Economic failure in one system must have bounded impact on composed systems.

---

## 5. Economic Admissibility as Formal Predicate

The complete admissibility condition for a state becomes:

```
Admissible(s) ≡
  ValidState(s) ∧
  EconomicallyValid(s) ∧
  ∀ G_structural: G(s) ∧
  ∀ G_economic: G_econ(s)
```

For a trace:

```
AdmissibleTrace(τ) ≡
  ValidTrace(τ) ∧
  ∀ s_i ∈ τ: EconomicallyValid(s_i) ∧
  ∀ TE: TE(τ)
```

The proof obligation becomes:

```
Verify(π) ⟹ AdmissibleTrace(τ)
```

This is strictly stronger than the original:

```
Verify(π) ⟹ ValidTrace(τ)
```

---

## 6. Integration with Existing Architecture

### 6.1 Invariant System (INVARIANTS.md)

Economic invariants are added as a fourth category alongside local, global, and temporal. They follow the same enforcement requirements: expressible in FSL, preserved in SIR, enforced in CDL, testable in execution.

### 6.2 Constraint Derivation (CONSTRAINT_DERIVATION.md)

Economic invariants must be encoded in the constraint system. Each economic invariant generates constraint templates following the same derivation rules as structural invariants. The constraint coverage matrix must include economic invariants.

### 6.3 Proof Obligations (PROOF_OBLIGATIONS.md)

New proof obligations:

```
ECON-1: ∀ (s, σ, s') ∈ T: EconomicallyValid(s) ⟹ EconomicallyValid(s')
ECON-2: ∀ s₀ ∈ I: EconomicallyValid(s₀)
ECON-3: ∀ τ: AdmissibleTrace(τ) ⟹ ∀ TE: TE(τ)
```

### 6.4 Counterexample Catalog (COUNTEREXAMPLE_CATALOG.md)

Economic counterexamples are expanded into a full family (see separate expansion).

### 6.5 Edge Case Atlas (EDGE_CASE_ATLAS.md)

Family 8 (Economically Absurd but Formally Valid) is expanded with the formalized economic invariants as detection criteria.

### 6.6 Semantic Mapping

The economic context Ω must be included in the semantic mapping:

```
μ_Ω: Ω_c → Ω_f
```

The commutativity theorem (THM-1) extends to include economic context preservation.

---

## 7. Domain Expert Integration Process

Economic invariants require domain expertise to define. The process is:

### Step 1: Domain Expert Expression

The domain expert expresses economic properties in semi-formal language:

```
"No flash loan without collateral"
"No entity should be able to extract more than X per epoch"
"Price impact of any single trade must be bounded"
```

### Step 2: Formal Translation

The formal methods engineer translates to predicates:

```
∀ τ_atomic: UncollateralizedExposure(τ_atomic) ≤ FlashLimit(Ω)
∀ τ_epoch: NetExtraction(τ_epoch, entity) ≤ MaxExtraction(Ω)
∀ (s, σ, s'): |PriceImpact(s, σ)| ≤ MaxSlippage(Ω, σ)
```

### Step 3: Integration

The predicate enters the invariant system with:
- Proof obligation (what must be demonstrated)
- Counterexample family (what would destroy it)
- Constraint encoding (how it is enforced in proofs)
- Coverage matrix entry (traceability)

### Step 4: Validation

The domain expert validates that the formal predicate captures the intended economic property. The formal methods engineer validates that the predicate is enforceable and complete.

This process is not optional. It is the mechanism by which economic intent becomes formal specification.

---

## 8. Relationship to Structural Invariants

Economic invariants are not weaker than structural invariants. They are orthogonal.

```
ValidState(s) ∧ ¬EconomicallyValid(s)  →  state is rejected
¬ValidState(s) ∧ EconomicallyValid(s)  →  state is rejected
ValidState(s) ∧ EconomicallyValid(s)   →  state is admissible
```

Neither subsumes the other. Both are required for admissibility.

The key insight is that economic invariants often manifest as temporal properties (attacks are sequences, not single steps) while structural invariants are often local or global. This means the temporal invariant machinery of VSEL is particularly important for economic correctness.

---

## 9. Parameterization

Economic invariants are parameterized by the economic context Ω. This means:

- Different deployments can have different economic parameters
- Parameters can be updated through governance (modeled as transitions)
- Parameter changes must preserve all structural invariants
- The parameter space itself must be constrained (no parameter combination may make the system economically unsound)

```
∀ Ω ∈ ValidEconomicParameters:
  SystemWithParameters(Ω) satisfies all economic invariants
```

---

## 10. Closing Statement

Economic semantics is not a soft requirement bolted onto a formal system.

It is a formal requirement that was previously missing from the specification.

VSEL's architecture already has every mechanism needed to absorb it: invariants, proof obligations, counterexamples, constraint coverage, temporal properties, and compositional reasoning.

The only thing that was missing was the decision to treat economic intent with the same unforgiving rigor as structural correctness.

That decision is now made.
