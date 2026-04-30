/-
  VSEL Foundation Types — State Model
  Mirrors: protocol/crates/vsel-core/src/state.rs, types.rs
  Requirements: 9.6, 9.8, 14.7

  State tuple: s = (C, D, E, Ω, τ)
  - C: CanonicalState — minimal semantic state
  - D: DerivedState — D = Derive(C) (DEF-1)
  - E: Environment — external context
  - Ω: EconomicContext — Ω = DeriveEconomic(C, E)
  - τ: TraceMetadata — execution metadata
-/

namespace VSEL.Foundations

-- ---------------------------------------------------------------------------
-- Instances for Fin n → UInt8 (fixed-length byte arrays)
-- We use ByteArray32 as a wrapper to avoid universe issues with autoImplicit=false.
-- ---------------------------------------------------------------------------

/-- 32-byte array wrapper with decidable equality and repr. -/
structure ByteArray32 where
  data : List UInt8
  len_eq : data.length = 32 := by decide
  deriving Repr

instance : DecidableEq ByteArray32 :=
  fun a b =>
    if h : a.data = b.data then
      isTrue (by cases a; cases b; simp at h; subst h; rfl)
    else
      isFalse (by intro heq; apply h; cases heq; rfl)

instance : Inhabited ByteArray32 where
  default := { data := List.replicate 32 0, len_eq := by native_decide }

-- ---------------------------------------------------------------------------
-- Base types (mirrors types.rs)
-- ---------------------------------------------------------------------------

/-- 32-byte account identifier. -/
structure AccountId where
  bytes : ByteArray32
  deriving DecidableEq, Repr

/-- Byte-vector storage key. -/
structure StorageKey where
  data : List UInt8
  deriving DecidableEq, Repr

/-- Byte-vector storage value. -/
structure StorageValue where
  data : List UInt8
  deriving DecidableEq, Repr

/-- 32-byte cryptographic hash. -/
structure Hash where
  bytes : ByteArray32
  deriving DecidableEq, Repr

/-- Domain separation tag — wraps a Hash for domain-separated crypto operations. -/
structure DomainTag where
  hash : Hash
  deriving DecidableEq, Repr

/-- Protocol version with semantic versioning. -/
structure ProtocolVersion where
  major : Nat
  minor : Nat
  patch : Nat
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Cryptographic types — hybrid classical + PQC
-- ---------------------------------------------------------------------------

/-- Hybrid public key — both classical (Ed25519) and PQC (ML-DSA/Falcon) components. -/
structure HybridPublicKey where
  classical : List UInt8
  pqc : List UInt8
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Economic types (mirrors types.rs economic section)
-- ---------------------------------------------------------------------------

/-- Asset pair for price oracle lookups. -/
structure AssetPair where
  base : String
  quote : String
  deriving DecidableEq, Repr

/-- Price value (Nat for arbitrary precision, mirrors Rust u128). -/
structure Price where
  val : Nat
  deriving DecidableEq, Repr

/-- 32-byte entity identifier. -/
structure EntityId where
  bytes : ByteArray32
  deriving DecidableEq, Repr

/-- Exposure limit for an entity. -/
structure ExposureLimit where
  val : Nat
  deriving DecidableEq, Repr

/-- 32-byte pool identifier. -/
structure PoolId where
  bytes : ByteArray32
  deriving DecidableEq, Repr

/-- Liquidity threshold for a pool. -/
structure LiquidityThreshold where
  val : Nat
  deriving DecidableEq, Repr

/-- Position type for collateral requirements. -/
inductive PositionType where
  | long
  | short
  | neutral
  deriving DecidableEq, Repr

/-- Collateral ratio in basis points. 10_000 bps = 100%. -/
structure CollateralRatio where
  val : Nat
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Supporting types (mirrors types.rs supporting section)
-- ---------------------------------------------------------------------------

/-- System-wide data stored in canonical state. -/
structure SystemData where
  protocolVersion : ProtocolVersion
  totalSupply : Nat
  parameters : List (String × List UInt8)
  deriving DecidableEq, Repr

/-- Fee schedule for economic context. -/
structure FeeSchedule where
  baseFee : Nat
  feeRateBps : Nat
  overrides : List (String × Nat)
  deriving DecidableEq, Repr

/-- Epoch-level accounting data. -/
structure EpochAccounting where
  epoch : Nat
  totalFeesCollected : Nat
  totalTransactions : Nat
  deriving DecidableEq, Repr

/-- Economic parameters for the system. -/
structure EconomicParameters where
  maxLeverageBps : Nat
  minCollateralRatioBps : Nat
  dustThreshold : Nat
  extra : List (String × Nat)
  deriving DecidableEq, Repr

/-- Output event produced by a transition. -/
structure OutputEvent where
  eventType : String
  data : List UInt8
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Account data
-- ---------------------------------------------------------------------------

/-- Per-account data stored in canonical state. -/
structure AccountData where
  balance : Nat
  nonce : Nat
  data : List UInt8
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Canonical state — C
-- ---------------------------------------------------------------------------

/-- CanonicalState — the minimal, sufficient, deterministic representation
    of system state. Uses association lists for deterministic ordering. -/
structure CanonicalState where
  accounts : List (AccountId × AccountData)
  storage : List (StorageKey × StorageValue)
  systemData : SystemData
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Derived state — D = Derive(C)
-- ---------------------------------------------------------------------------

/-- DerivedState — must satisfy D = Derive(C) (DEF-1).
    Computed deterministically from CanonicalState. -/
structure DerivedState where
  stateRoot : Hash
  auxiliaryRoots : List (String × Hash)
  aggregates : List (String × Nat)
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Environment — E
-- ---------------------------------------------------------------------------

/-- Environment — external context, explicit. -/
structure Environment where
  timestamp : Nat
  blockHeight : Nat
  executionDomain : DomainTag
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Economic context — Ω = DeriveEconomic(C, E)
-- ---------------------------------------------------------------------------

/-- EconomicContext — deterministically derived from CanonicalState + Environment. -/
structure EconomicContext where
  priceOracle : List (AssetPair × Price)
  exposureLimits : List (EntityId × ExposureLimit)
  liquidityThresholds : List (PoolId × LiquidityThreshold)
  feeSchedule : FeeSchedule
  epochAccounting : EpochAccounting
  collateralRequirements : List (PositionType × CollateralRatio)
  economicParameters : EconomicParameters
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Trace metadata — τ
-- ---------------------------------------------------------------------------

/-- TraceMetadata — ordering and trace consistency. -/
structure TraceMetadata where
  sequenceIndex : Nat
  previousCommitment : Hash
  epoch : Nat
  timestamp : Nat
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- State tuple — s = (C, D, E, Ω, τ)
-- ---------------------------------------------------------------------------

/-- State tuple s = (C, D, E, Ω, τ). -/
structure State where
  canonical : CanonicalState
  derived : DerivedState
  environment : Environment
  economic : EconomicContext
  metadata : TraceMetadata
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Zero hash constant
-- ---------------------------------------------------------------------------

/-- The zero hash (all bytes zero). -/
def zeroHash : Hash :=
  { bytes := default }

-- ---------------------------------------------------------------------------
-- Inhabited instances for opaque return types
-- ---------------------------------------------------------------------------

instance : Inhabited Hash where
  default := { bytes := default }

instance : Inhabited DerivedState where
  default := { stateRoot := default, auxiliaryRoots := [], aggregates := [] }

instance : Inhabited EconomicContext where
  default := {
    priceOracle := []
    exposureLimits := []
    liquidityThresholds := []
    feeSchedule := { baseFee := 0, feeRateBps := 0, overrides := [] }
    epochAccounting := { epoch := 0, totalFeesCollected := 0, totalTransactions := 0 }
    collateralRequirements := []
    economicParameters := { maxLeverageBps := 0, minCollateralRatioBps := 0, dustThreshold := 0, extra := [] }
  }

-- ---------------------------------------------------------------------------
-- Derive functions (opaque — implementation in Rust, proven properties in Lean)
-- ---------------------------------------------------------------------------

/-- Deterministically compute DerivedState from CanonicalState.
    Opaque: the concrete implementation is in Rust; Lean reasons about properties. -/
opaque Derive (c : CanonicalState) : DerivedState

/-- Deterministically compute EconomicContext from CanonicalState + Environment.
    Opaque: the concrete implementation is in Rust; Lean reasons about properties. -/
opaque DeriveEconomic (c : CanonicalState) (e : Environment) : EconomicContext

-- ---------------------------------------------------------------------------
-- State validity predicates — DEF-1
-- ValidState(s) ≡ P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ)
-- ---------------------------------------------------------------------------

/-- P_C: Canonical state validity.
    All balances sum to total_supply. -/
def ValidCanonical (c : CanonicalState) : Prop :=
  let totalBalance := c.accounts.foldl (fun acc (_, a) => acc + a.balance) 0
  totalBalance = c.systemData.totalSupply

/-- P_D: Derived state consistency — D = Derive(C). -/
def ValidDerived (c : CanonicalState) (d : DerivedState) : Prop :=
  d = Derive c

/-- P_E: Environment validity.
    Domain tag must not be the zero hash. -/
def ValidEnvironment (e : Environment) : Prop :=
  e.executionDomain.hash ≠ zeroHash

/-- P_τ: Metadata validity.
    Genesis (seq 0) must have zero commitment; non-genesis must have non-zero. -/
def ValidMetadata (m : TraceMetadata) : Prop :=
  if m.sequenceIndex = 0 then
    m.previousCommitment = zeroHash
  else
    m.previousCommitment ≠ zeroHash

/-- ValidState(s) ≡ P_C(C) ∧ P_D(D) ∧ P_E(E) ∧ P_τ(τ) (DEF-1). -/
def ValidState (s : State) : Prop :=
  ValidCanonical s.canonical
  ∧ ValidDerived s.canonical s.derived
  ∧ ValidEnvironment s.environment
  ∧ ValidMetadata s.metadata

-- ---------------------------------------------------------------------------
-- Economic validity
-- ---------------------------------------------------------------------------

/-- EconomicallyValid — all economic invariants hold on a state.
    Opaque: full definition depends on invariant system. -/
opaque EconomicallyValid (s : State) : Prop

-- ---------------------------------------------------------------------------
-- Admissible predicate
-- ---------------------------------------------------------------------------

/-- Admissible(s) ≡ ValidState(s) ∧ EconomicallyValid(s).
    A state that is structurally valid but economically inadmissible is rejected. -/
def Admissible (s : State) : Prop :=
  ValidState s ∧ EconomicallyValid s

end VSEL.Foundations
