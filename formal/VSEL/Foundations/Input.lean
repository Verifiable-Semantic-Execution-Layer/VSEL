/-
  VSEL Foundation Types — Input Model
  Mirrors: protocol/crates/vsel-core/src/input.rs, types.rs
  Requirements: 9.6, 9.8, 14.7

  Input: σ = (payload, auth, aux)
  - payload: Semantic content
  - auth: Authorization evidence (hybrid classical + PQC)
  - aux: Auxiliary data — must NOT influence semantics (THM-4)
-/

import VSEL.Foundations.State

namespace VSEL.Foundations

-- ---------------------------------------------------------------------------
-- Payload — semantic content of an input
-- ---------------------------------------------------------------------------

/-- Semantic payload of an input. -/
structure Payload where
  payloadType : String
  data : List UInt8
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Auxiliary data
-- ---------------------------------------------------------------------------

/-- Auxiliary data attached to an input.
    Must NOT influence semantic outcome (THM-4). -/
structure AuxiliaryData where
  data : List UInt8
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Authorization — hybrid classical + PQC
-- ---------------------------------------------------------------------------

/-- Authorization evidence for an input.
    Both classical (Ed25519) and PQC (ML-DSA/Falcon) signatures must be
    present and non-empty for the input to be structurally valid. -/
structure Authorization where
  classicalSig : List UInt8
  pqcSig : List UInt8
  publicKey : HybridPublicKey
  nonce : Nat
  domain : DomainTag
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Input — σ = (payload, auth, aux)
-- ---------------------------------------------------------------------------

/-- Input to the VSEL state machine.
    Auxiliary data (aux) must NOT influence semantic outcome (THM-4). -/
structure Input where
  payload : Payload
  auth : Authorization
  aux : AuxiliaryData
  deriving DecidableEq, Repr

-- ---------------------------------------------------------------------------
-- Input validity predicate
-- ---------------------------------------------------------------------------

/-- Payload validity: type identifier and data must both be non-empty. -/
def ValidPayload (p : Payload) : Prop :=
  p.payloadType ≠ "" ∧ p.data ≠ []

/-- Authorization validity:
    - Both signature components are non-empty.
    - Both public key components are non-empty.
    - Domain tag is not the zero hash. -/
def ValidAuthorization (a : Authorization) : Prop :=
  a.classicalSig ≠ []
  ∧ a.pqcSig ≠ []
  ∧ a.publicKey.classical ≠ []
  ∧ a.publicKey.pqc ≠ []
  ∧ a.domain.hash ≠ zeroHash

/-- ValidInput(σ) — structural validity of an input.
    Checks payload non-empty, auth sigs non-empty, pubkey non-empty, domain non-zero. -/
def ValidInput (sigma : Input) : Prop :=
  ValidPayload sigma.payload ∧ ValidAuthorization sigma.auth

end VSEL.Foundations
