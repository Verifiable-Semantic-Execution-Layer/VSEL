/-
  VSEL — Root module
  Imports all VSEL library modules for the `lake build` target.
-/

-- Foundations
import VSEL.Foundations.State
import VSEL.Foundations.Input
import VSEL.Foundations.Transition
import VSEL.Foundations.Invariants

-- Refinement
import VSEL.Refinement.FormalToSIR
import VSEL.Refinement.SIRToConcrete
import VSEL.Refinement.ConcreteToConstraint

-- Mapping
import VSEL.Mapping.SemanticMapping
import VSEL.Mapping.Commutativity
import VSEL.Mapping.Observable

-- Composition
import VSEL.Composition.Contract
import VSEL.Composition.Soundness

-- Witness
import VSEL.Witness.Uniqueness

-- Executable checker
import VSEL.Checker.Certificate
