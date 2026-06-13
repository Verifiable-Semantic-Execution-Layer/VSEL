/-!
  VSEL semantic certificate checker.

  This executable checker validates the canonical semantic certificate emitted
  by the Rust strict verifier. It deliberately stays in Lean's core language so
  it remains tied to the repository's pinned Lean toolchain without additional
  packages.
-/

namespace VSEL.Checker

structure Certificate where
  fields : List (String × String)
  obligations : List String
  deriving Repr

inductive CertificateError where
  | empty
  | badHeader
  | malformedLine (line : String)
  | duplicateField (key : String)
  | missingField (key : String)
  | invalidField (key : String) (reason : String)
  | missingObligation (name : String)
  deriving Repr, DecidableEq

def header : String := "VSEL_SEMANTIC_CERTIFICATE_V1"

def requiredFields : List String := [
  "protocol_major", "protocol_minor", "protocol_patch", "proof_system",
  "stark_required", "trace_commitment", "witness_commitment",
  "constraint_commitment", "root_init", "root_final", "domain",
  "formal_spec_commitment", "trace_entries", "public_observables",
  "witness_inputs", "witness_intermediate_states", "witness_aux_values",
  "constraint_count", "witness_variable_count", "public_constraint_input_count"
]

def requiredObligations : List String := [
  "trace:chain_integrity", "trace:public_input_binding",
  "trace:deterministic_replay", "trace:observable_binding",
  "trace:witness_auxiliary_binding", "constraints:non_empty"
]

def starkObligations : List String := [
  "stark:non_placeholder_proof_system_binding",
  "stark:artifact_shape_binding"
]

def cairoObligations : List String := [
  "cairo:program_binding",
  "cairo:source_manifest_binding",
  "cairo:semantic_binding_report_binding",
  "cairo:sierra_casm_binding",
  "cairo:public_input_hash_binding",
  "cairo:constraint_commitment_binding",
  "cairo:adapter_verifier_certificate_binding",
  "cairo:native_verifier_success"
]

def cairoRequiredFields : List String := [
  "cairo_backend_id", "cairo_program_hash", "cairo_source_manifest_hash",
  "cairo_sierra_program_hash", "cairo_casm_program_hash",
  "cairo_executable_program_hash", "cairo_semantic_binding_hash",
  "cairo_trace_hash", "cairo_public_input_hash", "cairo_constraint_commitment",
  "cairo_statement_hash", "cairo_proof_hash", "cairo_proof_byte_len",
  "cairo_verifier_adapter_id", "cairo_verifier_version",
  "cairo_verifier_binary_hash", "cairo_verifier_backend_id",
  "cairo_verifier_program_hash", "cairo_verifier_sierra_program_hash",
  "cairo_verifier_casm_program_hash", "cairo_verifier_executable_program_hash",
  "cairo_verifier_semantic_binding_hash",
  "cairo_verifier_trace_hash", "cairo_verifier_public_input_hash",
  "cairo_verifier_constraint_commitment", "cairo_verifier_statement_hash",
  "cairo_verifier_proof_hash", "cairo_verifier_transcript_hash",
  "cairo_verifier_accepted"
]

def cairoHashFields : List String := [
  "cairo_program_hash", "cairo_source_manifest_hash",
  "cairo_sierra_program_hash", "cairo_casm_program_hash",
  "cairo_executable_program_hash", "cairo_semantic_binding_hash", "cairo_trace_hash",
  "cairo_public_input_hash", "cairo_constraint_commitment",
  "cairo_statement_hash", "cairo_proof_hash",
  "cairo_verifier_binary_hash", "cairo_verifier_program_hash",
  "cairo_verifier_sierra_program_hash", "cairo_verifier_casm_program_hash",
  "cairo_verifier_executable_program_hash", "cairo_verifier_semantic_binding_hash",
  "cairo_verifier_trace_hash",
  "cairo_verifier_public_input_hash", "cairo_verifier_constraint_commitment",
  "cairo_verifier_statement_hash", "cairo_verifier_proof_hash",
  "cairo_verifier_transcript_hash"
]

def getField (fields : List (String × String)) (key : String) : Option String :=
  match fields with
  | [] => none
  | (k, v) :: rest => if k = key then some v else getField rest key

def hasField (fields : List (String × String)) (key : String) : Bool :=
  match getField fields key with
  | some _ => true
  | none => false

def isDigitChar (c : Char) : Bool :=
  "0123456789".contains c

def isHexChar (c : Char) : Bool :=
  "0123456789abcdefABCDEF".contains c

def allChars (p : Char → Bool) (chars : List Char) : Bool :=
  match chars with
  | [] => true
  | c :: rest => p c && allChars p rest

def isHex32 (s : String) : Bool :=
  s.length = 64 && allChars isHexChar s.data

def isZeroHex32 (s : String) : Bool :=
  s.length = 64 && allChars (fun c => c = '0') s.data

def hasInfix (needle haystack : String) : Bool :=
  match haystack.splitOn needle with
  | [_] => false
  | _ => true

def startsWith (pref value : String) : Bool :=
  match value.splitOn pref with
  | "" :: _ => true
  | _ => false

def cairoAdapterFromProofSystem (proofSystem : String) : Option String :=
  match proofSystem.splitOn "cairo-stark/" with
  | ["", adapter] =>
      if adapter.isEmpty then none else some adapter
  | _ => none

def parseNatStrict (s : String) : Option Nat :=
  if s.isEmpty then
    none
  else if allChars isDigitChar s.data then
    s.toNat?
  else
    none

def parseBoolStrict (s : String) : Option Bool :=
  if s = "true" then some true
  else if s = "false" then some false
  else none

def splitKV (line : String) : Except CertificateError (String × String) :=
  match line.splitOn "=" with
  | [k, v] =>
      if k.isEmpty then
        throw (.malformedLine line)
      else
        pure (k, v)
  | _ => throw (.malformedLine line)

def parseLines
    (lines : List String)
    (fields : List (String × String))
    (obligations : List String) :
    Except CertificateError Certificate :=
  match lines with
  | [] => pure { fields := fields.reverse, obligations := obligations.reverse }
  | line :: rest =>
      if line.isEmpty then
        parseLines rest fields obligations
      else do
        let (key, value) ← splitKV line
        if key = "obligation" then
          parseLines rest fields (value :: obligations)
        else if hasField fields key then
          throw (.duplicateField key)
        else
          parseLines rest ((key, value) :: fields) obligations

def parseCertificate (text : String) : Except CertificateError Certificate :=
  match text.splitOn "\n" with
  | [] => throw .empty
  | first :: rest =>
      if first = header then
        parseLines rest [] []
      else
        throw .badHeader

def requireField (cert : Certificate) (key : String) : Except CertificateError String :=
  match getField cert.fields key with
  | some value =>
      if value.isEmpty then
        throw (.invalidField key "empty value")
      else
        pure value
  | none => throw (.missingField key)

def requireNatField (cert : Certificate) (key : String) : Except CertificateError Nat := do
  let value ← requireField cert key
  match parseNatStrict value with
  | some n => pure n
  | none => throw (.invalidField key "expected decimal natural number")

def requireBoolField (cert : Certificate) (key : String) : Except CertificateError Bool := do
  let value ← requireField cert key
  match parseBoolStrict value with
  | some b => pure b
  | none => throw (.invalidField key "expected true or false")

def requireFieldEquals
    (cert : Certificate)
    (leftKey : String)
    (rightKey : String) :
    Except CertificateError Unit := do
  let left ← requireField cert leftKey
  let right ← requireField cert rightKey
  if left = right then pure ()
  else throw (.invalidField rightKey ("must equal " ++ leftKey))

def requireFieldValue
    (cert : Certificate)
    (key : String)
    (expected : String)
    (reason : String) :
    Except CertificateError Unit := do
  let actual ← requireField cert key
  if actual = expected then pure ()
  else throw (.invalidField key reason)

def requirePositiveNatField (cert : Certificate) (key : String) :
    Except CertificateError Nat := do
  let value ← requireNatField cert key
  if value = 0 then
    throw (.invalidField key "expected positive decimal natural number")
  pure value

def requireHex32Field (cert : Certificate) (key : String) : Except CertificateError Unit := do
  let value ← requireField cert key
  if !isHex32 value then
    throw (.invalidField key "expected 32-byte hex commitment")
  if isZeroHex32 value then
    throw (.invalidField key "zero commitment is not authoritative evidence")
  pure ()

def requireObligation (cert : Certificate) (name : String) : Except CertificateError Unit :=
  if cert.obligations.contains name then pure ()
  else throw (.missingObligation name)

def validateProofSystem (proofSystem : String) (starkRequired : Bool) :
    Except CertificateError Unit := do
  if hasInfix "placeholder" proofSystem then
    throw (.invalidField "proof_system" "placeholder proof systems are not final evidence")
  if starkRequired then
    if proofSystem = "plonky3-stark" || startsWith "cairo-stark/" proofSystem then
      pure ()
    else
      throw (.invalidField "proof_system" "expected plonky3-stark or cairo-stark/<adapter>")

def requireAllFields (cert : Certificate) (keys : List String) :
    Except CertificateError Unit := do
  match keys with
  | [] => pure ()
  | key :: rest =>
      discard <| requireField cert key
      requireAllFields cert rest

def requireAllHexFields (cert : Certificate) (keys : List String) :
    Except CertificateError Unit := do
  match keys with
  | [] => pure ()
  | key :: rest =>
      requireHex32Field cert key
      requireAllHexFields cert rest

def requireAllObligations (cert : Certificate) (names : List String) :
    Except CertificateError Unit := do
  match names with
  | [] => pure ()
  | name :: rest =>
      requireObligation cert name
      requireAllObligations cert rest

def validateCairoCertificate
    (cert : Certificate)
    (proofSystem : String) :
    Except CertificateError Unit := do
  requireAllObligations cert cairoObligations
  requireAllFields cert cairoRequiredFields
  requireAllHexFields cert cairoHashFields
  discard <| requirePositiveNatField cert "cairo_proof_byte_len"

  requireFieldValue cert "cairo_backend_id" proofSystem
    "must equal proof_system for Cairo/STARK final evidence"
  requireFieldValue cert "cairo_verifier_backend_id" proofSystem
    "native verifier certificate must bind the same Cairo backend id"
  requireFieldValue cert "cairo_verifier_accepted" "true"
    "native Cairo verifier must explicitly accept"

  match cairoAdapterFromProofSystem proofSystem with
  | some adapter =>
      requireFieldValue cert "cairo_verifier_adapter_id" adapter
        "native verifier adapter id must equal proof_system suffix"
  | none =>
      throw (.invalidField "proof_system" "expected cairo-stark/<adapter>")

  requireFieldEquals cert "constraint_commitment" "cairo_constraint_commitment"
  requireFieldEquals cert "cairo_program_hash" "cairo_source_manifest_hash"
  requireFieldEquals cert "cairo_program_hash" "cairo_verifier_program_hash"
  requireFieldEquals cert "cairo_sierra_program_hash" "cairo_verifier_sierra_program_hash"
  requireFieldEquals cert "cairo_casm_program_hash" "cairo_verifier_casm_program_hash"
  requireFieldEquals cert "cairo_executable_program_hash"
    "cairo_verifier_executable_program_hash"
  requireFieldEquals cert "cairo_semantic_binding_hash"
    "cairo_verifier_semantic_binding_hash"
  requireFieldEquals cert "cairo_trace_hash" "cairo_verifier_trace_hash"
  requireFieldEquals cert "cairo_public_input_hash" "cairo_verifier_public_input_hash"
  requireFieldEquals cert "cairo_constraint_commitment" "cairo_verifier_constraint_commitment"
  requireFieldEquals cert "cairo_statement_hash" "cairo_verifier_statement_hash"
  requireFieldEquals cert "cairo_proof_hash" "cairo_verifier_proof_hash"

def validateCertificate (cert : Certificate) : Except CertificateError Unit := do
  requireAllFields cert requiredFields
  requireAllHexFields cert [
    "trace_commitment", "witness_commitment", "constraint_commitment",
    "root_init", "root_final", "domain", "formal_spec_commitment"
  ]

  discard <| requireNatField cert "protocol_major"
  discard <| requireNatField cert "protocol_minor"
  discard <| requireNatField cert "protocol_patch"

  let traceEntries ← requireNatField cert "trace_entries"
  let publicObservables ← requireNatField cert "public_observables"
  let witnessInputs ← requireNatField cert "witness_inputs"
  let constraintCount ← requireNatField cert "constraint_count"
  discard <| requireNatField cert "witness_intermediate_states"
  discard <| requireNatField cert "witness_aux_values"
  discard <| requireNatField cert "witness_variable_count"
  discard <| requireNatField cert "public_constraint_input_count"

  if traceEntries = 0 then
    throw (.invalidField "trace_entries" "final semantic evidence requires a non-empty trace")
  if traceEntries ≠ publicObservables then
    throw (.invalidField "public_observables" "observable count must equal trace entry count")
  if traceEntries ≠ witnessInputs then
    throw (.invalidField "witness_inputs" "witness input count must equal trace entry count")
  if constraintCount = 0 then
    throw (.invalidField "constraint_count" "final semantic evidence requires constraints")

  requireAllObligations cert requiredObligations

  let starkRequired ← requireBoolField cert "stark_required"
  let proofSystem ← requireField cert "proof_system"
  validateProofSystem proofSystem starkRequired

  if starkRequired then
    requireAllObligations cert starkObligations
    if startsWith "cairo-stark/" proofSystem then
      validateCairoCertificate cert proofSystem

def checkCertificateText (text : String) : Except CertificateError Unit := do
  let cert ← parseCertificate text
  validateCertificate cert

theorem requiredObligations_nonempty : requiredObligations ≠ [] := by
  native_decide

theorem starkObligations_nonempty : starkObligations ≠ [] := by
  native_decide

theorem cairoObligations_nonempty : cairoObligations ≠ [] := by
  native_decide

theorem cairoRequiredFields_nonempty : cairoRequiredFields ≠ [] := by
  native_decide

theorem cairoHashFields_nonempty : cairoHashFields ≠ [] := by
  native_decide

end VSEL.Checker
