//! Input and state canonicalization (DEF-5).
//!
//! Derived from: SEMANTIC_MAPPING.md, SEMANTIC_PRESERVATION_THEOREMS.md,
//! Requirement 4.4.
//!
//! Canonicalization normalizes concrete inputs and states into a canonical
//! form before semantic interpretation. The key property is **idempotence**:
//!
//!   `Canonical(Canonical(x)) = Canonical(x)` (DEF-5)
//!
//! All functions are pure, deterministic, and total for valid inputs.
//! Malformed or ambiguous inputs are rejected with a `CanonicalizationError`.

use thiserror::Error;

use vsel_core::input::{Authorization, Input};
use vsel_core::state::{derive, derive_economic, valid_state, State};
use vsel_core::types::{AuxiliaryData, Hash, Payload};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced when canonicalization encounters malformed or ambiguous data.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CanonicalizationError {
    /// Payload type is empty after trimming/normalization.
    #[error("empty payload type after normalization")]
    EmptyPayloadType,

    /// Payload data is empty.
    #[error("empty payload data")]
    EmptyPayloadData,

    /// Authorization signatures are missing or empty.
    #[error("missing or empty authorization signatures")]
    MissingSignatures,

    /// Public key components are missing or empty.
    #[error("missing or empty public key components")]
    MissingPublicKey,

    /// Domain tag is the zero hash (invalid).
    #[error("zero domain tag")]
    ZeroDomainTag,

    /// State canonical/derived consistency violation.
    #[error("invalid state: {0}")]
    InvalidState(String),
}

// ---------------------------------------------------------------------------
// canonicalize_input — idempotent (DEF-5)
// ---------------------------------------------------------------------------

/// Canonicalize a concrete `Input` into canonical form.
///
/// Normalization steps:
/// 1. Trim and lowercase `payload_type`.
/// 2. Keep `payload.data` as-is (semantic content).
/// 3. Keep `auth` fields as-is (cryptographic data must not be modified).
/// 4. Clear auxiliary data to empty vec (THM-4: aux must not influence semantics).
///
/// Validation (rejects malformed inputs):
/// - `payload_type` must be non-empty after trim/lowercase.
/// - `payload.data` must be non-empty.
/// - Both signature components must be non-empty.
/// - Both public key components must be non-empty.
/// - Domain tag must not be the zero hash.
///
/// Idempotent: `canonicalize_input(canonicalize_input(σ)) = canonicalize_input(σ)` (DEF-5).
pub fn canonicalize_input(input: &Input) -> Result<Input, CanonicalizationError> {
    // Normalize payload_type: trim whitespace, convert to lowercase.
    let normalized_type = input.payload.payload_type.trim().to_lowercase();

    if normalized_type.is_empty() {
        return Err(CanonicalizationError::EmptyPayloadType);
    }

    if input.payload.data.is_empty() {
        return Err(CanonicalizationError::EmptyPayloadData);
    }

    // Validate authorization structural requirements.
    validate_authorization(&input.auth)?;

    // Build canonical input.
    Ok(Input {
        payload: Payload {
            payload_type: normalized_type,
            data: input.payload.data.clone(),
        },
        auth: input.auth.clone(),
        aux: AuxiliaryData { data: vec![] }, // THM-4: clear auxiliary data
    })
}

// ---------------------------------------------------------------------------
// canonicalize_state — idempotent (DEF-5)
// ---------------------------------------------------------------------------

/// Canonicalize a concrete `State` into canonical form.
///
/// Normalization steps:
/// 1. Keep canonical state C as-is (source of truth).
/// 2. Recompute derived state: `D = derive(C)`.
/// 3. Keep environment E as-is (external context, source of truth).
/// 4. Recompute economic context: `Ω = derive_economic(C, E)`.
/// 5. Keep metadata τ as-is (trace ordering data).
///
/// Validation:
/// - The resulting state must satisfy `valid_state`.
///
/// Idempotent: `canonicalize_state(canonicalize_state(s)) = canonicalize_state(s)` (DEF-5).
pub fn canonicalize_state(state: &State) -> Result<State, CanonicalizationError> {
    // Recompute derived state from canonical (DEF-1).
    let derived = derive(&state.canonical);

    // Recompute economic context from canonical + environment.
    let economic = derive_economic(&state.canonical, &state.environment);

    let canonical_state = State {
        canonical: state.canonical.clone(),
        derived,
        environment: state.environment.clone(),
        economic,
        metadata: state.metadata.clone(),
    };

    // Validate the resulting state.
    if !valid_state(&canonical_state) {
        return Err(CanonicalizationError::InvalidState(
            "canonicalized state fails valid_state predicate".to_string(),
        ));
    }

    Ok(canonical_state)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validate authorization structural requirements.
fn validate_authorization(auth: &Authorization) -> Result<(), CanonicalizationError> {
    if auth.classical_sig.is_empty() || auth.pqc_sig.is_empty() {
        return Err(CanonicalizationError::MissingSignatures);
    }

    if auth.public_key.classical.is_empty() || auth.public_key.pqc.is_empty() {
        return Err(CanonicalizationError::MissingPublicKey);
    }

    if auth.domain.0 == Hash([0u8; 32]) {
        return Err(CanonicalizationError::ZeroDomainTag);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::state::*;
    use vsel_core::types::*;

    // -- Test helpers --

    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        DomainTag(Hash(h))
    }

    fn valid_auth() -> Authorization {
        Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: 42,
            domain: test_domain_tag(),
        }
    }

    fn valid_input_fixture() -> Input {
        Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: vec![0xFF],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![0xDE, 0xAD] },
        }
    }

    fn minimal_canonical() -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: ProtocolVersion { major: 0, minor: 1, patch: 0 },
                total_supply: 0,
                parameters: BTreeMap::new(),
            },
        }
    }

    fn build_valid_state(c: CanonicalState) -> State {
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let meta = TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp: 1_000_000,
        };
        State { canonical: c, derived: d, environment: env, economic: econ, metadata: meta }
    }

    // -- canonicalize_input: happy path --

    #[test]
    fn test_canonicalize_input_normalizes_payload_type() {
        let mut input = valid_input_fixture();
        input.payload.payload_type = "  Transfer  ".to_string();
        let result = canonicalize_input(&input).unwrap();
        assert_eq!(result.payload.payload_type, "transfer");
    }

    #[test]
    fn test_canonicalize_input_clears_aux_data() {
        let input = valid_input_fixture();
        assert!(!input.aux.data.is_empty(), "precondition: aux has data");
        let result = canonicalize_input(&input).unwrap();
        assert!(result.aux.data.is_empty(), "THM-4: aux must be cleared");
    }

    #[test]
    fn test_canonicalize_input_preserves_payload_data() {
        let input = valid_input_fixture();
        let result = canonicalize_input(&input).unwrap();
        assert_eq!(result.payload.data, input.payload.data);
    }

    #[test]
    fn test_canonicalize_input_preserves_auth() {
        let input = valid_input_fixture();
        let result = canonicalize_input(&input).unwrap();
        assert_eq!(result.auth, input.auth);
    }

    #[test]
    fn test_canonicalize_input_idempotent() {
        let input = valid_input_fixture();
        let once = canonicalize_input(&input).unwrap();
        let twice = canonicalize_input(&once).unwrap();
        assert_eq!(once, twice, "DEF-5: canonicalization must be idempotent");
    }

    // -- canonicalize_input: rejection cases --

    #[test]
    fn test_canonicalize_input_rejects_empty_payload_type() {
        let mut input = valid_input_fixture();
        input.payload.payload_type = String::new();
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::EmptyPayloadType)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_whitespace_only_payload_type() {
        let mut input = valid_input_fixture();
        input.payload.payload_type = "   ".to_string();
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::EmptyPayloadType)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_empty_payload_data() {
        let mut input = valid_input_fixture();
        input.payload.data = vec![];
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::EmptyPayloadData)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_empty_classical_sig() {
        let mut input = valid_input_fixture();
        input.auth.classical_sig = vec![];
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::MissingSignatures)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_empty_pqc_sig() {
        let mut input = valid_input_fixture();
        input.auth.pqc_sig = vec![];
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::MissingSignatures)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_empty_classical_pubkey() {
        let mut input = valid_input_fixture();
        input.auth.public_key.classical = vec![];
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::MissingPublicKey)
        );
    }

    #[test]
    fn test_canonicalize_input_rejects_zero_domain() {
        let mut input = valid_input_fixture();
        input.auth.domain = DomainTag(Hash([0u8; 32]));
        assert_eq!(
            canonicalize_input(&input),
            Err(CanonicalizationError::ZeroDomainTag)
        );
    }

    // -- canonicalize_state: happy path --

    #[test]
    fn test_canonicalize_state_valid() {
        let s = build_valid_state(minimal_canonical());
        let result = canonicalize_state(&s).unwrap();
        assert_eq!(result.canonical, s.canonical);
        assert_eq!(result.environment, s.environment);
        assert_eq!(result.metadata, s.metadata);
    }

    #[test]
    fn test_canonicalize_state_recomputes_derived() {
        let mut s = build_valid_state(minimal_canonical());
        // Corrupt derived state.
        s.derived.state_root = Hash([0xFFu8; 32]);
        let result = canonicalize_state(&s).unwrap();
        let expected_derived = derive(&s.canonical);
        assert_eq!(result.derived, expected_derived);
    }

    #[test]
    fn test_canonicalize_state_idempotent() {
        let s = build_valid_state(minimal_canonical());
        let once = canonicalize_state(&s).unwrap();
        let twice = canonicalize_state(&once).unwrap();
        assert_eq!(once, twice, "DEF-5: state canonicalization must be idempotent");
    }

    // -- canonicalize_state: rejection cases --

    #[test]
    fn test_canonicalize_state_rejects_invalid_state() {
        let mut s = build_valid_state(minimal_canonical());
        // Make canonical state invalid: total_supply doesn't match balances.
        s.canonical.system_data.total_supply = 999;
        assert!(canonicalize_state(&s).is_err());
    }
}
