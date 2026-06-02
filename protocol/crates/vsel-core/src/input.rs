//! Input model for the VSEL protocol.
//!
//! Derived from: SEMANTIC_MAPPING.md §5, TECH_SPEC.md §3.4,
//! FORMAL_SPECIFICATION.md §3.
//!
//! Input: σ = (payload, auth, aux)
//! - payload: Semantic content (Payload from types.rs)
//! - auth: Authorization evidence (hybrid classical + PQC)
//! - aux: Auxiliary data — must NOT influence semantics (THM-4)

use crate::types::*;

// ---------------------------------------------------------------------------
// Authorization — hybrid classical + PQC
// ---------------------------------------------------------------------------

/// Authorization evidence for an input.
///
/// Both classical (Ed25519) and PQC (ML-DSA/Falcon) signatures must be
/// present and non-empty for the input to be structurally valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Ed25519 signature bytes.
    pub classical_sig: Vec<u8>,
    /// ML-DSA/Falcon signature bytes.
    pub pqc_sig: Vec<u8>,
    /// Hybrid public key (classical + PQC components).
    pub public_key: HybridPublicKey,
    /// Replay-prevention nonce.
    pub nonce: u64,
    /// Domain separation tag for this authorization.
    pub domain: DomainTag,
}

// ---------------------------------------------------------------------------
// Input — σ = (payload, auth, aux)
// ---------------------------------------------------------------------------

/// Input to the VSEL state machine.
///
/// SEMANTIC_MAPPING.md §5, TECH_SPEC.md §3.4.
/// Auxiliary data (`aux`) must NOT influence semantic outcome (THM-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    /// Semantic content of the input.
    pub payload: Payload,
    /// Authorization / permission evidence.
    pub auth: Authorization,
    /// Auxiliary data — ignored by execution semantics.
    pub aux: AuxiliaryData,
}

// ---------------------------------------------------------------------------
// Input validity predicate
// ---------------------------------------------------------------------------

/// Check whether an `Input` is structurally valid.
///
/// Validates (Requirements 1.1, 4.5, 10.1):
/// - Payload has a non-empty `payload_type` and non-empty `data`.
/// - Authorization has non-empty classical and PQC signatures.
/// - Authorization has non-empty classical and PQC public key components.
/// - Domain tag is not the zero hash.
/// - Nonce is structurally valid (always true for u64).
pub fn valid_input(sigma: &Input) -> bool {
    valid_payload(&sigma.payload) && valid_authorization(&sigma.auth)
}

/// Payload validity: type identifier and data must both be non-empty.
fn valid_payload(p: &Payload) -> bool {
    !p.payload_type.is_empty() && !p.data.is_empty()
}

/// Authorization validity:
/// - Both signature components are non-empty.
/// - Both public key components are non-empty.
/// - Domain tag is not the zero hash.
fn valid_authorization(a: &Authorization) -> bool {
    !a.classical_sig.is_empty()
        && !a.pqc_sig.is_empty()
        && !a.public_key.classical.is_empty()
        && !a.public_key.pqc.is_empty()
        && a.domain.0 != Hash([0u8; 32])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a non-zero domain tag.
    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        DomainTag(Hash(h))
    }

    /// Helper: build a valid Authorization.
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

    /// Helper: build a valid Input.
    fn valid_input_fixture() -> Input {
        Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: vec![0xFF],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    // -- happy path --

    #[test]
    fn test_valid_input_passes() {
        let input = valid_input_fixture();
        assert!(valid_input(&input));
    }

    #[test]
    fn test_valid_input_with_nonempty_aux() {
        let mut input = valid_input_fixture();
        input.aux.data = vec![0xDE, 0xAD];
        assert!(valid_input(&input), "aux data should not affect validity");
    }

    // -- payload failures --

    #[test]
    fn test_invalid_empty_payload_type() {
        let mut input = valid_input_fixture();
        input.payload.payload_type = String::new();
        assert!(!valid_input(&input));
    }

    #[test]
    fn test_invalid_empty_payload_data() {
        let mut input = valid_input_fixture();
        input.payload.data = vec![];
        assert!(!valid_input(&input));
    }

    // -- authorization failures --

    #[test]
    fn test_invalid_empty_classical_sig() {
        let mut input = valid_input_fixture();
        input.auth.classical_sig = vec![];
        assert!(!valid_input(&input));
    }

    #[test]
    fn test_invalid_empty_pqc_sig() {
        let mut input = valid_input_fixture();
        input.auth.pqc_sig = vec![];
        assert!(!valid_input(&input));
    }

    #[test]
    fn test_invalid_empty_classical_pubkey() {
        let mut input = valid_input_fixture();
        input.auth.public_key.classical = vec![];
        assert!(!valid_input(&input));
    }

    #[test]
    fn test_invalid_empty_pqc_pubkey() {
        let mut input = valid_input_fixture();
        input.auth.public_key.pqc = vec![];
        assert!(!valid_input(&input));
    }

    #[test]
    fn test_invalid_zero_domain_tag() {
        let mut input = valid_input_fixture();
        input.auth.domain = DomainTag(Hash([0u8; 32]));
        assert!(!valid_input(&input));
    }

    // -- nonce is always structurally valid --

    #[test]
    fn test_nonce_zero_is_valid() {
        let mut input = valid_input_fixture();
        input.auth.nonce = 0;
        assert!(valid_input(&input));
    }

    #[test]
    fn test_nonce_max_is_valid() {
        let mut input = valid_input_fixture();
        input.auth.nonce = u64::MAX;
        assert!(valid_input(&input));
    }
}
