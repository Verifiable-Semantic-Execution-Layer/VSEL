//! Counter overflow boundary tests — L-004 remediation.
//!
//! Validates that monotonic counters (`sequence_index`, `epoch`) behave
//! correctly at the `u64::MAX` boundary. While physically unreachable
//! (~1.8 × 10¹⁹ transitions), explicit overflow handling is formally
//! important for the G_mono invariant.
//!
//! Overflow policy: **saturating arithmetic**. Counters stop at `u64::MAX`
//! rather than wrapping, preserving `post.sequence_index >= pre.sequence_index`.

use std::collections::BTreeMap;

use vsel_core::input::{Authorization, Input};
use vsel_core::state::{
    derive, derive_economic, valid_state, CanonicalState, Environment, State, TraceMetadata,
};
use vsel_core::transition::apply;
use vsel_core::types::*;
use vsel_invariants::global::g_mono;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn minimal_canonical() -> CanonicalState {
    CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

/// Build a state at a given sequence_index with a given epoch.
fn build_state(seq: u64, epoch: u64) -> State {
    let c = minimal_canonical();
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    // Non-genesis states need a non-zero previous_commitment.
    let commitment = if seq == 0 {
        Hash([0u8; 32])
    } else {
        Hash([0xABu8; 32])
    };
    let meta = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch,
        timestamp: 1_000_000,
    };
    State {
        canonical: c,
        derived: d,
        environment: env,
        economic: econ,
        metadata: meta,
    }
}

fn make_noop_input() -> Input {
    Input {
        payload: Payload {
            payload_type: "unknown_op".to_string(),
            data: vec![0x01],
        },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

// ===========================================================================
// sequence_index boundary tests
// ===========================================================================

/// Transition at u64::MAX - 1 must increment sequence_index to u64::MAX.
#[test]
fn sequence_index_increments_to_max() {
    let s = build_state(u64::MAX - 1, 0);
    let sigma = make_noop_input();

    let post = apply(&s, &sigma);

    assert_eq!(
        post.metadata.sequence_index,
        u64::MAX,
        "sequence_index must increment from MAX-1 to MAX"
    );
    assert!(
        post.metadata.sequence_index > s.metadata.sequence_index,
        "G_mono: post.sequence_index must be strictly greater than pre"
    );
}

/// Transition at u64::MAX must saturate — sequence_index stays at u64::MAX.
/// This is the explicit overflow handling: saturating_add prevents panic/wrap.
#[test]
fn sequence_index_saturates_at_max() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();

    let post = apply(&s, &sigma);

    assert_eq!(
        post.metadata.sequence_index,
        u64::MAX,
        "sequence_index must saturate at u64::MAX (no wrap, no panic)"
    );
    assert!(
        post.metadata.sequence_index >= s.metadata.sequence_index,
        "G_mono: post.sequence_index >= pre.sequence_index must hold at boundary"
    );
}

/// Two consecutive transitions at u64::MAX both saturate.
#[test]
fn sequence_index_saturates_repeatedly() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();

    let post1 = apply(&s, &sigma);
    let post2 = apply(&post1, &sigma);

    assert_eq!(post1.metadata.sequence_index, u64::MAX);
    assert_eq!(post2.metadata.sequence_index, u64::MAX);
    assert!(
        post2.metadata.sequence_index >= post1.metadata.sequence_index,
        "G_mono must hold across repeated saturated transitions"
    );
}

/// State validity holds at u64::MAX sequence_index.
#[test]
fn state_valid_at_max_sequence_index() {
    let s = build_state(u64::MAX, 0);
    assert!(
        valid_state(&s),
        "State with sequence_index = u64::MAX must be valid"
    );
}

/// Post-state after transition at u64::MAX is valid.
#[test]
fn post_state_valid_after_saturated_transition() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();
    let post = apply(&s, &sigma);

    assert!(
        valid_state(&post),
        "Post-state after saturated transition must be valid (AX-2 closure)"
    );
}

/// G_mono invariant holds at u64::MAX - 1 boundary.
#[test]
fn g_mono_holds_at_max_minus_one() {
    let s = build_state(u64::MAX - 1, 0);
    let result = g_mono(&s);
    assert!(
        result.valid,
        "G_mono must hold at sequence_index = u64::MAX - 1"
    );
}

/// G_mono invariant holds at u64::MAX boundary.
#[test]
fn g_mono_holds_at_max() {
    let s = build_state(u64::MAX, 0);
    let result = g_mono(&s);
    assert!(
        result.valid,
        "G_mono must hold at sequence_index = u64::MAX"
    );
}

/// G_mono holds on post-state after transition at u64::MAX.
#[test]
fn g_mono_holds_after_saturated_transition() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();
    let post = apply(&s, &sigma);

    let result = g_mono(&post);
    assert!(
        result.valid,
        "G_mono must hold on post-state after saturated transition"
    );
}

// ===========================================================================
// epoch boundary tests
// ===========================================================================

/// Epoch at u64::MAX does not cause issues during transition.
/// (epoch is not incremented by advance_metadata — it is externally managed.)
#[test]
fn epoch_at_max_does_not_panic() {
    let s = build_state(1, u64::MAX);
    let sigma = make_noop_input();

    let post = apply(&s, &sigma);

    assert_eq!(
        post.metadata.epoch, u64::MAX,
        "epoch must remain at u64::MAX (not incremented by advance_metadata)"
    );
    assert!(
        valid_state(&post),
        "Post-state with epoch = u64::MAX must be valid"
    );
}

/// State validity holds with epoch at u64::MAX.
#[test]
fn state_valid_at_max_epoch() {
    let s = build_state(1, u64::MAX);
    assert!(
        valid_state(&s),
        "State with epoch = u64::MAX must be valid"
    );
}

/// G_mono holds with epoch at u64::MAX.
#[test]
fn g_mono_holds_at_max_epoch() {
    let s = build_state(1, u64::MAX);
    let result = g_mono(&s);
    assert!(
        result.valid,
        "G_mono must hold with epoch = u64::MAX"
    );
}

/// Both counters at u64::MAX simultaneously.
#[test]
fn both_counters_at_max() {
    let s = build_state(u64::MAX, u64::MAX);
    let sigma = make_noop_input();

    let post = apply(&s, &sigma);

    assert_eq!(post.metadata.sequence_index, u64::MAX);
    assert_eq!(post.metadata.epoch, u64::MAX);
    assert!(
        valid_state(&post),
        "Post-state with both counters at u64::MAX must be valid"
    );

    let result = g_mono(&post);
    assert!(
        result.valid,
        "G_mono must hold with both counters at u64::MAX"
    );
}

// ===========================================================================
// Commitment chain integrity at boundary
// ===========================================================================

/// Commitment chain still advances even when sequence_index saturates.
/// The commitment hash changes because it incorporates the current
/// sequence_index value, so two consecutive saturated transitions
/// produce different commitments (the hash input is the same, but
/// the previous_commitment differs after the first transition).
#[test]
fn commitment_advances_at_saturation() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();

    let post1 = apply(&s, &sigma);
    let post2 = apply(&post1, &sigma);

    // Both saturate at u64::MAX
    assert_eq!(post1.metadata.sequence_index, u64::MAX);
    assert_eq!(post2.metadata.sequence_index, u64::MAX);

    // But commitments differ because previous_commitment feeds into the hash
    assert_ne!(
        post1.metadata.previous_commitment,
        s.metadata.previous_commitment,
        "Commitment must change on first saturated transition"
    );
    assert_ne!(
        post2.metadata.previous_commitment,
        post1.metadata.previous_commitment,
        "Commitment must change on second saturated transition"
    );
}

/// Canonical state is preserved through noop at u64::MAX boundary.
#[test]
fn canonical_state_preserved_at_boundary() {
    let s = build_state(u64::MAX, 0);
    let sigma = make_noop_input();
    let post = apply(&s, &sigma);

    assert_eq!(
        s.canonical, post.canonical,
        "Noop at u64::MAX boundary must not change canonical state"
    );
}
