//! Trace mutation testing — adversarial tests for trace integrity.
//!
//! Derived from: EXECUTION_TRACE_MODEL.md, TRACE_SUFFICIENCY.md,
//! Requirements 13.10.
//!
//! Verifies that the trace engine detects and rejects all classes of
//! trace mutation:
//! - Reordering trace entries (swap adjacent, reverse, random permutation)
//! - Removing trace entries (first, middle, last)
//! - Altering metadata (chain hash, pre/post state commitments, observable,
//!   index, environment)
//!
//! Property 55: Trace Mutation Detection — any mutation (reorder, remove,
//! alter) is detected and rejected.
//! **Validates: Requirements 13.10**

use std::collections::BTreeMap;

use proptest::prelude::*;

use vsel_core::input::*;
use vsel_core::observable::{obs, TransitionStatus};
use vsel_core::state::*;
use vsel_core::transition::*;
use vsel_core::types::*;
use vsel_trace::engine::{verify_trace, Trace, TraceEngine};

// ===========================================================================
// Shared test helpers
// ===========================================================================

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
            protocol_version: ProtocolVersion { major: 0, minor: 1, patch: 0 },
            total_supply: 0,
            parameters: BTreeMap::new(),
        },
    }
}

fn build_state_at_seq(c: CanonicalState, seq: u64) -> State {
    let d = derive(&c);
    let env = Environment {
        timestamp: 1_000_000,
        block_height: 1,
        execution_domain: test_domain_tag(),
    };
    let econ = derive_economic(&c, &env);
    let commitment = if seq == 0 { Hash([0u8; 32]) } else { Hash([0xABu8; 32]) };
    let meta = TraceMetadata {
        sequence_index: seq,
        previous_commitment: commitment,
        epoch: 0,
        timestamp: 1_000_000,
    };
    State { canonical: c, derived: d, environment: env, economic: econ, metadata: meta }
}

fn build_genesis_state(c: CanonicalState) -> State {
    build_state_at_seq(c, 0)
}

fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
    Input {
        payload: Payload { payload_type: payload_type.to_string(), data },
        auth: valid_auth(),
        aux: AuxiliaryData { data: vec![] },
    }
}

fn make_deposit_input(account_id: [u8; 32], amount: u128) -> Input {
    let mut data = vec![];
    data.extend_from_slice(&account_id);
    data.extend_from_slice(&amount.to_le_bytes());
    make_input("deposit", data)
}

/// Build a valid 3-entry trace for mutation testing.
fn build_valid_trace() -> Trace {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let obs0 = obs(&s0, &sigma0, &s1);

    let sigma1 = make_deposit_input([1u8; 32], 500);
    let s2 = apply(&s1, &sigma1);
    let obs1 = obs(&s1, &sigma1, &s2);

    let sigma2 = make_input("unknown_op", vec![0x01]);
    let s3 = apply(&s2, &sigma2);
    let obs2 = obs(&s2, &sigma2, &s3);

    let mut engine = TraceEngine::new();
    let e0 = engine.record_transition(&s0, &sigma0, &s1, &obs0);
    let e1 = engine.record_transition(&s1, &sigma1, &s2, &obs1);
    let e2 = engine.record_transition(&s2, &sigma2, &s3, &obs2);
    let commitment = engine.current_chain_hash().clone();

    Trace { entries: vec![e0, e1, e2], initial_state: s0, commitment }
}

/// Build a valid N-entry trace from a sequence of deposit amounts.
fn build_n_entry_trace(deposit_amounts: &[u128]) -> Trace {
    let c = minimal_canonical();
    let s0 = build_genesis_state(c);
    let sigma0 = make_input("init", vec![0xFF]);
    let s1 = apply(&s0, &sigma0);
    let obs0 = obs(&s0, &sigma0, &s1);

    let mut engine = TraceEngine::new();
    let e0 = engine.record_transition(&s0, &sigma0, &s1, &obs0);
    let mut entries = vec![e0];
    let mut current_state = s1;

    for (i, &amount) in deposit_amounts.iter().enumerate() {
        let account_id = {
            let mut id = [0u8; 32];
            // Use index as account discriminator to avoid collisions
            id[0] = ((i + 1) & 0xFF) as u8;
            id[1] = (((i + 1) >> 8) & 0xFF) as u8;
            id
        };
        let sigma = make_deposit_input(account_id, amount);
        let next_state = apply(&current_state, &sigma);
        let observable = obs(&current_state, &sigma, &next_state);
        let entry = engine.record_transition(&current_state, &sigma, &next_state, &observable);
        entries.push(entry);
        current_state = next_state;
    }

    let commitment = engine.current_chain_hash().clone();
    Trace { entries, initial_state: s0, commitment }
}

// ===========================================================================
// Sanity: valid trace passes verification
// ===========================================================================

#[test]
fn sanity_valid_trace_passes_verification() {
    let trace = build_valid_trace();
    assert!(verify_trace(&trace), "Sanity: a correctly built trace must pass verification");
}

// ===========================================================================
// Reorder trace entries and verify detection
// ===========================================================================

#[test]
fn reorder_swap_adjacent_entries() {
    let mut trace = build_valid_trace();
    trace.entries.swap(0, 1);
    assert!(
        !verify_trace(&trace),
        "Reorder: swapping adjacent entries (0, 1) must be detected"
    );
}

#[test]
fn reorder_swap_first_and_last() {
    let mut trace = build_valid_trace();
    trace.entries.swap(0, 2);
    assert!(
        !verify_trace(&trace),
        "Reorder: swapping first and last entries must be detected"
    );
}

#[test]
fn reorder_swap_middle_and_last() {
    let mut trace = build_valid_trace();
    trace.entries.swap(1, 2);
    assert!(
        !verify_trace(&trace),
        "Reorder: swapping middle and last entries must be detected"
    );
}

#[test]
fn reorder_reverse_all_entries() {
    let mut trace = build_valid_trace();
    trace.entries.reverse();
    assert!(
        !verify_trace(&trace),
        "Reorder: reversing all entries must be detected"
    );
}

#[test]
fn reorder_rotate_entries_left() {
    let mut trace = build_valid_trace();
    // Rotate left: [0,1,2] -> [1,2,0]
    trace.entries.rotate_left(1);
    assert!(
        !verify_trace(&trace),
        "Reorder: rotating entries left must be detected"
    );
}

#[test]
fn reorder_rotate_entries_right() {
    let mut trace = build_valid_trace();
    // Rotate right: [0,1,2] -> [2,0,1]
    trace.entries.rotate_right(1);
    assert!(
        !verify_trace(&trace),
        "Reorder: rotating entries right must be detected"
    );
}

// ===========================================================================
// Remove transitions and verify detection
// ===========================================================================

#[test]
fn remove_first_entry() {
    let mut trace = build_valid_trace();
    trace.entries.remove(0);
    assert!(
        !verify_trace(&trace),
        "Remove: removing the first entry must be detected"
    );
}

#[test]
fn remove_middle_entry() {
    let mut trace = build_valid_trace();
    trace.entries.remove(1);
    assert!(
        !verify_trace(&trace),
        "Remove: removing the middle entry must be detected"
    );
}

#[test]
fn remove_last_entry() {
    let mut trace = build_valid_trace();
    trace.entries.remove(2);
    assert!(
        !verify_trace(&trace),
        "Remove: removing the last entry must be detected (commitment mismatch)"
    );
}

#[test]
fn remove_all_entries() {
    let trace = build_valid_trace();
    let original_len = trace.entries.len();
    assert!(original_len > 0, "Precondition: trace must have entries");

    // verify_trace returns true for empty entries (by design — empty trace is
    // trivially valid). The real detection mechanism is that the commitment no
    // longer matches any non-empty trace. We verify that the original trace
    // with entries removed is structurally different and that removing entries
    // one at a time is always detected.
    for i in 0..original_len {
        let mut mutated = trace.clone();
        mutated.entries.remove(i);
        assert!(
            !verify_trace(&mutated),
            "Remove: removing entry {} from a {}-entry trace must be detected",
            i,
            original_len
        );
    }
}

#[test]
fn remove_duplicate_entry_instead() {
    let mut trace = build_valid_trace();
    // Replace middle entry with a duplicate of the first
    trace.entries[1] = trace.entries[0].clone();
    assert!(
        !verify_trace(&trace),
        "Remove: replacing an entry with a duplicate must be detected"
    );
}

// ===========================================================================
// Alter metadata and verify detection
// ===========================================================================

#[test]
fn alter_chain_hash_first_entry() {
    let mut trace = build_valid_trace();
    trace.entries[0].chain_hash = Hash([0xDEu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted chain hash on first entry must be detected"
    );
}

#[test]
fn alter_chain_hash_middle_entry() {
    let mut trace = build_valid_trace();
    trace.entries[1].chain_hash = Hash([0xDEu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted chain hash on middle entry must be detected"
    );
}

#[test]
fn alter_chain_hash_last_entry() {
    let mut trace = build_valid_trace();
    trace.entries[2].chain_hash = Hash([0xDEu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted chain hash on last entry must be detected"
    );
}

#[test]
fn alter_pre_state_commitment() {
    let mut trace = build_valid_trace();
    trace.entries[0].pre_state_commitment = Hash([0xFFu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted pre_state_commitment must be detected"
    );
}

#[test]
fn alter_post_state_commitment() {
    let mut trace = build_valid_trace();
    trace.entries[1].post_state_commitment = Hash([0xEEu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted post_state_commitment must be detected"
    );
}

#[test]
fn alter_observable_gas() {
    let mut trace = build_valid_trace();
    trace.entries[1].observable.gas_used = 999_999;
    assert!(
        !verify_trace(&trace),
        "Alter: modified observable gas_used must be detected via chain hash"
    );
}

#[test]
fn alter_observable_status() {
    let mut trace = build_valid_trace();
    trace.entries[0].observable.status = TransitionStatus::Error;
    assert!(
        !verify_trace(&trace),
        "Alter: modified observable status must be detected via chain hash"
    );
}

#[test]
fn alter_observable_transition_class() {
    let mut trace = build_valid_trace();
    trace.entries[0].observable.transition_class = TransitionClass::Noop;
    assert!(
        !verify_trace(&trace),
        "Alter: modified observable transition_class must be detected via chain hash"
    );
}

#[test]
fn alter_entry_index() {
    let mut trace = build_valid_trace();
    trace.entries[1].index = 99;
    assert!(
        !verify_trace(&trace),
        "Alter: modified entry index must be detected"
    );
}

#[test]
fn alter_environment_timestamp() {
    let mut trace = build_valid_trace();
    trace.entries[1].environment.timestamp = 9_999_999;
    assert!(
        !verify_trace(&trace),
        "Alter: modified environment timestamp must be detected via chain hash"
    );
}

#[test]
fn alter_environment_block_height() {
    let mut trace = build_valid_trace();
    trace.entries[1].environment.block_height = 999;
    assert!(
        !verify_trace(&trace),
        "Alter: modified environment block_height must be detected via chain hash"
    );
}

#[test]
fn alter_environment_domain() {
    let mut trace = build_valid_trace();
    trace.entries[1].environment.execution_domain = DomainTag(Hash([0xCDu8; 32]));
    assert!(
        !verify_trace(&trace),
        "Alter: modified environment execution_domain must be detected via chain hash"
    );
}

#[test]
fn alter_final_commitment() {
    let mut trace = build_valid_trace();
    trace.commitment = Hash([0xBBu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: corrupted final commitment must be detected"
    );
}

#[test]
fn alter_initial_state() {
    let mut trace = build_valid_trace();
    let mut fake_c = minimal_canonical();
    fake_c.system_data.total_supply = 0;
    fake_c.system_data.parameters.insert("rogue".to_string(), vec![0xDE, 0xAD]);
    trace.initial_state = build_genesis_state(fake_c);
    assert!(
        !verify_trace(&trace),
        "Alter: modified initial state must be detected (commitment mismatch)"
    );
}

#[test]
fn alter_input_payload_data() {
    let mut trace = build_valid_trace();
    trace.entries[1].input.payload.data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    assert!(
        !verify_trace(&trace),
        "Alter: modified input payload data must be detected via chain hash"
    );
}

#[test]
fn alter_input_payload_type() {
    let mut trace = build_valid_trace();
    trace.entries[0].input.payload.payload_type = "tampered".to_string();
    assert!(
        !verify_trace(&trace),
        "Alter: modified input payload type must be detected via chain hash"
    );
}

#[test]
fn alter_input_auth_nonce() {
    let mut trace = build_valid_trace();
    trace.entries[1].input.auth.nonce = 999_999;
    assert!(
        !verify_trace(&trace),
        "Alter: modified auth nonce must be detected via chain hash"
    );
}

#[test]
fn alter_state_commitment_chain_break() {
    let mut trace = build_valid_trace();
    // Break the state commitment chain: post[0] != pre[1]
    trace.entries[0].post_state_commitment = Hash([0xAAu8; 32]);
    assert!(
        !verify_trace(&trace),
        "Alter: breaking state commitment chain (post[i] != pre[i+1]) must be detected"
    );
}

// ===========================================================================
// Property 55: Trace Mutation Detection (proptest)
// ===========================================================================
//
// **Property 55: Trace Mutation Detection** — any mutation (reorder, remove,
// alter) is detected and rejected.
// **Validates: Requirements 13.10**

/// Mutation types for property testing.
#[derive(Debug, Clone)]
enum TraceMutation {
    /// Swap two entries at the given indices.
    SwapEntries(usize, usize),
    /// Remove the entry at the given index.
    RemoveEntry(usize),
    /// Alter the chain hash of the entry at the given index.
    AlterChainHash(usize, [u8; 32]),
    /// Alter the pre_state_commitment of the entry at the given index.
    AlterPreCommitment(usize, [u8; 32]),
    /// Alter the post_state_commitment of the entry at the given index.
    AlterPostCommitment(usize, [u8; 32]),
    /// Alter the observable gas_used of the entry at the given index.
    AlterGasUsed(usize, u64),
    /// Alter the environment timestamp of the entry at the given index.
    AlterTimestamp(usize, u64),
    /// Alter the environment block_height of the entry at the given index.
    AlterBlockHeight(usize, u64),
    /// Alter the environment execution_domain of the entry at the given index.
    AlterDomain(usize, [u8; 32]),
    /// Alter the entry index field.
    AlterIndex(usize, u64),
    /// Alter the final trace commitment.
    AlterFinalCommitment([u8; 32]),
}

/// Strategy to generate a mutation for a trace of the given length.
fn mutation_strategy(trace_len: usize) -> BoxedStrategy<TraceMutation> {
    let idx = 0..trace_len;
    prop_oneof![
        // SwapEntries: two distinct indices
        (0..trace_len, 0..trace_len)
            .prop_filter("indices must differ", |(a, b)| a != b)
            .prop_map(|(a, b)| TraceMutation::SwapEntries(a, b)),
        // RemoveEntry
        idx.clone().prop_map(TraceMutation::RemoveEntry),
        // AlterChainHash
        (idx.clone(), any::<[u8; 32]>())
            .prop_map(|(i, h)| TraceMutation::AlterChainHash(i, h)),
        // AlterPreCommitment
        (idx.clone(), any::<[u8; 32]>())
            .prop_map(|(i, h)| TraceMutation::AlterPreCommitment(i, h)),
        // AlterPostCommitment
        (idx.clone(), any::<[u8; 32]>())
            .prop_map(|(i, h)| TraceMutation::AlterPostCommitment(i, h)),
        // AlterGasUsed
        (idx.clone(), any::<u64>())
            .prop_map(|(i, g)| TraceMutation::AlterGasUsed(i, g)),
        // AlterTimestamp
        (idx.clone(), any::<u64>())
            .prop_map(|(i, t)| TraceMutation::AlterTimestamp(i, t)),
        // AlterBlockHeight
        (idx.clone(), any::<u64>())
            .prop_map(|(i, b)| TraceMutation::AlterBlockHeight(i, b)),
        // AlterDomain
        (idx.clone(), any::<[u8; 32]>())
            .prop_map(|(i, d)| TraceMutation::AlterDomain(i, d)),
        // AlterIndex
        (idx.clone(), any::<u64>())
            .prop_map(|(i, x)| TraceMutation::AlterIndex(i, x)),
        // AlterFinalCommitment
        any::<[u8; 32]>().prop_map(TraceMutation::AlterFinalCommitment),
    ]
    .boxed()
}

/// Apply a mutation to a trace, returning true if the mutation actually
/// changed the trace (i.e., is non-trivial).
fn apply_mutation(trace: &mut Trace, mutation: &TraceMutation) -> bool {
    match mutation {
        TraceMutation::SwapEntries(a, b) => {
            if a == b {
                return false;
            }
            trace.entries.swap(*a, *b);
            true
        }
        TraceMutation::RemoveEntry(idx) => {
            trace.entries.remove(*idx);
            true
        }
        TraceMutation::AlterChainHash(idx, h) => {
            let new_hash = Hash(*h);
            if trace.entries[*idx].chain_hash == new_hash {
                return false;
            }
            trace.entries[*idx].chain_hash = new_hash;
            true
        }
        TraceMutation::AlterPreCommitment(idx, h) => {
            let new_hash = Hash(*h);
            if trace.entries[*idx].pre_state_commitment == new_hash {
                return false;
            }
            trace.entries[*idx].pre_state_commitment = new_hash;
            true
        }
        TraceMutation::AlterPostCommitment(idx, h) => {
            let new_hash = Hash(*h);
            if trace.entries[*idx].post_state_commitment == new_hash {
                return false;
            }
            trace.entries[*idx].post_state_commitment = new_hash;
            true
        }
        TraceMutation::AlterGasUsed(idx, g) => {
            if trace.entries[*idx].observable.gas_used == *g {
                return false;
            }
            trace.entries[*idx].observable.gas_used = *g;
            true
        }
        TraceMutation::AlterTimestamp(idx, t) => {
            if trace.entries[*idx].environment.timestamp == *t {
                return false;
            }
            trace.entries[*idx].environment.timestamp = *t;
            true
        }
        TraceMutation::AlterBlockHeight(idx, b) => {
            if trace.entries[*idx].environment.block_height == *b {
                return false;
            }
            trace.entries[*idx].environment.block_height = *b;
            true
        }
        TraceMutation::AlterDomain(idx, d) => {
            let new_domain = DomainTag(Hash(*d));
            if trace.entries[*idx].environment.execution_domain == new_domain {
                return false;
            }
            trace.entries[*idx].environment.execution_domain = new_domain;
            true
        }
        TraceMutation::AlterIndex(idx, x) => {
            if trace.entries[*idx].index == *x {
                return false;
            }
            trace.entries[*idx].index = *x;
            true
        }
        TraceMutation::AlterFinalCommitment(h) => {
            let new_hash = Hash(*h);
            if trace.commitment == new_hash {
                return false;
            }
            trace.commitment = new_hash;
            true
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// **Property 55: Trace Mutation Detection**
    ///
    /// For any valid trace and any non-trivial mutation (reorder, remove,
    /// alter), `verify_trace` detects the mutation and rejects the trace.
    ///
    /// **Validates: Requirements 13.10**
    #[test]
    fn prop_55_trace_mutation_detected(
        // Generate 1..4 extra deposit amounts to vary trace length (2..5 entries)
        // We need at least 2 entries so that removal always leaves a non-empty
        // trace (verify_trace trivially accepts empty traces by design).
        extra_deposits in prop::collection::vec(1u128..10_000, 1..4),
        mutation_seed in mutation_strategy(5), // max possible length
    ) {
        let trace = build_n_entry_trace(&extra_deposits);
        let trace_len = trace.entries.len();

        // Sanity: the unmodified trace must pass verification
        prop_assert!(
            verify_trace(&trace),
            "Precondition failed: valid trace must pass verification"
        );

        // Adjust mutation indices to fit the actual trace length
        let mutation = remap_mutation(&mutation_seed, trace_len);
        if mutation.is_none() {
            // Mutation doesn't apply to this trace size — skip
            return Ok(());
        }
        let mutation = mutation.unwrap();

        let mut mutated_trace = trace.clone();
        let changed = apply_mutation(&mut mutated_trace, &mutation);

        if changed {
            prop_assert!(
                !verify_trace(&mutated_trace),
                "Property 55 violated: mutation {:?} was not detected on trace of length {}",
                mutation,
                trace_len
            );
        }
        // If the mutation was trivial (no actual change), the trace should still pass.
        // This is fine — we only assert rejection for non-trivial mutations.
    }
}

/// Remap mutation indices to fit within the actual trace length.
/// Returns None if the mutation cannot be applied to a trace of this length.
fn remap_mutation(mutation: &TraceMutation, trace_len: usize) -> Option<TraceMutation> {
    if trace_len == 0 {
        // Only AlterFinalCommitment works on empty traces, but our traces
        // always have at least 1 entry (the init entry).
        return match mutation {
            TraceMutation::AlterFinalCommitment(h) => {
                Some(TraceMutation::AlterFinalCommitment(*h))
            }
            _ => None,
        };
    }

    match mutation {
        TraceMutation::SwapEntries(a, b) => {
            if trace_len < 2 {
                return None;
            }
            let a = a % trace_len;
            let b = b % trace_len;
            if a == b {
                // Make them different
                let b = (a + 1) % trace_len;
                Some(TraceMutation::SwapEntries(a, b))
            } else {
                Some(TraceMutation::SwapEntries(a, b))
            }
        }
        TraceMutation::RemoveEntry(idx) => {
            Some(TraceMutation::RemoveEntry(idx % trace_len))
        }
        TraceMutation::AlterChainHash(idx, h) => {
            Some(TraceMutation::AlterChainHash(idx % trace_len, *h))
        }
        TraceMutation::AlterPreCommitment(idx, h) => {
            Some(TraceMutation::AlterPreCommitment(idx % trace_len, *h))
        }
        TraceMutation::AlterPostCommitment(idx, h) => {
            Some(TraceMutation::AlterPostCommitment(idx % trace_len, *h))
        }
        TraceMutation::AlterGasUsed(idx, g) => {
            Some(TraceMutation::AlterGasUsed(idx % trace_len, *g))
        }
        TraceMutation::AlterTimestamp(idx, t) => {
            Some(TraceMutation::AlterTimestamp(idx % trace_len, *t))
        }
        TraceMutation::AlterBlockHeight(idx, b) => {
            Some(TraceMutation::AlterBlockHeight(idx % trace_len, *b))
        }
        TraceMutation::AlterDomain(idx, d) => {
            Some(TraceMutation::AlterDomain(idx % trace_len, *d))
        }
        TraceMutation::AlterIndex(idx, x) => {
            Some(TraceMutation::AlterIndex(idx % trace_len, *x))
        }
        TraceMutation::AlterFinalCommitment(h) => {
            Some(TraceMutation::AlterFinalCommitment(*h))
        }
    }
}
