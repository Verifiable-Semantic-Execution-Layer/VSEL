//! Transition guard system for the VSEL execution engine.
//!
//! Derived from: STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md,
//! FORMAL_SPECIFICATION.md §3, Requirements 2.7.
//!
//! Provides a structured, extensible guard-based approach to transition
//! classification. Each transition class has a dedicated guard that
//! determines whether a (state, input) pair belongs to that class.
//!
//! Guards are evaluated in strict priority order:
//!   Reject > Init > Error > Batch > Update > Noop
//!
//! Guarantees:
//! - **Exhaustiveness**: every (s, σ) pair is handled by exactly one class.
//! - **Disjointness**: after priority resolution, no (s, σ) pair triggers
//!   two classes.

use vsel_core::input::{valid_input, Input};
use vsel_core::state::State;
use vsel_core::transition::TransitionClass;

// ---------------------------------------------------------------------------
// TransitionGuard trait
// ---------------------------------------------------------------------------

/// A guard that determines whether a (state, input) pair belongs to a
/// specific transition class.
///
/// Guards are evaluated in priority order (lowest discriminant first).
/// The first matching guard wins, ensuring disjointness.
pub trait TransitionGuard {
    /// Returns `true` if this guard matches the given (state, input) pair.
    fn matches(&self, state: &State, input: &Input) -> bool;

    /// The transition class this guard produces when it matches.
    fn class(&self) -> TransitionClass;
}

// ---------------------------------------------------------------------------
// Concrete guard structs
// ---------------------------------------------------------------------------

/// Guard for `TransitionClass::Reject` — structurally invalid input.
///
/// Matches when the input fails structural validity checks (empty payload
/// type, empty payload data, missing signatures, zero domain tag, etc.).
pub struct RejectGuard;

impl TransitionGuard for RejectGuard {
    fn matches(&self, _state: &State, input: &Input) -> bool {
        !valid_input(input)
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Reject
    }
}

/// Guard for `TransitionClass::Init` — initialization transition.
///
/// Matches when the state is at genesis (sequence_index == 0) and the
/// input payload type is "init".
pub struct InitGuard;

impl TransitionGuard for InitGuard {
    fn matches(&self, state: &State, input: &Input) -> bool {
        state.metadata.sequence_index == 0 && input.payload.payload_type == "init"
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Init
    }
}

/// Guard for `TransitionClass::Error` — precondition failure.
///
/// Matches when the input is structurally valid but the state does not
/// satisfy the preconditions for the requested operation (e.g., transfer
/// from a non-existent account).
pub struct ErrorGuard;

impl TransitionGuard for ErrorGuard {
    fn matches(&self, state: &State, input: &Input) -> bool {
        is_precondition_failure(state, input)
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Error
    }
}

/// Guard for `TransitionClass::Batch` — batch processing.
///
/// Matches when the payload type is "batch".
pub struct BatchGuard;

impl TransitionGuard for BatchGuard {
    fn matches(&self, _state: &State, input: &Input) -> bool {
        input.payload.payload_type == "batch"
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Batch
    }
}

/// Guard for `TransitionClass::Update` — standard state update.
///
/// Matches when the payload type is a recognized operation type.
pub struct UpdateGuard;

impl TransitionGuard for UpdateGuard {
    fn matches(&self, _state: &State, input: &Input) -> bool {
        is_recognized_payload(&input.payload.payload_type)
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Update
    }
}

/// Guard for `TransitionClass::Noop` — catch-all, lowest priority.
///
/// Always matches. Because it is evaluated last (lowest priority), it
/// only fires when no higher-priority guard matched.
pub struct NoopGuard;

impl TransitionGuard for NoopGuard {
    fn matches(&self, _state: &State, _input: &Input) -> bool {
        true // catch-all
    }

    fn class(&self) -> TransitionClass {
        TransitionClass::Noop
    }
}

// ---------------------------------------------------------------------------
// Guard registry — ordered by priority
// ---------------------------------------------------------------------------

/// Returns the complete set of guards in priority order (highest first).
///
/// The ordering matches the spec's priority:
///   Reject (0) > Init (1) > Error (2) > Batch (3) > Update (4) > Noop (5)
pub fn guards_in_priority_order() -> Vec<Box<dyn TransitionGuard>> {
    vec![
        Box::new(RejectGuard),
        Box::new(InitGuard),
        Box::new(ErrorGuard),
        Box::new(BatchGuard),
        Box::new(UpdateGuard),
        Box::new(NoopGuard),
    ]
}

// ---------------------------------------------------------------------------
// classify_transition — priority-based guard evaluation
// ---------------------------------------------------------------------------

/// Classify a (state, input) pair into exactly one `TransitionClass`.
///
/// Evaluates guards in priority order (highest priority first). The first
/// matching guard determines the class. Because `NoopGuard` always matches,
/// this function is total — every (s, σ) pair is classified.
///
/// This guarantees:
/// - **Exhaustiveness**: `NoopGuard` is a catch-all, so classification
///   always succeeds.
/// - **Disjointness**: priority ordering means only the first match fires.
///
/// Requirements: 2.7
pub fn classify_transition(state: &State, input: &Input) -> TransitionClass {
    for guard in guards_in_priority_order() {
        if guard.matches(state, input) {
            return guard.class();
        }
    }
    // Unreachable: NoopGuard always matches.
    // Included for defensive completeness.
    TransitionClass::Noop
}

// ---------------------------------------------------------------------------
// Individual guard functions (convenience wrappers)
// ---------------------------------------------------------------------------

/// Returns `true` if the (state, input) pair triggers the Reject guard.
pub fn guard_reject(state: &State, input: &Input) -> bool {
    RejectGuard.matches(state, input)
}

/// Returns `true` if the (state, input) pair triggers the Init guard.
pub fn guard_init(state: &State, input: &Input) -> bool {
    InitGuard.matches(state, input)
}

/// Returns `true` if the (state, input) pair triggers the Error guard.
pub fn guard_error(state: &State, input: &Input) -> bool {
    ErrorGuard.matches(state, input)
}

/// Returns `true` if the (state, input) pair triggers the Batch guard.
pub fn guard_batch(state: &State, input: &Input) -> bool {
    BatchGuard.matches(state, input)
}

/// Returns `true` if the (state, input) pair triggers the Update guard.
pub fn guard_update(state: &State, input: &Input) -> bool {
    UpdateGuard.matches(state, input)
}

/// Returns `true` if the (state, input) pair triggers the Noop guard.
pub fn guard_noop(state: &State, input: &Input) -> bool {
    NoopGuard.matches(state, input)
}

// ---------------------------------------------------------------------------
// Internal helpers (mirror vsel-core logic for guard evaluation)
// ---------------------------------------------------------------------------

/// Check whether a precondition failure exists for the given (state, input).
///
/// A precondition failure occurs when the input is structurally valid but
/// the state does not satisfy the requirements for the requested operation.
fn is_precondition_failure(s: &State, sigma: &Input) -> bool {
    match sigma.payload.payload_type.as_str() {
        "transfer" => {
            // Transfer requires the sender account to exist.
            // Payload data must contain at least 32 bytes (sender account id).
            if sigma.payload.data.len() < 32 {
                return true;
            }
            let mut sender_id = [0u8; 32];
            sender_id.copy_from_slice(&sigma.payload.data[..32]);
            let sender = vsel_core::types::AccountId(sender_id);
            !s.canonical.accounts.contains_key(&sender)
        }
        _ => false,
    }
}

/// Check whether a payload type is a recognized operation type.
fn is_recognized_payload(payload_type: &str) -> bool {
    matches!(
        payload_type,
        "transfer" | "init" | "batch" | "deposit" | "withdraw" | "update"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::Authorization;
    use vsel_core::state::{
        derive, derive_economic, AccountData, CanonicalState, Environment, TraceMetadata,
    };
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

    fn build_state_at_seq(c: CanonicalState, seq: u64) -> State {
        let d = derive(&c);
        let env = Environment {
            timestamp: 1_000_000,
            block_height: 1,
            execution_domain: test_domain_tag(),
        };
        let econ = derive_economic(&c, &env);
        let commitment = if seq == 0 {
            Hash([0u8; 32])
        } else {
            Hash([0xABu8; 32])
        };
        let meta = TraceMetadata {
            sequence_index: seq,
            previous_commitment: commitment,
            epoch: 0,
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

    fn make_input(payload_type: &str, data: Vec<u8>) -> Input {
        Input {
            payload: Payload {
                payload_type: payload_type.to_string(),
                data,
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    fn make_invalid_input() -> Input {
        Input {
            payload: Payload {
                payload_type: String::new(), // empty = invalid
                data: vec![],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    // -- Guard priority ordering tests --

    #[test]
    fn test_guards_in_priority_order() {
        let guards = guards_in_priority_order();
        assert_eq!(guards.len(), 6);
        assert_eq!(guards[0].class(), TransitionClass::Reject);
        assert_eq!(guards[1].class(), TransitionClass::Init);
        assert_eq!(guards[2].class(), TransitionClass::Error);
        assert_eq!(guards[3].class(), TransitionClass::Batch);
        assert_eq!(guards[4].class(), TransitionClass::Update);
        assert_eq!(guards[5].class(), TransitionClass::Noop);
    }

    // -- classify_transition tests --

    #[test]
    fn test_classify_reject() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_invalid_input();
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Reject);
    }

    #[test]
    fn test_classify_init() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Init);
    }

    #[test]
    fn test_classify_error() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        // Transfer with non-existent sender
        let sigma = make_input("transfer", vec![1u8; 32]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Error);
    }

    #[test]
    fn test_classify_batch() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("batch", vec![0x01]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Batch);
    }

    #[test]
    fn test_classify_update() {
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        c.accounts.insert(
            sender_id,
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1000;
        let s = build_state_at_seq(c, 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Update);
    }

    #[test]
    fn test_classify_noop() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_operation", vec![0x01]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Noop);
    }

    // -- Consistency with vsel-core::transition::classify --

    #[test]
    fn test_consistency_with_core_classify() {
        use vsel_core::transition::classify;

        let test_cases: Vec<(State, Input)> = vec![
            // Reject
            (build_state_at_seq(minimal_canonical(), 1), make_invalid_input()),
            // Init
            (build_state_at_seq(minimal_canonical(), 0), make_input("init", vec![0xFF])),
            // Error
            (build_state_at_seq(minimal_canonical(), 1), make_input("transfer", vec![1u8; 32])),
            // Batch
            (build_state_at_seq(minimal_canonical(), 1), make_input("batch", vec![0x01])),
            // Noop
            (build_state_at_seq(minimal_canonical(), 1), make_input("unknown", vec![0x01])),
            // Update (deposit)
            (build_state_at_seq(minimal_canonical(), 1), make_input("deposit", vec![0x01; 48])),
        ];

        for (state, input) in &test_cases {
            let engine_class = classify_transition(state, input);
            let core_class = classify(state, input);
            assert_eq!(
                engine_class, core_class,
                "Engine guard classification must match core classify for payload_type='{}'",
                input.payload.payload_type
            );
        }
    }

    // -- Exhaustiveness test --

    #[test]
    fn test_exhaustiveness_every_pair_classified() {
        // Every (s, σ) pair must be classified into exactly one class.
        let states = vec![
            build_state_at_seq(minimal_canonical(), 0),
            build_state_at_seq(minimal_canonical(), 1),
            build_state_at_seq(minimal_canonical(), 100),
        ];

        let inputs = vec![
            make_invalid_input(),
            make_input("init", vec![0xFF]),
            make_input("transfer", vec![1u8; 32]),
            make_input("batch", vec![0x01]),
            make_input("deposit", vec![0x01; 48]),
            make_input("withdraw", vec![0x01; 48]),
            make_input("update", vec![0x01]),
            make_input("unknown_op", vec![0x01]),
        ];

        for state in &states {
            for input in &inputs {
                let class = classify_transition(state, input);
                assert!(
                    matches!(
                        class,
                        TransitionClass::Reject
                            | TransitionClass::Init
                            | TransitionClass::Error
                            | TransitionClass::Batch
                            | TransitionClass::Update
                            | TransitionClass::Noop
                    ),
                    "Every (s, σ) pair must classify to a valid TransitionClass"
                );
            }
        }
    }

    // -- Disjointness test --

    #[test]
    fn test_disjointness_at_most_one_class_after_priority() {
        // After priority resolution, exactly one guard fires per (s, σ).
        // We verify this by checking that classify_transition returns a
        // single deterministic result and that the result matches the
        // first matching guard in priority order.
        let states = vec![
            build_state_at_seq(minimal_canonical(), 0),
            build_state_at_seq(minimal_canonical(), 1),
        ];

        let inputs = vec![
            make_invalid_input(),
            make_input("init", vec![0xFF]),
            make_input("transfer", vec![1u8; 32]),
            make_input("batch", vec![0x01]),
            make_input("deposit", vec![0x01; 48]),
            make_input("unknown_op", vec![0x01]),
        ];

        for state in &states {
            for input in &inputs {
                let guards = guards_in_priority_order();
                let mut first_match: Option<TransitionClass> = None;

                for guard in &guards {
                    if guard.matches(state, input) {
                        if first_match.is_none() {
                            first_match = Some(guard.class());
                        }
                        // Don't break — we want to verify the first match
                        // is what classify_transition returns.
                    }
                }

                let classified = classify_transition(state, input);
                assert_eq!(
                    first_match,
                    Some(classified),
                    "classify_transition must return the first matching guard's class"
                );
            }
        }
    }

    // -- Individual guard function tests --

    #[test]
    fn test_guard_reject_fn() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        assert!(guard_reject(&s, &make_invalid_input()));
        assert!(!guard_reject(&s, &make_input("transfer", vec![0x01])));
    }

    #[test]
    fn test_guard_init_fn() {
        let s0 = build_state_at_seq(minimal_canonical(), 0);
        let s1 = build_state_at_seq(minimal_canonical(), 1);
        let init_input = make_input("init", vec![0xFF]);
        assert!(guard_init(&s0, &init_input));
        assert!(!guard_init(&s1, &init_input));
    }

    #[test]
    fn test_guard_error_fn() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        assert!(guard_error(&s, &sigma));
    }

    #[test]
    fn test_guard_batch_fn() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        assert!(guard_batch(&s, &make_input("batch", vec![0x01])));
        assert!(!guard_batch(&s, &make_input("transfer", vec![0x01])));
    }

    #[test]
    fn test_guard_update_fn() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        assert!(guard_update(&s, &make_input("deposit", vec![0x01; 48])));
        assert!(!guard_update(&s, &make_input("unknown", vec![0x01])));
    }

    #[test]
    fn test_guard_noop_fn() {
        // NoopGuard always matches
        let s = build_state_at_seq(minimal_canonical(), 1);
        assert!(guard_noop(&s, &make_input("anything", vec![0x01])));
        assert!(guard_noop(&s, &make_invalid_input()));
    }

    // -- Priority resolution edge cases --

    #[test]
    fn test_reject_takes_priority_over_init() {
        // Invalid input at genesis: Reject wins over Init
        let s = build_state_at_seq(minimal_canonical(), 0);
        let mut sigma = make_input("init", vec![0xFF]);
        sigma.payload.data = vec![]; // make it invalid
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Reject);
    }

    #[test]
    fn test_init_takes_priority_over_update() {
        // "init" at genesis: Init wins over Update (since "init" is recognized)
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Init);
    }

    #[test]
    fn test_error_takes_priority_over_update() {
        // Transfer with non-existent sender: Error wins over Update
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("transfer", vec![1u8; 32]);
        assert_eq!(classify_transition(&s, &sigma), TransitionClass::Error);
    }
}
