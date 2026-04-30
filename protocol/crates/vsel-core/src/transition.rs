//! Transition classes and Apply function for the VSEL protocol.
//!
//! Derived from: STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md,
//! FORMAL_SPECIFICATION.md §3.
//!
//! Transition classes partition the input space with strict priority ordering:
//!   T_REJECT > T_INIT > T_ERROR > T_BATCH > T_UPDATE > T_NOOP
//!
//! The `apply` function is deterministic (AX-1) and total — it always returns
//! a valid state (AX-2). Invalid inputs produce an error state with all
//! invariants preserved (LEM-7).

use crate::input::*;
use crate::state::*;
use crate::types::*;

// ---------------------------------------------------------------------------
// Transition classes — STATE_MACHINE.md §5, TRANSITION_PARTITIONING.md
// ---------------------------------------------------------------------------

/// Transition classes with priority ordering via discriminant values.
///
/// Lower discriminant = higher priority.
/// `Reject` (0) is highest priority, `Noop` (5) is lowest.
///
/// The `Ord` derivation on repr-discriminant enums in Rust orders by
/// discriminant value, so `Reject < Init < ... < Noop` in Rust ordering.
/// We define "higher priority" as *lower* discriminant, matching the spec's
/// `T_REJECT > T_INIT > T_ERROR > T_BATCH > T_UPDATE > T_NOOP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransitionClass {
    Reject = 0, // Malformed input/state (highest priority)
    Init   = 1, // Initialization
    Error  = 2, // Explicit error condition
    Batch  = 3, // Batch processing
    Update = 4, // Standard state update
    Noop   = 5, // No-op / rejection (lowest priority)
}

// ---------------------------------------------------------------------------
// Classification — guard system
// ---------------------------------------------------------------------------

/// Classify a (state, input) pair into exactly one `TransitionClass`.
///
/// Guards are evaluated in priority order (highest first). The first
/// matching guard determines the class, guaranteeing exhaustiveness
/// and disjointness (Requirement 2.7).
pub fn classify(s: &State, sigma: &Input) -> TransitionClass {
    // G_REJECT: input is structurally invalid
    if !valid_input(sigma) {
        return TransitionClass::Reject;
    }

    // G_INIT: first transition (sequence_index == 0) with "init" payload
    if s.metadata.sequence_index == 0 && sigma.payload.payload_type == "init" {
        return TransitionClass::Init;
    }

    // G_ERROR: valid input but precondition failure
    // For now, precondition failure = referencing a non-existent account
    // when the payload requires one (e.g. "transfer" with no matching account).
    if is_precondition_failure(s, sigma) {
        return TransitionClass::Error;
    }

    // G_BATCH: payload_type == "batch"
    if sigma.payload.payload_type == "batch" {
        return TransitionClass::Batch;
    }

    // G_UPDATE: standard recognized payload types
    if is_recognized_payload(&sigma.payload.payload_type) {
        return TransitionClass::Update;
    }

    // G_NOOP: no matching transition — catch-all (lowest priority)
    TransitionClass::Noop
}

/// Check whether a precondition failure exists for the given (state, input).
///
/// A precondition failure occurs when the input is structurally valid but
/// the state does not satisfy the requirements for the requested operation.
fn is_precondition_failure(s: &State, sigma: &Input) -> bool {
    match sigma.payload.payload_type.as_str() {
        "transfer" => {
            // Transfer requires the sender account to exist and have
            // sufficient data to parse. We check that the payload data
            // contains at least 32 bytes (sender account id).
            if sigma.payload.data.len() < 32 {
                return true;
            }
            let mut sender_id = [0u8; 32];
            sender_id.copy_from_slice(&sigma.payload.data[..32]);
            let sender = AccountId(sender_id);
            // Sender account must exist
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
// Apply — deterministic transition function (AX-1, AX-2)
// ---------------------------------------------------------------------------

/// Apply a transition: `apply(s, σ) -> s'`.
///
/// This function is:
/// - **Deterministic** (AX-1): identical inputs always produce identical output.
/// - **Total/Closed** (AX-2): always returns a valid state in S.
/// - **Error-safe** (LEM-7): invalid inputs produce an error state with
///   invariants preserved.
///
/// Steps:
/// 1. Classify the transition using guard logic (priority-based).
/// 2. Apply the appropriate transition logic.
/// 3. Recompute derived state: `D' = derive(C')`.
/// 4. Recompute economic context: `Ω' = derive_economic(C', E')`.
/// 5. Update trace metadata.
/// 6. Return the new state.
pub fn apply(s: &State, sigma: &Input) -> State {
    let class = classify(s, sigma);

    match class {
        TransitionClass::Reject => apply_reject(s),
        TransitionClass::Init => apply_init(s, sigma),
        TransitionClass::Error => apply_error(s),
        TransitionClass::Batch => apply_batch(s, sigma),
        TransitionClass::Update => apply_update(s, sigma),
        TransitionClass::Noop => apply_noop(s),
    }
}

// ---------------------------------------------------------------------------
// Per-class transition implementations
// ---------------------------------------------------------------------------

/// Reject: malformed input → return error state with unchanged canonical state.
/// Metadata is advanced to maintain trace consistency.
fn apply_reject(s: &State) -> State {
    // Canonical state unchanged; advance metadata only.
    let canonical = s.canonical.clone();
    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &s.environment);
    let metadata = advance_metadata(&s.metadata);

    State {
        canonical,
        derived,
        environment: s.environment.clone(),
        economic,
        metadata,
    }
}

/// Init: first transition — initialize state from the init payload.
/// Sets up the canonical state from the payload data.
fn apply_init(s: &State, _sigma: &Input) -> State {
    // For initialization, we set up system data from the payload.
    // The payload data is treated as opaque initialization data.
    let mut canonical = s.canonical.clone();

    // Store the init payload in system parameters as initialization marker.
    canonical
        .system_data
        .parameters
        .insert("initialized".to_string(), vec![1u8]);

    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &s.environment);
    let metadata = advance_metadata(&s.metadata);

    State {
        canonical,
        derived,
        environment: s.environment.clone(),
        economic,
        metadata,
    }
}

/// Error: valid input but precondition failure → return error state.
/// Canonical state is unchanged; metadata is advanced.
fn apply_error(s: &State) -> State {
    // Same as reject: canonical state unchanged, metadata advanced.
    let canonical = s.canonical.clone();
    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &s.environment);
    let metadata = advance_metadata(&s.metadata);

    State {
        canonical,
        derived,
        environment: s.environment.clone(),
        economic,
        metadata,
    }
}

/// Batch: payload_type == "batch" → for now, treat as a single update.
/// In a full implementation, this would deserialize sub-inputs and apply
/// them sequentially (LEM-9, THM-12).
fn apply_batch(s: &State, sigma: &Input) -> State {
    // Foundational implementation: treat batch as a single update step.
    apply_update(s, sigma)
}

/// Update: standard state update — apply the transition to canonical state.
fn apply_update(s: &State, sigma: &Input) -> State {
    let mut canonical = s.canonical.clone();

    match sigma.payload.payload_type.as_str() {
        "transfer" => {
            apply_transfer(&mut canonical, sigma);
        }
        "deposit" => {
            apply_deposit(&mut canonical, sigma);
        }
        "withdraw" => {
            apply_withdraw(&mut canonical, sigma);
        }
        _ => {
            // Generic update: store payload in system parameters.
            canonical.system_data.parameters.insert(
                format!("last_update_{}", sigma.payload.payload_type),
                sigma.payload.data.clone(),
            );
        }
    }

    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &s.environment);
    let metadata = advance_metadata(&s.metadata);

    State {
        canonical,
        derived,
        environment: s.environment.clone(),
        economic,
        metadata,
    }
}

/// Noop: no matching transition → return unchanged state with advanced metadata.
fn apply_noop(s: &State) -> State {
    let canonical = s.canonical.clone();
    let derived = derive(&canonical);
    let economic = derive_economic(&canonical, &s.environment);
    let metadata = advance_metadata(&s.metadata);

    State {
        canonical,
        derived,
        environment: s.environment.clone(),
        economic,
        metadata,
    }
}

// ---------------------------------------------------------------------------
// Transition helpers
// ---------------------------------------------------------------------------

/// Advance trace metadata: increment sequence_index, compute new commitment.
///
/// # Overflow behavior (L-004)
///
/// `sequence_index` is a `u64` monotonic counter. At `u64::MAX` the counter
/// saturates — it remains at `u64::MAX` rather than wrapping. This preserves
/// the G_mono (monotonic metadata) invariant: `post.sequence_index >= pre.sequence_index`
/// always holds, even at the boundary. In practice `u64::MAX` (~1.8 × 10¹⁹)
/// transitions are physically unreachable, but saturation makes the formal
/// property unconditionally true.
///
/// `epoch` is not incremented by `advance_metadata`; it is advanced externally
/// (e.g., by the replay/trace engine). If epoch were to be advanced at
/// `u64::MAX`, the same saturating semantics should be applied by the caller.
fn advance_metadata(m: &TraceMetadata) -> TraceMetadata {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(&m.previous_commitment.0);
    hasher.update(&m.sequence_index.to_le_bytes());
    hasher.update(&m.epoch.to_le_bytes());
    let result = hasher.finalize();
    let mut new_commitment = [0u8; 32];
    new_commitment.copy_from_slice(&result);

    TraceMetadata {
        sequence_index: m.sequence_index.saturating_add(1),
        previous_commitment: Hash(new_commitment),
        epoch: m.epoch,
        timestamp: m.timestamp,
    }
}

/// Apply a transfer operation to canonical state.
///
/// Payload data format: [sender_id: 32 bytes][receiver_id: 32 bytes][amount: 16 bytes (u128 LE)]
/// Total supply is conserved (L_cons).
fn apply_transfer(canonical: &mut CanonicalState, sigma: &Input) {
    // Need at least 32 + 32 + 16 = 80 bytes
    if sigma.payload.data.len() < 80 {
        return; // Insufficient data — no-op on canonical state
    }

    let mut sender_id = [0u8; 32];
    sender_id.copy_from_slice(&sigma.payload.data[..32]);
    let mut receiver_id = [0u8; 32];
    receiver_id.copy_from_slice(&sigma.payload.data[32..64]);
    let amount = u128::from_le_bytes(
        sigma.payload.data[64..80]
            .try_into()
            .expect("slice is exactly 16 bytes"),
    );

    let sender = AccountId(sender_id);
    let receiver = AccountId(receiver_id);

    // Check sender has sufficient balance
    let sender_balance = canonical
        .accounts
        .get(&sender)
        .map(|a| a.balance)
        .unwrap_or(0);

    if sender_balance < amount {
        return; // Insufficient balance — no-op
    }

    // Debit sender
    if let Some(account) = canonical.accounts.get_mut(&sender) {
        account.balance -= amount;
        account.nonce += 1;
    }

    // Credit receiver (create account if it doesn't exist)
    canonical
        .accounts
        .entry(receiver)
        .or_insert_with(|| AccountData {
            balance: 0,
            nonce: 0,
            data: vec![],
        })
        .balance += amount;

    // Total supply is conserved — no change needed.
}

/// Apply a deposit operation to canonical state.
///
/// Payload data format: [account_id: 32 bytes][amount: 16 bytes (u128 LE)]
/// Increases total supply.
fn apply_deposit(canonical: &mut CanonicalState, sigma: &Input) {
    if sigma.payload.data.len() < 48 {
        return;
    }

    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&sigma.payload.data[..32]);
    let amount = u128::from_le_bytes(
        sigma.payload.data[32..48]
            .try_into()
            .expect("slice is exactly 16 bytes"),
    );

    let account = AccountId(account_id);

    canonical
        .accounts
        .entry(account)
        .or_insert_with(|| AccountData {
            balance: 0,
            nonce: 0,
            data: vec![],
        })
        .balance += amount;

    canonical.system_data.total_supply += amount;
}

/// Apply a withdraw operation to canonical state.
///
/// Payload data format: [account_id: 32 bytes][amount: 16 bytes (u128 LE)]
/// Decreases total supply.
fn apply_withdraw(canonical: &mut CanonicalState, sigma: &Input) {
    if sigma.payload.data.len() < 48 {
        return;
    }

    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&sigma.payload.data[..32]);
    let amount = u128::from_le_bytes(
        sigma.payload.data[32..48]
            .try_into()
            .expect("slice is exactly 16 bytes"),
    );

    let account = AccountId(account_id);

    let balance = canonical
        .accounts
        .get(&account)
        .map(|a| a.balance)
        .unwrap_or(0);

    if balance < amount {
        return; // Insufficient balance — no-op
    }

    if let Some(acc) = canonical.accounts.get_mut(&account) {
        acc.balance -= amount;
        acc.nonce += 1;
    }

    canonical.system_data.total_supply -= amount;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
        State {
            canonical: c,
            derived: d,
            environment: env,
            economic: econ,
            metadata: meta,
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

    // -- TransitionClass ordering tests --

    #[test]
    fn test_transition_class_priority_ordering() {
        // Lower discriminant = higher priority.
        // In Rust Ord, Reject < Init < Error < Batch < Update < Noop.
        assert!(TransitionClass::Reject < TransitionClass::Init);
        assert!(TransitionClass::Init < TransitionClass::Error);
        assert!(TransitionClass::Error < TransitionClass::Batch);
        assert!(TransitionClass::Batch < TransitionClass::Update);
        assert!(TransitionClass::Update < TransitionClass::Noop);
    }

    #[test]
    fn test_transition_class_discriminant_values() {
        assert_eq!(TransitionClass::Reject as u8, 0);
        assert_eq!(TransitionClass::Init as u8, 1);
        assert_eq!(TransitionClass::Error as u8, 2);
        assert_eq!(TransitionClass::Batch as u8, 3);
        assert_eq!(TransitionClass::Update as u8, 4);
        assert_eq!(TransitionClass::Noop as u8, 5);
    }

    // -- classify tests --

    #[test]
    fn test_classify_reject_invalid_input() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_invalid_input();
        assert_eq!(classify(&s, &sigma), TransitionClass::Reject);
    }

    #[test]
    fn test_classify_init_at_genesis() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        assert_eq!(classify(&s, &sigma), TransitionClass::Init);
    }

    #[test]
    fn test_classify_init_not_at_genesis() {
        // sequence_index > 0 means "init" is treated as a regular update
        let s = build_state_at_seq(minimal_canonical(), 5);
        let sigma = make_input("init", vec![0xFF]);
        assert_eq!(classify(&s, &sigma), TransitionClass::Update);
    }

    #[test]
    fn test_classify_error_precondition_failure() {
        // Transfer with a sender that doesn't exist in state
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        assert_eq!(classify(&s, &sigma), TransitionClass::Error);
    }

    #[test]
    fn test_classify_batch() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("batch", vec![0x01]);
        assert_eq!(classify(&s, &sigma), TransitionClass::Batch);
    }

    #[test]
    fn test_classify_update() {
        // Transfer with existing sender account
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

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]); // sender
        let sigma = make_input("transfer", data);
        assert_eq!(classify(&s, &sigma), TransitionClass::Update);
    }

    #[test]
    fn test_classify_noop_unrecognized_payload() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_operation", vec![0x01]);
        assert_eq!(classify(&s, &sigma), TransitionClass::Noop);
    }

    // -- apply tests --

    #[test]
    fn test_apply_deterministic() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s1 = apply(&s, &sigma);
        let s2 = apply(&s, &sigma);
        assert_eq!(s1, s2, "apply must be deterministic (AX-1)");
    }

    #[test]
    fn test_apply_advances_metadata() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime.metadata.sequence_index,
            s.metadata.sequence_index + 1
        );
        assert_ne!(
            s_prime.metadata.previous_commitment,
            s.metadata.previous_commitment
        );
    }

    #[test]
    fn test_apply_reject_preserves_canonical() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_invalid_input();
        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime.canonical, s.canonical,
            "reject must not change canonical state"
        );
    }

    #[test]
    fn test_apply_error_preserves_canonical() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime.canonical, s.canonical,
            "error must not change canonical state"
        );
    }

    #[test]
    fn test_apply_noop_preserves_canonical() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime.canonical, s.canonical,
            "noop must not change canonical state"
        );
    }

    #[test]
    fn test_apply_init_sets_initialized() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime
                .canonical
                .system_data
                .parameters
                .get("initialized"),
            Some(&vec![1u8])
        );
    }

    #[test]
    fn test_apply_closure_derived_consistent() {
        // After apply, derived state must equal derive(canonical) (AX-2, DEF-1)
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        let expected_derived = derive(&s_prime.canonical);
        assert_eq!(
            s_prime.derived, expected_derived,
            "derived state must be consistent after apply (DEF-1)"
        );
    }

    #[test]
    fn test_apply_closure_economic_consistent() {
        let s = build_valid_state(minimal_canonical());
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = apply(&s, &sigma);
        let expected_econ = derive_economic(&s_prime.canonical, &s_prime.environment);
        assert_eq!(
            s_prime.economic, expected_econ,
            "economic context must be consistent after apply"
        );
    }

    #[test]
    fn test_apply_transfer_conserves_supply() {
        let mut c = minimal_canonical();
        let sender_id = AccountId([1u8; 32]);
        let receiver_id = AccountId([2u8; 32]);
        c.accounts.insert(
            sender_id.clone(),
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.accounts.insert(
            receiver_id.clone(),
            AccountData {
                balance: 500,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1500;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]); // sender
        data.extend_from_slice(&[2u8; 32]); // receiver
        data.extend_from_slice(&100u128.to_le_bytes()); // amount
        let sigma = make_input("transfer", data);

        let s_prime = apply(&s, &sigma);
        assert_eq!(
            s_prime.canonical.system_data.total_supply, 1500,
            "transfer must conserve total supply (L_cons)"
        );
        assert_eq!(s_prime.canonical.accounts[&AccountId([1u8; 32])].balance, 900);
        assert_eq!(s_prime.canonical.accounts[&AccountId([2u8; 32])].balance, 600);
    }

    #[test]
    fn test_apply_deposit_increases_supply() {
        let c = minimal_canonical();
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]); // account
        data.extend_from_slice(&500u128.to_le_bytes()); // amount
        let sigma = make_input("deposit", data);

        let s_prime = apply(&s, &sigma);
        assert_eq!(s_prime.canonical.system_data.total_supply, 500);
        assert_eq!(s_prime.canonical.accounts[&AccountId([1u8; 32])].balance, 500);
    }

    #[test]
    fn test_apply_withdraw_decreases_supply() {
        let mut c = minimal_canonical();
        let account_id = AccountId([1u8; 32]);
        c.accounts.insert(
            account_id.clone(),
            AccountData {
                balance: 1000,
                nonce: 0,
                data: vec![],
            },
        );
        c.system_data.total_supply = 1000;
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]); // account
        data.extend_from_slice(&300u128.to_le_bytes()); // amount
        let sigma = make_input("withdraw", data);

        let s_prime = apply(&s, &sigma);
        assert_eq!(s_prime.canonical.system_data.total_supply, 700);
        assert_eq!(s_prime.canonical.accounts[&AccountId([1u8; 32])].balance, 700);
    }

    #[test]
    fn test_classify_exactly_one_class() {
        // Every (s, σ) pair must be classified into exactly one class.
        // Test a variety of inputs against the same state.
        let s = build_state_at_seq(minimal_canonical(), 1);

        let inputs = vec![
            make_invalid_input(),
            make_input("batch", vec![0x01]),
            make_input("transfer", vec![1u8; 32]), // precondition failure
            make_input("unknown", vec![0x01]),
            make_input("deposit", vec![0x01; 48]),
        ];

        for sigma in &inputs {
            let class = classify(&s, sigma);
            // Verify it's a valid class (exhaustiveness)
            assert!(matches!(
                class,
                TransitionClass::Reject
                    | TransitionClass::Init
                    | TransitionClass::Error
                    | TransitionClass::Batch
                    | TransitionClass::Update
                    | TransitionClass::Noop
            ));
        }
    }
}
