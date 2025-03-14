//! Observable functions for the VSEL protocol.
//!
//! Derived from: FORMAL_SPECIFICATION.md §3 (DEF-4), STATE_MACHINE.md §5,
//! SEMANTIC_MAPPING.md §5.
//!
//! Observables `Obs: S × Σ × S → O` are deterministic functions derivable
//! entirely from (s, σ, s') with no hidden side effects (DEF-4).
//!
//! The `obs` function:
//! 1. Classifies the transition via `classify(s, σ)`.
//! 2. Maps the class to a `TransitionStatus`.
//! 3. Derives output events from the state diff.
//! 4. Computes a deterministic gas cost.
//! 5. Returns the `Observable`.

use crate::input::Input;
use crate::state::State;
use crate::transition::{classify, TransitionClass};
use crate::types::OutputEvent;

// ---------------------------------------------------------------------------
// TransitionStatus — outcome classification
// ---------------------------------------------------------------------------

/// Status of a transition from the observer's perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionStatus {
    /// The transition was applied successfully.
    Success,
    /// The transition was rejected (invalid input or no-op).
    Rejected,
    /// The transition encountered an explicit error condition.
    Error,
}

// ---------------------------------------------------------------------------
// Observable — externally visible output of a transition
// ---------------------------------------------------------------------------

/// Observable — externally visible output of a transition (DEF-4).
///
/// Deterministic and derivable entirely from `(s, σ, s')`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observable {
    /// The transition class that was applied.
    pub transition_class: TransitionClass,
    /// Output events derived from the state diff.
    pub outputs: Vec<OutputEvent>,
    /// Deterministic measure of computation cost.
    pub gas_used: u64,
    /// Outcome status of the transition.
    pub status: TransitionStatus,
}

// ---------------------------------------------------------------------------
// obs — deterministic observable function (DEF-4)
// ---------------------------------------------------------------------------

/// Base gas cost for any transition.
const BASE_GAS: u64 = 21_000;

/// Per-byte gas cost for payload data.
const GAS_PER_BYTE: u64 = 16;

/// Per-account-change gas cost.
const GAS_PER_ACCOUNT_CHANGE: u64 = 5_000;

/// Compute the observable for a transition `(s, σ, s')`.
///
/// This function is:
/// - **Deterministic**: identical `(s, σ, s')` always produce identical output.
/// - **Derivable from state**: no hidden side effects (DEF-4).
///
/// Steps:
/// 1. Classify the transition using `classify(s, σ)`.
/// 2. Map the class to a `TransitionStatus`.
/// 3. Derive output events from the state diff `(s, s')`.
/// 4. Compute gas deterministically from `(σ, s, s')`.
/// 5. Return the `Observable`.
pub fn obs(s: &State, sigma: &Input, s_prime: &State) -> Observable {
    let transition_class = classify(s, sigma);
    let status = status_from_class(transition_class);
    let outputs = derive_outputs(s, s_prime, transition_class);
    let gas_used = compute_gas(sigma, s, s_prime);

    Observable {
        transition_class,
        outputs,
        gas_used,
        status,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map a `TransitionClass` to a `TransitionStatus`.
///
/// - Reject → Rejected
/// - Error  → Error
/// - Noop   → Rejected (no-op is a soft rejection)
/// - Init, Batch, Update → Success
fn status_from_class(class: TransitionClass) -> TransitionStatus {
    match class {
        TransitionClass::Reject => TransitionStatus::Rejected,
        TransitionClass::Error => TransitionStatus::Error,
        TransitionClass::Noop => TransitionStatus::Rejected,
        TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update => {
            TransitionStatus::Success
        }
    }
}

/// Derive output events from the state diff `(s, s')`.
///
/// Deterministic: iterates accounts in BTreeMap order and emits events
/// for balance changes, new accounts, and system parameter changes.
fn derive_outputs(s: &State, s_prime: &State, class: TransitionClass) -> Vec<OutputEvent> {
    let mut outputs = Vec::new();

    // Only successful transitions produce meaningful output events.
    if !matches!(
        class,
        TransitionClass::Init | TransitionClass::Batch | TransitionClass::Update
    ) {
        return outputs;
    }

    // Emit events for account balance changes (deterministic BTreeMap order).
    for (id, new_account) in &s_prime.canonical.accounts {
        match s.canonical.accounts.get(id) {
            Some(old_account) if old_account.balance != new_account.balance => {
                // Balance changed — emit a balance_change event.
                let mut data = Vec::with_capacity(48);
                data.extend_from_slice(&id.0);
                data.extend_from_slice(&new_account.balance.to_le_bytes());
                outputs.push(OutputEvent {
                    event_type: "balance_change".to_string(),
                    data,
                });
            }
            None => {
                // New account created.
                let mut data = Vec::with_capacity(48);
                data.extend_from_slice(&id.0);
                data.extend_from_slice(&new_account.balance.to_le_bytes());
                outputs.push(OutputEvent {
                    event_type: "account_created".to_string(),
                    data,
                });
            }
            _ => {} // No change — no event.
        }
    }

    // Emit events for system parameter changes (deterministic BTreeMap order).
    for (key, new_val) in &s_prime.canonical.system_data.parameters {
        let changed = match s.canonical.system_data.parameters.get(key) {
            Some(old_val) => old_val != new_val,
            None => true,
        };
        if changed {
            let mut data = Vec::new();
            data.extend_from_slice(key.as_bytes());
            data.push(0x00); // separator
            data.extend_from_slice(new_val);
            outputs.push(OutputEvent {
                event_type: "param_change".to_string(),
                data,
            });
        }
    }

    outputs
}

/// Compute gas deterministically from `(σ, s, s')`.
///
/// Gas = BASE_GAS + (payload bytes × GAS_PER_BYTE) + (account changes × GAS_PER_ACCOUNT_CHANGE)
///
/// This is a deterministic measure of computation cost derivable entirely
/// from the input and state diff.
fn compute_gas(sigma: &Input, s: &State, s_prime: &State) -> u64 {
    let payload_gas = (sigma.payload.data.len() as u64).saturating_mul(GAS_PER_BYTE);

    // Count account changes: accounts whose data differs between s and s'.
    let mut account_changes: u64 = 0;
    for (id, new_account) in &s_prime.canonical.accounts {
        match s.canonical.accounts.get(id) {
            Some(old_account) if old_account != new_account => {
                account_changes += 1;
            }
            None => {
                account_changes += 1; // new account
            }
            _ => {}
        }
    }

    BASE_GAS
        .saturating_add(payload_gas)
        .saturating_add(account_changes.saturating_mul(GAS_PER_ACCOUNT_CHANGE))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Authorization;
    use crate::state::*;
    use crate::types::*;
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
                payload_type: String::new(),
                data: vec![],
            },
            auth: valid_auth(),
            aux: AuxiliaryData { data: vec![] },
        }
    }

    // -- status_from_class tests --

    #[test]
    fn test_status_reject_is_rejected() {
        assert_eq!(
            status_from_class(TransitionClass::Reject),
            TransitionStatus::Rejected
        );
    }

    #[test]
    fn test_status_error_is_error() {
        assert_eq!(
            status_from_class(TransitionClass::Error),
            TransitionStatus::Error
        );
    }

    #[test]
    fn test_status_noop_is_rejected() {
        assert_eq!(
            status_from_class(TransitionClass::Noop),
            TransitionStatus::Rejected
        );
    }

    #[test]
    fn test_status_init_is_success() {
        assert_eq!(
            status_from_class(TransitionClass::Init),
            TransitionStatus::Success
        );
    }

    #[test]
    fn test_status_batch_is_success() {
        assert_eq!(
            status_from_class(TransitionClass::Batch),
            TransitionStatus::Success
        );
    }

    #[test]
    fn test_status_update_is_success() {
        assert_eq!(
            status_from_class(TransitionClass::Update),
            TransitionStatus::Success
        );
    }

    // -- obs determinism (DEF-4) --

    #[test]
    fn test_obs_deterministic() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = crate::transition::apply(&s, &sigma);

        let o1 = obs(&s, &sigma, &s_prime);
        let o2 = obs(&s, &sigma, &s_prime);
        assert_eq!(o1, o2, "obs must be deterministic (DEF-4)");
    }

    // -- obs for reject --

    #[test]
    fn test_obs_reject() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_invalid_input();
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Reject);
        assert_eq!(o.status, TransitionStatus::Rejected);
        assert!(o.outputs.is_empty(), "reject should produce no output events");
    }

    // -- obs for init --

    #[test]
    fn test_obs_init() {
        let s = build_state_at_seq(minimal_canonical(), 0);
        let sigma = make_input("init", vec![0xFF]);
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Init);
        assert_eq!(o.status, TransitionStatus::Success);
        // Init sets "initialized" param → should produce a param_change event.
        assert!(
            o.outputs.iter().any(|e| e.event_type == "param_change"),
            "init should produce a param_change output event"
        );
    }

    // -- obs for error --

    #[test]
    fn test_obs_error() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        // Transfer with non-existent sender → precondition failure → Error
        let sender = [1u8; 32];
        let sigma = make_input("transfer", sender.to_vec());
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Error);
        assert_eq!(o.status, TransitionStatus::Error);
        assert!(o.outputs.is_empty(), "error should produce no output events");
    }

    // -- obs for noop --

    #[test]
    fn test_obs_noop() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Noop);
        assert_eq!(o.status, TransitionStatus::Rejected);
        assert!(o.outputs.is_empty(), "noop should produce no output events");
    }

    // -- obs for update (transfer) --

    #[test]
    fn test_obs_update_transfer() {
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
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Update);
        assert_eq!(o.status, TransitionStatus::Success);
        // Should have balance_change events for sender and receiver.
        let balance_changes: Vec<_> = o
            .outputs
            .iter()
            .filter(|e| e.event_type == "balance_change")
            .collect();
        assert_eq!(
            balance_changes.len(),
            2,
            "transfer should produce 2 balance_change events"
        );
    }

    // -- gas computation --

    #[test]
    fn test_gas_includes_base() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let sigma = make_input("unknown_op", vec![0x01]);
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert!(
            o.gas_used >= BASE_GAS,
            "gas should include at least the base cost"
        );
    }

    #[test]
    fn test_gas_scales_with_payload() {
        let s = build_state_at_seq(minimal_canonical(), 1);
        let small = make_input("unknown_op", vec![0x01]);
        let big = make_input("unknown_op", vec![0x01; 100]);
        let s_prime_small = crate::transition::apply(&s, &small);
        let s_prime_big = crate::transition::apply(&s, &big);

        let o_small = obs(&s, &small, &s_prime_small);
        let o_big = obs(&s, &big, &s_prime_big);
        assert!(
            o_big.gas_used > o_small.gas_used,
            "larger payload should cost more gas"
        );
    }

    // -- obs for deposit (new account creation) --

    #[test]
    fn test_obs_deposit_creates_account() {
        let c = minimal_canonical();
        let s = build_state_at_seq(c, 1);

        let mut data = vec![];
        data.extend_from_slice(&[1u8; 32]); // account
        data.extend_from_slice(&500u128.to_le_bytes()); // amount
        let sigma = make_input("deposit", data);
        let s_prime = crate::transition::apply(&s, &sigma);

        let o = obs(&s, &sigma, &s_prime);
        assert_eq!(o.transition_class, TransitionClass::Update);
        assert_eq!(o.status, TransitionStatus::Success);
        assert!(
            o.outputs.iter().any(|e| e.event_type == "account_created"),
            "deposit to new account should produce account_created event"
        );
    }
}
