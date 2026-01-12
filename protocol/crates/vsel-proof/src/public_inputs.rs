//! Public input definition for the VSEL proof system.
//!
//! Derived from: PROOF_LAYER.md §4, Requirements 7.3, 7.7.
//!
//! Public inputs Pub = (root_init, root_final, observables, domain, version)
//! define the externally visible statement that a proof attests to.
//!
//! Observable binding (PROOF-2): all observables Obs(τ) are included in
//! or derivable from public inputs — no hidden outputs.

use vsel_core::observable::Observable;
use vsel_core::state::commit;
use vsel_core::types::{DomainTag, Hash, ProtocolVersion};
use vsel_trace::engine::Trace;

// ---------------------------------------------------------------------------
// PublicInputs — externally visible proof statement
// ---------------------------------------------------------------------------

/// Public inputs for the VSEL proof system.
///
/// PROOF_LAYER.md §4: Pub = (root_init, root_final, observables, domain, version).
///
/// These are the values that the verifier checks against — they define
/// what the proof is *about*. The prover commits to these values, and
/// the verifier confirms the proof is consistent with them.
///
/// Requirements 7.3 (observable binding), 7.7 (well-defined public inputs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// Commitment of the initial canonical state: Commit(C₀).
    pub root_init: Hash,
    /// Commitment of the final canonical state: Commit(Cₙ).
    pub root_final: Hash,
    /// All observables from the execution trace, in order.
    pub observables: Vec<Observable>,
    /// Domain separation tag for this proof context.
    pub domain: DomainTag,
    /// Protocol version under which the execution was performed.
    pub version: ProtocolVersion,
}

impl PublicInputs {
    /// Extract public inputs from an execution trace.
    ///
    /// Computes initial and final state commitments, collects all
    /// observables from trace entries, and captures the domain and
    /// protocol version from the trace's initial state.
    ///
    /// Requirements 7.3, 7.7.
    pub fn from_trace(trace: &Trace) -> Self {
        let root_init = commit(&trace.initial_state.canonical);

        // Final state commitment: if the trace has entries, use the last
        // entry's post_state_commitment. Otherwise, the final state is
        // the initial state.
        let root_final = if let Some(last_entry) = trace.entries.last() {
            last_entry.post_state_commitment.clone()
        } else {
            root_init.clone()
        };

        let observables: Vec<Observable> = trace
            .entries
            .iter()
            .map(|entry| entry.observable.clone())
            .collect();

        let domain = trace.initial_state.environment.execution_domain.clone();
        let version = trace
            .initial_state
            .canonical
            .system_data
            .protocol_version
            .clone();

        PublicInputs {
            root_init,
            root_final,
            observables,
            domain,
            version,
        }
    }

    /// Verify observable binding (PROOF-2): all provided observables are
    /// included in the public inputs.
    ///
    /// Returns true if every observable in `observables` is present in
    /// `self.observables`. This enforces that no observable output is
    /// hidden from the verifier.
    ///
    /// Requirement 7.3.
    pub fn verify_observable_binding(&self, observables: &[Observable]) -> bool {
        // Every observable must be present in the public inputs.
        // We check that each provided observable appears in our list
        // at the corresponding position (order matters for trace binding).
        if observables.len() != self.observables.len() {
            return false;
        }

        observables
            .iter()
            .zip(self.observables.iter())
            .all(|(provided, expected)| provided == expected)
    }

    /// Verify that these public inputs match a given trace.
    ///
    /// Checks:
    /// 1. root_init matches Commit(trace.initial_state.canonical)
    /// 2. root_final matches the last entry's post_state_commitment
    /// 3. All observables match the trace entries in order
    /// 4. Domain matches the trace's execution domain
    /// 5. Version matches the trace's protocol version
    ///
    /// Requirements 7.3, 7.7.
    pub fn matches_trace(&self, trace: &Trace) -> bool {
        // Check 1: initial state commitment
        let expected_root_init = commit(&trace.initial_state.canonical);
        if self.root_init != expected_root_init {
            return false;
        }

        // Check 2: final state commitment
        let expected_root_final = if let Some(last_entry) = trace.entries.last() {
            last_entry.post_state_commitment.clone()
        } else {
            expected_root_init.clone()
        };
        if self.root_final != expected_root_final {
            return false;
        }

        // Check 3: observable binding — all observables match in order
        let trace_observables: Vec<&Observable> =
            trace.entries.iter().map(|e| &e.observable).collect();
        if self.observables.len() != trace_observables.len() {
            return false;
        }
        for (pub_obs, trace_obs) in self.observables.iter().zip(trace_observables.iter()) {
            if pub_obs != *trace_obs {
                return false;
            }
        }

        // Check 4: domain matches
        if self.domain != trace.initial_state.environment.execution_domain {
            return false;
        }

        // Check 5: version matches
        if self.version != trace.initial_state.canonical.system_data.protocol_version {
            return false;
        }

        true
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vsel_core::input::{Authorization, Input};
    use vsel_core::observable::{Observable, TransitionStatus};
    use vsel_core::state::*;
    use vsel_core::transition::TransitionClass;
    use vsel_core::types::*;
    use vsel_trace::engine::{Trace, TraceEntry};

    // -- Test helpers --

    fn test_domain_tag() -> DomainTag {
        let mut h = [0u8; 32];
        h[0] = 0xAB;
        DomainTag(Hash(h))
    }

    fn test_version() -> ProtocolVersion {
        ProtocolVersion {
            major: 1,
            minor: 0,
            patch: 0,
        }
    }

    fn minimal_canonical() -> CanonicalState {
        CanonicalState {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            system_data: SystemData {
                protocol_version: test_version(),
                total_supply: 0,
                parameters: BTreeMap::new(),
            },
        }
    }

    fn test_state() -> State {
        let c = minimal_canonical();
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

    fn test_input() -> Input {
        Input {
            payload: Payload {
                payload_type: "transfer".to_string(),
                data: vec![1, 2, 3],
            },
            auth: Authorization {
                classical_sig: vec![1; 64],
                pqc_sig: vec![2; 128],
                public_key: HybridPublicKey {
                    classical: vec![3; 32],
                    pqc: vec![4; 64],
                },
                nonce: 1,
                domain: test_domain_tag(),
            },
            aux: AuxiliaryData {
                data: vec![0xAA, 0xBB],
            },
        }
    }

    fn test_observable() -> Observable {
        Observable {
            transition_class: TransitionClass::Update,
            outputs: vec![OutputEvent {
                event_type: "balance_change".to_string(),
                data: vec![1, 2, 3],
            }],
            gas_used: 21_000,
            status: TransitionStatus::Success,
        }
    }

    fn test_trace(num_entries: usize) -> Trace {
        let initial_state = test_state();
        let init_commit = commit(&initial_state.canonical);
        let mut entries = Vec::new();

        for i in 0..num_entries {
            let pre_commit = if i == 0 {
                init_commit.clone()
            } else {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                Hash(h)
            };
            let mut post_hash = [0u8; 32];
            post_hash[0] = (i + 1) as u8;
            let mut chain = [0u8; 32];
            chain[0] = (i + 100) as u8;

            entries.push(TraceEntry {
                index: i as u64,
                pre_state_commitment: pre_commit,
                input: test_input(),
                post_state_commitment: Hash(post_hash),
                observable: test_observable(),
                environment: initial_state.environment.clone(),
                chain_hash: Hash(chain),
            });
        }

        let final_commitment = if let Some(last) = entries.last() {
            last.chain_hash.clone()
        } else {
            Hash([0u8; 32])
        };

        Trace {
            entries,
            initial_state,
            commitment: final_commitment,
        }
    }

    // -----------------------------------------------------------------------
    // PublicInputs::from_trace tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_trace_empty() {
        let trace = test_trace(0);
        let pub_inputs = PublicInputs::from_trace(&trace);

        let expected_root = commit(&trace.initial_state.canonical);
        assert_eq!(pub_inputs.root_init, expected_root);
        assert_eq!(pub_inputs.root_final, expected_root, "empty trace: root_final == root_init");
        assert!(pub_inputs.observables.is_empty());
        assert_eq!(pub_inputs.domain, test_domain_tag());
        assert_eq!(pub_inputs.version, test_version());
    }

    #[test]
    fn test_from_trace_single_entry() {
        let trace = test_trace(1);
        let pub_inputs = PublicInputs::from_trace(&trace);

        let expected_root_init = commit(&trace.initial_state.canonical);
        assert_eq!(pub_inputs.root_init, expected_root_init);
        assert_eq!(
            pub_inputs.root_final,
            trace.entries[0].post_state_commitment
        );
        assert_eq!(pub_inputs.observables.len(), 1);
        assert_eq!(pub_inputs.observables[0], test_observable());
    }

    #[test]
    fn test_from_trace_multiple_entries() {
        let trace = test_trace(3);
        let pub_inputs = PublicInputs::from_trace(&trace);

        assert_eq!(pub_inputs.observables.len(), 3);
        assert_eq!(
            pub_inputs.root_final,
            trace.entries[2].post_state_commitment
        );
        // All observables should match trace entries in order.
        for (i, obs) in pub_inputs.observables.iter().enumerate() {
            assert_eq!(obs, &trace.entries[i].observable);
        }
    }

    #[test]
    fn test_from_trace_captures_domain_and_version() {
        let trace = test_trace(1);
        let pub_inputs = PublicInputs::from_trace(&trace);

        assert_eq!(
            pub_inputs.domain,
            trace.initial_state.environment.execution_domain
        );
        assert_eq!(
            pub_inputs.version,
            trace.initial_state.canonical.system_data.protocol_version
        );
    }

    // -----------------------------------------------------------------------
    // verify_observable_binding tests (PROOF-2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_observable_binding_matches() {
        let trace = test_trace(2);
        let pub_inputs = PublicInputs::from_trace(&trace);

        let trace_obs: Vec<Observable> =
            trace.entries.iter().map(|e| e.observable.clone()).collect();
        assert!(pub_inputs.verify_observable_binding(&trace_obs));
    }

    #[test]
    fn test_observable_binding_empty() {
        let trace = test_trace(0);
        let pub_inputs = PublicInputs::from_trace(&trace);

        assert!(pub_inputs.verify_observable_binding(&[]));
    }

    #[test]
    fn test_observable_binding_length_mismatch() {
        let trace = test_trace(2);
        let pub_inputs = PublicInputs::from_trace(&trace);

        // Fewer observables than expected.
        let partial: Vec<Observable> = vec![test_observable()];
        assert!(!pub_inputs.verify_observable_binding(&partial));

        // More observables than expected.
        let extra: Vec<Observable> = vec![test_observable(); 3];
        assert!(!pub_inputs.verify_observable_binding(&extra));
    }

    #[test]
    fn test_observable_binding_content_mismatch() {
        let trace = test_trace(1);
        let pub_inputs = PublicInputs::from_trace(&trace);

        let mut wrong_obs = test_observable();
        wrong_obs.gas_used = 999_999;
        assert!(!pub_inputs.verify_observable_binding(&[wrong_obs]));
    }

    #[test]
    fn test_observable_binding_order_matters() {
        let trace = test_trace(2);
        let pub_inputs = PublicInputs::from_trace(&trace);

        // Create two different observables.
        let obs1 = test_observable();
        let mut obs2 = test_observable();
        obs2.gas_used = 42_000;

        // Build public inputs with [obs1, obs2].
        let custom_pub = PublicInputs {
            observables: vec![obs1.clone(), obs2.clone()],
            ..pub_inputs
        };

        // Reversed order should fail.
        assert!(!custom_pub.verify_observable_binding(&[obs2, obs1]));
    }

    // -----------------------------------------------------------------------
    // matches_trace tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_trace_valid() {
        let trace = test_trace(2);
        let pub_inputs = PublicInputs::from_trace(&trace);

        assert!(pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_empty() {
        let trace = test_trace(0);
        let pub_inputs = PublicInputs::from_trace(&trace);

        assert!(pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_wrong_root_init() {
        let trace = test_trace(1);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        pub_inputs.root_init = Hash([0xFF; 32]);

        assert!(!pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_wrong_root_final() {
        let trace = test_trace(1);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        pub_inputs.root_final = Hash([0xFF; 32]);

        assert!(!pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_wrong_observables() {
        let trace = test_trace(1);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        pub_inputs.observables[0].gas_used = 999_999;

        assert!(!pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_wrong_domain() {
        let trace = test_trace(1);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        pub_inputs.domain = DomainTag(Hash([0xFF; 32]));

        assert!(!pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_wrong_version() {
        let trace = test_trace(1);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        pub_inputs.version = ProtocolVersion {
            major: 99,
            minor: 0,
            patch: 0,
        };

        assert!(!pub_inputs.matches_trace(&trace));
    }

    #[test]
    fn test_matches_trace_observable_count_mismatch() {
        let trace = test_trace(2);
        let mut pub_inputs = PublicInputs::from_trace(&trace);
        // Remove one observable.
        pub_inputs.observables.pop();

        assert!(!pub_inputs.matches_trace(&trace));
    }

    // -----------------------------------------------------------------------
    // Round-trip: from_trace then matches_trace
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_trace_roundtrip() {
        for n in 0..5 {
            let trace = test_trace(n);
            let pub_inputs = PublicInputs::from_trace(&trace);
            assert!(
                pub_inputs.matches_trace(&trace),
                "from_trace → matches_trace round-trip failed for {} entries",
                n
            );
        }
    }

    // -----------------------------------------------------------------------
    // Observable binding with from_trace
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_trace_observable_binding_roundtrip() {
        let trace = test_trace(3);
        let pub_inputs = PublicInputs::from_trace(&trace);

        let trace_obs: Vec<Observable> =
            trace.entries.iter().map(|e| e.observable.clone()).collect();
        assert!(
            pub_inputs.verify_observable_binding(&trace_obs),
            "PROOF-2: observables from trace must bind to public inputs"
        );
    }
}
