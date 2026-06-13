pub const MAX_COUNTER: u64 = 1000000;
pub const MAX_DELTA: u64 = 1000;
pub const OBSERVABLE_DOMAIN: felt252 = 'VSEL_REF_SM_V1';
pub const APPLY_KIND: felt252 = 'APPLY';
pub const SEAL_KIND: felt252 = 'SEAL';

#[derive(Copy, Drop, Serde, Debug, PartialEq)]
pub struct MachineState {
    pub counter: u64,
    pub version: u64,
    pub last_transition_id: u64,
    pub sealed: bool,
    pub last_observable: felt252,
}

#[derive(Copy, Drop, Serde, Debug, PartialEq)]
pub struct TransitionInput {
    pub transition_id: u64,
    pub expected_version: u64,
    pub delta: u64,
    pub actor: felt252,
}

#[derive(Copy, Drop, Serde, Debug, PartialEq)]
pub struct TransitionObservable {
    pub transition_kind: felt252,
    pub transition_id: u64,
    pub actor: felt252,
    pub previous_version: u64,
    pub next_version: u64,
    pub previous_counter: u64,
    pub delta: u64,
    pub next_counter: u64,
    pub commitment: felt252,
}

pub fn initial_state() -> MachineState {
    MachineState {
        counter: 0, version: 0, last_transition_id: 0, sealed: false, last_observable: 0,
    }
}

pub fn apply_transition(
    state: MachineState, input: TransitionInput,
) -> (MachineState, TransitionObservable) {
    assert(!state.sealed, 'machine sealed');
    assert(input.delta != 0, 'zero delta');
    assert(input.delta <= MAX_DELTA, 'delta too large');
    assert(input.expected_version == state.version, 'version mismatch');
    assert(input.transition_id == state.last_transition_id + 1, 'bad transition id');

    let next_counter = state.counter + input.delta;
    assert(next_counter <= MAX_COUNTER, 'counter bound');

    let next_version = state.version + 1;
    let commitment = compute_observable_commitment(
        APPLY_KIND,
        input.transition_id,
        input.expected_version,
        state.counter,
        input.delta,
        next_counter,
        input.actor,
    );
    let next = MachineState {
        counter: next_counter,
        version: next_version,
        last_transition_id: input.transition_id,
        sealed: false,
        last_observable: commitment,
    };
    assert(invariant_holds(next), 'VSEL_INV');

    (
        next,
        TransitionObservable {
            transition_kind: APPLY_KIND,
            transition_id: input.transition_id,
            actor: input.actor,
            previous_version: state.version,
            next_version,
            previous_counter: state.counter,
            delta: input.delta,
            next_counter,
            commitment,
        },
    )
}

pub fn seal(
    state: MachineState, transition_id: u64, expected_version: u64, actor: felt252,
) -> (MachineState, TransitionObservable) {
    assert(!state.sealed, 'machine sealed');
    assert(expected_version == state.version, 'version mismatch');
    assert(transition_id == state.last_transition_id + 1, 'bad transition id');

    let next_version = state.version + 1;
    let commitment = compute_observable_commitment(
        SEAL_KIND, transition_id, expected_version, state.counter, 0, state.counter, actor,
    );
    let next = MachineState {
        counter: state.counter,
        version: next_version,
        last_transition_id: transition_id,
        sealed: true,
        last_observable: commitment,
    };
    assert(invariant_holds(next), 'VSEL_INV');

    (
        next,
        TransitionObservable {
            transition_kind: SEAL_KIND,
            transition_id,
            actor,
            previous_version: state.version,
            next_version,
            previous_counter: state.counter,
            delta: 0,
            next_counter: state.counter,
            commitment,
        },
    )
}

pub fn invariant_holds(state: MachineState) -> bool {
    state.counter <= MAX_COUNTER && state.version == state.last_transition_id
}

pub fn compute_observable_commitment(
    transition_kind: felt252,
    transition_id: u64,
    expected_version: u64,
    previous_counter: u64,
    delta: u64,
    next_counter: u64,
    actor: felt252,
) -> felt252 {
    OBSERVABLE_DOMAIN
        + transition_kind
        + actor
        + transition_id.into() * 3
        + expected_version.into() * 5
        + previous_counter.into() * 7
        + delta.into() * 11
        + next_counter.into() * 13
}

#[cfg(test)]
mod tests {
    use super::{TransitionInput, apply_transition, initial_state, invariant_holds, seal};

    #[test]
    fn valid_transition_preserves_all_invariants() {
        let state = initial_state();
        let input = TransitionInput {
            transition_id: 1, expected_version: 0, delta: 7, actor: 'alice',
        };
        let (next, observable) = apply_transition(state, input);

        assert(next.counter == 7, 'BAD_COUNTER');
        assert(next.version == 1, 'BAD_VERSION');
        assert(next.last_transition_id == 1, 'BAD_ID');
        assert(!next.sealed, 'BAD_SEAL');
        assert(next.last_observable == observable.commitment, 'BAD_OBS');
        assert(invariant_holds(next), 'BAD_INV');
    }

    #[test]
    fn seal_is_final_state_transition() {
        let state = initial_state();
        let input = TransitionInput {
            transition_id: 1, expected_version: 0, delta: 7, actor: 'alice',
        };
        let (after_apply, _) = apply_transition(state, input);
        let (after_seal, observable) = seal(after_apply, 2, 1, 'auditor');

        assert(after_seal.counter == 7, 'BAD_COUNTER');
        assert(after_seal.version == 2, 'BAD_VERSION');
        assert(after_seal.last_transition_id == 2, 'BAD_ID');
        assert(after_seal.sealed, 'BAD_SEAL');
        assert(after_seal.last_observable == observable.commitment, 'BAD_OBS');
        assert(invariant_holds(after_seal), 'BAD_INV');
    }

    #[test]
    #[should_panic(expected: ('zero delta',))]
    fn zero_delta_is_rejected() {
        let input = TransitionInput {
            transition_id: 1, expected_version: 0, delta: 0, actor: 'alice',
        };
        apply_transition(initial_state(), input);
    }

    #[test]
    #[should_panic(expected: ('version mismatch',))]
    fn stale_version_is_rejected() {
        let input = TransitionInput {
            transition_id: 1, expected_version: 1, delta: 7, actor: 'alice',
        };
        apply_transition(initial_state(), input);
    }

    #[test]
    #[should_panic(expected: ('bad transition id',))]
    fn out_of_order_transition_is_rejected() {
        let input = TransitionInput {
            transition_id: 2, expected_version: 0, delta: 7, actor: 'alice',
        };
        apply_transition(initial_state(), input);
    }
}
