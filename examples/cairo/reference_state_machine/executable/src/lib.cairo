use vsel_reference_state_machine_core::{TransitionInput, apply_transition, initial_state};

#[executable]
fn main(
    transition_id: u64, expected_version: u64, delta: u64, actor: felt252,
) -> (u64, u64, u64, felt252) {
    let input = TransitionInput { transition_id, expected_version, delta, actor };
    let (next, observable) = apply_transition(initial_state(), input);
    (next.counter, next.version, next.last_transition_id, observable.commitment)
}
