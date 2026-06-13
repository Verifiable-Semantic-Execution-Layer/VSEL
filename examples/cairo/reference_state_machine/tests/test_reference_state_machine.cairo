use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use vsel_reference_state_machine::reference_contract::{
    IReferenceStateMachineDispatcher, IReferenceStateMachineDispatcherTrait,
    IReferenceStateMachineSafeDispatcher, IReferenceStateMachineSafeDispatcherTrait,
};

const OBSERVABLE_DOMAIN: felt252 = 'VSEL_REF_SM_V1';
const APPLY_KIND: felt252 = 'APPLY';
const SEAL_KIND: felt252 = 'SEAL';

fn deploy_contract() -> ContractAddress {
    let contract = declare("ReferenceStateMachine").unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@ArrayTrait::new()).unwrap();
    contract_address
}

fn expected_observable_commitment(
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

#[test]
fn initial_state_satisfies_invariants() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineDispatcher { contract_address };

    let (counter, version, last_transition_id, sealed, observable) = dispatcher.snapshot();

    assert(counter == 0, 'counter');
    assert(version == 0, 'version');
    assert(last_transition_id == 0, 'transition id');
    assert(sealed == false, 'sealed');
    assert(observable == 0, 'observable');
    assert(dispatcher.invariant_holds(), 'invariant');
    assert(dispatcher.max_counter() == 1000000, 'max counter');
}

#[test]
fn ordered_transitions_update_state_and_observable_commitment() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineDispatcher { contract_address };

    let (counter_1, version_1, observable_1) = dispatcher.apply_transition(1, 0, 7, 'alice');
    assert(counter_1 == 7, 'counter 1');
    assert(version_1 == 1, 'version 1');
    assert(
        observable_1 == expected_observable_commitment(APPLY_KIND, 1, 0, 0, 7, 7, 'alice'),
        'observable 1',
    );

    let (counter_2, version_2, observable_2) = dispatcher.apply_transition(2, 1, 11, 'bob');
    assert(counter_2 == 18, 'counter 2');
    assert(version_2 == 2, 'version 2');
    assert(
        observable_2 == expected_observable_commitment(APPLY_KIND, 2, 1, 7, 11, 18, 'bob'),
        'observable 2',
    );

    let (counter, version, last_transition_id, sealed, observable) = dispatcher.snapshot();
    assert(counter == 18, 'final counter');
    assert(version == 2, 'final version');
    assert(last_transition_id == 2, 'final transition');
    assert(sealed == false, 'not sealed');
    assert(observable == observable_2, 'snapshot observable');
    assert(dispatcher.invariant_holds(), 'invariant');
}

#[test]
fn seal_is_final_transition() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineDispatcher { contract_address };

    dispatcher.apply_transition(1, 0, 5, 'alice');
    let (counter, version, observable) = dispatcher.seal(2, 1, 'auditor');

    assert(counter == 5, 'sealed counter');
    assert(version == 2, 'sealed version');
    assert(
        observable == expected_observable_commitment(SEAL_KIND, 2, 1, 5, 0, 5, 'auditor'),
        'seal observable',
    );

    let (snapshot_counter, snapshot_version, last_transition_id, sealed, snapshot_observable) =
        dispatcher
        .snapshot();
    assert(snapshot_counter == 5, 'snapshot counter');
    assert(snapshot_version == 2, 'snapshot version');
    assert(last_transition_id == 2, 'snapshot transition');
    assert(sealed == true, 'sealed');
    assert(snapshot_observable == observable, 'snapshot observable');
    assert(dispatcher.invariant_holds(), 'invariant');
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_zero_delta() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineSafeDispatcher { contract_address };

    match dispatcher.apply_transition(1, 0, 0, 'alice') {
        Result::Ok(_) => core::panic_with_felt252('accepted zero delta'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'zero delta', *panic_data.at(0));
        },
    };
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_version_mismatch() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineSafeDispatcher { contract_address };

    match dispatcher.apply_transition(1, 1, 3, 'alice') {
        Result::Ok(_) => core::panic_with_felt252('accepted bad version'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'version mismatch', *panic_data.at(0));
        },
    };
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_out_of_order_transition_id() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineSafeDispatcher { contract_address };

    match dispatcher.apply_transition(2, 0, 3, 'alice') {
        Result::Ok(_) => core::panic_with_felt252('accepted bad id'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'bad transition id', *panic_data.at(0));
        },
    };
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_delta_above_policy_limit() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineSafeDispatcher { contract_address };

    match dispatcher.apply_transition(1, 0, 1001, 'alice') {
        Result::Ok(_) => core::panic_with_felt252('accepted large delta'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'delta too large', *panic_data.at(0));
        },
    };
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_apply_after_seal() {
    let contract_address = deploy_contract();
    let dispatcher = IReferenceStateMachineDispatcher { contract_address };
    let safe_dispatcher = IReferenceStateMachineSafeDispatcher { contract_address };

    dispatcher.apply_transition(1, 0, 3, 'alice');
    dispatcher.seal(2, 1, 'auditor');

    match safe_dispatcher.apply_transition(3, 2, 1, 'alice') {
        Result::Ok(_) => core::panic_with_felt252('accepted after seal'),
        Result::Err(panic_data) => {
            assert(*panic_data.at(0) == 'machine sealed', *panic_data.at(0));
        },
    };
}
