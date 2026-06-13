#[starknet::interface]
pub trait IReferenceStateMachine<TContractState> {
    fn apply_transition(
        ref self: TContractState,
        transition_id: u64,
        expected_version: u64,
        delta: u64,
        actor: felt252,
    ) -> (u64, u64, felt252);

    fn seal(
        ref self: TContractState, transition_id: u64, expected_version: u64, actor: felt252,
    ) -> (u64, u64, felt252);

    fn snapshot(self: @TContractState) -> (u64, u64, u64, bool, felt252);

    fn invariant_holds(self: @TContractState) -> bool;

    fn max_counter(self: @TContractState) -> u64;
}

#[starknet::contract]
pub mod ReferenceStateMachine {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use vsel_reference_state_machine_core::{
        MAX_COUNTER, MachineState, TransitionInput, apply_transition as apply_pure, invariant_holds,
        seal as seal_pure,
    };

    #[storage]
    struct Storage {
        counter: u64,
        version: u64,
        last_transition_id: u64,
        sealed: bool,
        last_observable: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransitionApplied: TransitionApplied,
        MachineSealed: MachineSealed,
    }

    #[derive(Drop, starknet::Event)]
    struct TransitionApplied {
        #[key]
        transition_id: u64,
        #[key]
        actor: felt252,
        previous_version: u64,
        next_version: u64,
        previous_counter: u64,
        delta: u64,
        next_counter: u64,
        observable_commitment: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct MachineSealed {
        #[key]
        transition_id: u64,
        #[key]
        actor: felt252,
        previous_version: u64,
        next_version: u64,
        counter: u64,
        observable_commitment: felt252,
    }

    #[abi(embed_v0)]
    impl ReferenceStateMachineImpl of super::IReferenceStateMachine<ContractState> {
        fn apply_transition(
            ref self: ContractState,
            transition_id: u64,
            expected_version: u64,
            delta: u64,
            actor: felt252,
        ) -> (u64, u64, felt252) {
            let before = read_state(@self);
            let input = TransitionInput { transition_id, expected_version, delta, actor };
            let (after, observable) = apply_pure(before, input);
            write_state(ref self, after);

            self
                .emit(
                    Event::TransitionApplied(
                        TransitionApplied {
                            transition_id,
                            actor,
                            previous_version: observable.previous_version,
                            next_version: observable.next_version,
                            previous_counter: observable.previous_counter,
                            delta,
                            next_counter: observable.next_counter,
                            observable_commitment: observable.commitment,
                        },
                    ),
                );

            (after.counter, after.version, observable.commitment)
        }

        fn seal(
            ref self: ContractState, transition_id: u64, expected_version: u64, actor: felt252,
        ) -> (u64, u64, felt252) {
            let before = read_state(@self);
            let (after, observable) = seal_pure(before, transition_id, expected_version, actor);
            write_state(ref self, after);

            self
                .emit(
                    Event::MachineSealed(
                        MachineSealed {
                            transition_id,
                            actor,
                            previous_version: observable.previous_version,
                            next_version: observable.next_version,
                            counter: observable.next_counter,
                            observable_commitment: observable.commitment,
                        },
                    ),
                );

            (after.counter, after.version, observable.commitment)
        }

        fn snapshot(self: @ContractState) -> (u64, u64, u64, bool, felt252) {
            (
                self.counter.read(),
                self.version.read(),
                self.last_transition_id.read(),
                self.sealed.read(),
                self.last_observable.read(),
            )
        }

        fn invariant_holds(self: @ContractState) -> bool {
            invariant_holds(read_state(self))
        }

        fn max_counter(self: @ContractState) -> u64 {
            MAX_COUNTER
        }
    }

    fn read_state(self: @ContractState) -> MachineState {
        MachineState {
            counter: self.counter.read(),
            version: self.version.read(),
            last_transition_id: self.last_transition_id.read(),
            sealed: self.sealed.read(),
            last_observable: self.last_observable.read(),
        }
    }

    fn write_state(ref self: ContractState, state: MachineState) {
        self.counter.write(state.counter);
        self.version.write(state.version);
        self.last_transition_id.write(state.last_transition_id);
        self.sealed.write(state.sealed);
        self.last_observable.write(state.last_observable);
    }
}
