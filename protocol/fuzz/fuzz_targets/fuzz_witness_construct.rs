//! Fuzz target: Witness construction from arbitrary data.
//!
//! Accepts arbitrary bytes, constructs Witness structures from the byte
//! stream, and exercises WitnessEncoding. Must not panic on any input.
//!
//! Requirements: 6.1(c), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use vsel_core::state::{
    CanonicalState, Environment, State, TraceMetadata,
    derive, derive_economic,
};
use vsel_core::types::{
    DomainTag, Hash, ProtocolVersion, SystemData,
    Payload, AuxiliaryData, HybridPublicKey,
};
use vsel_core::input::{Authorization, Input};
use vsel_proof::witness::{AuxiliaryComputation, Witness, WitnessEncoding};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut cursor = 0usize;

    // Read counts (bounded to prevent OOM).
    let num_states = (read_u8(data, &mut cursor).unwrap_or(0) % 5) as usize;
    let num_inputs = (read_u8(data, &mut cursor).unwrap_or(0) % 5) as usize;
    let num_aux = (read_u8(data, &mut cursor).unwrap_or(0) % 5) as usize;

    // Build intermediate states.
    let mut intermediate_states = Vec::with_capacity(num_states);
    for i in 0..num_states {
        let state = build_state(data, &mut cursor, i as u64);
        intermediate_states.push(state);
    }

    // Build input sequence.
    let mut input_sequence = Vec::with_capacity(num_inputs);
    for _ in 0..num_inputs {
        let input = build_input(data, &mut cursor);
        input_sequence.push(input);
    }

    // Build auxiliary computation.
    let mut aux = AuxiliaryComputation::empty();
    for i in 0..num_aux {
        let name = format!("aux_{}", i);
        let value_len = (read_u8(data, &mut cursor).unwrap_or(0) % 16) as usize;
        let mut value = Vec::with_capacity(value_len);
        for _ in 0..value_len {
            value.push(read_u8(data, &mut cursor).unwrap_or(0));
        }
        aux.add(name, value);
    }

    // Construct the witness — must not panic.
    let witness = Witness {
        intermediate_states,
        input_sequence,
        aux_computation: aux,
    };

    // Exercise WitnessEncoding — must not panic.
    let encoding = WitnessEncoding::from_witness(&witness);

    // Exercise completeness check — must not panic.
    let _ = encoding.verify_completeness(&witness);
});

fn read_u8(data: &[u8], cursor: &mut usize) -> Option<u8> {
    if *cursor >= data.len() {
        return None;
    }
    let b = data[*cursor];
    *cursor += 1;
    Some(b)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> u64 {
    let mut bytes = [0u8; 8];
    for b in &mut bytes {
        *b = read_u8(data, cursor).unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn read_hash(data: &[u8], cursor: &mut usize) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = read_u8(data, cursor).unwrap_or(0);
    }
    Hash(h)
}

/// Build a State from fuzz data.
fn build_state(data: &[u8], cursor: &mut usize, seq_index: u64) -> State {
    let canonical = CanonicalState {
        accounts: BTreeMap::new(),
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
            total_supply: read_u64(data, cursor) as u128,
            parameters: BTreeMap::new(),
        },
    };

    let derived = derive(&canonical);

    let mut domain_bytes = [0u8; 32];
    domain_bytes[0] = 1; // Non-zero domain tag.
    let env = Environment {
        timestamp: read_u64(data, cursor),
        block_height: read_u64(data, cursor),
        execution_domain: DomainTag(Hash(domain_bytes)),
    };

    let economic = derive_economic(&canonical, &env);

    let metadata = TraceMetadata {
        sequence_index: seq_index,
        previous_commitment: read_hash(data, cursor),
        epoch: 0,
        timestamp: env.timestamp,
    };

    State {
        canonical,
        derived,
        environment: env,
        economic,
        metadata,
    }
}

/// Build an Input from fuzz data.
fn build_input(data: &[u8], cursor: &mut usize) -> Input {
    let payload_type_tag = read_u8(data, cursor).unwrap_or(0) % 3;
    let payload_type = match payload_type_tag {
        0 => "transfer",
        1 => "deposit",
        _ => "noop",
    };

    let payload_len = (read_u8(data, cursor).unwrap_or(1) % 16).max(1) as usize;
    let mut payload_data = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload_data.push(read_u8(data, cursor).unwrap_or(0xFF));
    }

    let mut domain_bytes = [0u8; 32];
    domain_bytes[0] = 0xAB; // Non-zero domain tag.

    Input {
        payload: Payload {
            payload_type: payload_type.to_string(),
            data: payload_data,
        },
        auth: Authorization {
            classical_sig: vec![1, 2, 3],
            pqc_sig: vec![4, 5, 6],
            public_key: HybridPublicKey {
                classical: vec![10, 11],
                pqc: vec![20, 21],
            },
            nonce: read_u64(data, cursor),
            domain: DomainTag(Hash(domain_bytes)),
        },
        aux: AuxiliaryData { data: vec![] },
    }
}
