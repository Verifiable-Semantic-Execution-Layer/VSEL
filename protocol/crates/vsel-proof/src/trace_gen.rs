//! Execution trace generation from Witness for Plonky3 STARK proofs.
//!
//! Derived from: design.md Component 1, Requirements 1.2, 1.4.
//!
//! This module converts a `Witness` (intermediate states, input sequence,
//! auxiliary computation) into a Plonky3 trace matrix suitable for STARK
//! proof generation. Each row of the trace corresponds to one execution
//! step; columns are laid out per the `ColumnMap`.
//!
//! # Trace Layout
//!
//! The trace matrix has dimensions `num_rows × num_cols` where:
//! - `num_rows` = `witness.trace_length()` padded to the next power of 2
//! - `num_cols` = `col_map.total_cols`
//!
//! Rows are filled from the witness data:
//! - Witness columns: state data and input payloads encoded as Goldilocks
//!   field elements
//! - Auxiliary columns: intermediate computation results from
//!   `witness.aux_computation`
//! - Constraint satisfaction flag: set to 1 for active rows, 0 for padding
//!
//! # FRI Padding
//!
//! Plonky3's FRI protocol requires the trace length to be a power of 2.
//! Padding rows are filled with zeros and have the constraint satisfaction
//! flag set to 0.
//!
//! # Module Gating
//!
//! This entire module is gated behind `#[cfg(feature = "plonky3-backend")]`.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::vsel_air::ColumnMap;
use crate::witness::Witness;

// ---------------------------------------------------------------------------
// Goldilocks encoding helpers
// ---------------------------------------------------------------------------

/// Encode a `u64` value as a Goldilocks field element.
///
/// The Goldilocks modulus is p = 2^64 - 2^32 + 1. Values that are
/// already < p are used directly; values >= p are reduced mod p.
#[inline]
fn encode_u64(val: u64) -> Goldilocks {
    use p3_field::PrimeCharacteristicRing;
    Goldilocks::from_u64(val)
}

/// Encode a byte slice as a sequence of Goldilocks field elements.
///
/// Splits the bytes into 7-byte chunks (to stay safely below the
/// Goldilocks modulus of ~2^64) and encodes each chunk as a
/// little-endian field element. Returns the encoded elements.
fn encode_bytes_as_field_elements(bytes: &[u8]) -> Vec<Goldilocks> {
    // Use 7-byte chunks to guarantee each chunk value < 2^56 < p.
    const CHUNK_SIZE: usize = 7;
    let mut elements = Vec::new();
    for chunk in bytes.chunks(CHUNK_SIZE) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let val = u64::from_le_bytes(buf);
        elements.push(encode_u64(val));
    }
    elements
}

// ---------------------------------------------------------------------------
// Trace length computation
// ---------------------------------------------------------------------------

/// Compute the effective trace length from a witness.
///
/// The trace length is the number of execution steps, which equals
/// the number of inputs in the input sequence. If the witness has
/// no inputs, the trace length is 1 (minimum for a valid trace).
fn witness_trace_length(witness: &Witness) -> usize {
    witness.input_sequence.len().max(1)
}

/// Round up to the next power of 2.
///
/// Plonky3's FRI protocol requires trace lengths to be powers of 2.
/// Returns the smallest power of 2 >= n.
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// Generate a Plonky3 execution trace matrix from a `Witness` and `ColumnMap`.
///
/// Converts the witness data (intermediate states, input sequence, auxiliary
/// computation) into a `RowMajorMatrix<Goldilocks>` where:
/// - Each row corresponds to one execution step
/// - Columns are laid out per the `ColumnMap`
/// - The trace is padded to a power of 2 for FRI
///
/// # Column filling strategy
///
/// For each execution step `i`:
/// 1. **Witness columns**: Filled from the input sequence. Each input's
///    payload data and authorization nonce are encoded as field elements
///    and distributed across witness columns.
/// 2. **Auxiliary columns**: Filled from `witness.aux_computation.values`.
///    Named auxiliary values are matched to their column indices via the
///    `ColumnMap`. Unmatched auxiliary values are skipped.
/// 3. **Constraint satisfaction flag**: Set to `Goldilocks(1)` for active
///    rows (rows with real execution data) and `Goldilocks(0)` for padding.
///
/// # Padding
///
/// Padding rows (beyond the witness trace length) are filled with zeros
/// in all columns, including the constraint satisfaction flag.
///
/// Requirements 1.2, 1.4.
pub fn generate_trace(witness: &Witness, col_map: &ColumnMap) -> RowMajorMatrix<Goldilocks> {
    let raw_len = witness_trace_length(witness);
    let padded_len = next_power_of_two(raw_len);
    let num_cols = col_map.total_cols;

    // Allocate the trace matrix: padded_len rows × num_cols columns.
    // Initialize all cells to zero (Goldilocks(0)).
    let mut values = vec![Goldilocks::ZERO; padded_len * num_cols];

    // Fill active rows from witness data.
    for row in 0..raw_len {
        let row_offset = row * num_cols;

        // --- Fill witness columns from input sequence ---
        if row < witness.input_sequence.len() {
            let input = &witness.input_sequence[row];
            fill_witness_columns_from_input(
                &mut values[row_offset..row_offset + num_cols],
                input,
                col_map,
            );
        }

        // --- Fill witness columns from intermediate states ---
        if row < witness.intermediate_states.len() {
            fill_witness_columns_from_state(
                &mut values[row_offset..row_offset + num_cols],
                &witness.intermediate_states[row],
                col_map,
            );
        }

        // --- Fill auxiliary columns from aux_computation ---
        fill_auxiliary_columns(
            &mut values[row_offset..row_offset + num_cols],
            &witness.aux_computation,
            col_map,
            row,
        );

        // --- Set constraint satisfaction flag to 1 for active rows ---
        if let Some(&flag_col) = col_map.aux_cols.get("__constraint_satisfaction_flag") {
            values[row_offset + flag_col] = Goldilocks::ONE;
        }
    }

    // Padding rows remain zero (already initialized).

    RowMajorMatrix::new(values, num_cols)
}

// ---------------------------------------------------------------------------
// Column filling helpers
// ---------------------------------------------------------------------------

/// Fill witness columns from an input's payload and authorization data.
///
/// Encodes the input's payload data and nonce as Goldilocks field elements
/// and writes them into the appropriate witness columns.
fn fill_witness_columns_from_input(
    row: &mut [Goldilocks],
    input: &vsel_core::input::Input,
    col_map: &ColumnMap,
) {
    // Encode payload data bytes as field elements and distribute
    // across witness columns that match input-related names.
    let payload_elements = encode_bytes_as_field_elements(&input.payload.data);

    // Fill named witness columns for input data.
    // Convention: witness columns named "input_payload_{i}" get payload data.
    for (i, &elem) in payload_elements.iter().enumerate() {
        let col_name = format!("input_payload_{}", i);
        if let Some(&col_idx) = col_map.witness_cols.get(&col_name) {
            if col_idx < row.len() {
                row[col_idx] = elem;
            }
        }
    }

    // Encode the authorization nonce.
    if let Some(&col_idx) = col_map.witness_cols.get("input_nonce") {
        if col_idx < row.len() {
            row[col_idx] = encode_u64(input.auth.nonce);
        }
    }

    // Encode payload type hash (first 7 bytes as a field element).
    if let Some(&col_idx) = col_map.witness_cols.get("payload_type") {
        if col_idx < row.len() {
            let type_elements =
                encode_bytes_as_field_elements(input.payload.payload_type.as_bytes());
            if let Some(&elem) = type_elements.first() {
                row[col_idx] = elem;
            }
        }
    }

    // For generic witness columns (e.g., "x", "y"), fill from payload
    // data sequentially if no specific named column matched.
    let mut payload_idx = 0;
    for (name, &col_idx) in &col_map.witness_cols {
        // Skip columns we've already filled by name convention.
        if name.starts_with("input_payload_") || name == "input_nonce" || name == "payload_type" {
            continue;
        }
        // Fill remaining witness columns from payload data.
        if col_idx < row.len() && payload_idx < payload_elements.len() {
            row[col_idx] = payload_elements[payload_idx];
            payload_idx += 1;
        }
    }
}

/// Fill witness columns from an intermediate state.
///
/// Encodes the state commitment as field elements and writes them
/// into state-related witness columns.
fn fill_witness_columns_from_state(
    row: &mut [Goldilocks],
    state: &vsel_core::state::State,
    col_map: &ColumnMap,
) {
    // Encode the state root commitment as field elements.
    let state_commit = vsel_core::state::commit(&state.canonical);
    let commit_elements = encode_bytes_as_field_elements(&state_commit.0);

    // Fill named witness columns for state data.
    for (i, &elem) in commit_elements.iter().enumerate() {
        let col_name = format!("state_commit_{}", i);
        if let Some(&col_idx) = col_map.witness_cols.get(&col_name) {
            if col_idx < row.len() {
                row[col_idx] = elem;
            }
        }
    }

    // Encode total_supply as a field element.
    if let Some(&col_idx) = col_map.witness_cols.get("total_supply") {
        if col_idx < row.len() {
            row[col_idx] = encode_u64(state.canonical.system_data.total_supply as u64);
        }
    }

    // Encode timestamp.
    if let Some(&col_idx) = col_map.witness_cols.get("timestamp") {
        if col_idx < row.len() {
            row[col_idx] = encode_u64(state.environment.timestamp);
        }
    }

    // Encode block height.
    if let Some(&col_idx) = col_map.witness_cols.get("block_height") {
        if col_idx < row.len() {
            row[col_idx] = encode_u64(state.environment.block_height);
        }
    }
}

/// Fill auxiliary columns from the witness auxiliary computation.
///
/// Named auxiliary values are matched to their column indices via the
/// `ColumnMap`. Values are encoded as Goldilocks field elements.
fn fill_auxiliary_columns(
    row: &mut [Goldilocks],
    aux: &crate::witness::AuxiliaryComputation,
    col_map: &ColumnMap,
    step_index: usize,
) {
    for (name, value_bytes) in &aux.values {
        // Try exact name match first.
        if let Some(&col_idx) = col_map.aux_cols.get(name) {
            if col_idx < row.len() {
                let elements = encode_bytes_as_field_elements(value_bytes);
                if let Some(&elem) = elements.first() {
                    row[col_idx] = elem;
                }
            }
            continue;
        }

        // Try step-indexed name match (e.g., "post_commitment_0" for step 0).
        // Auxiliary values are often named with a step suffix.
        if name.ends_with(&format!("_{}", step_index)) {
            // Strip the step suffix and try matching the base name.
            let base_name = &name[..name.len() - format!("_{}", step_index).len()];
            let indexed_name = format!("{}_{}", base_name, step_index);
            if let Some(&col_idx) = col_map.aux_cols.get(&indexed_name) {
                if col_idx < row.len() {
                    let elements = encode_bytes_as_field_elements(value_bytes);
                    if let Some(&elem) = elements.first() {
                        row[col_idx] = elem;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsel_air::{ColumnMap, VselAir};
    use crate::witness::{AuxiliaryComputation, Witness};
    use p3_matrix::Matrix;
    use std::collections::HashMap;
    use vsel_constraints::compiler::{
        Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
        PublicInput, WitnessVariable, WitnessVariableKind,
    };

    /// Helper: create a minimal Witness with the given number of inputs.
    fn test_witness(num_inputs: usize) -> Witness {
        use vsel_core::input::{Authorization, Input};
        use vsel_core::types::*;

        let zero_hash = Hash([0u8; 32]);
        let mut inputs = Vec::new();
        for i in 0..num_inputs {
            inputs.push(Input {
                payload: Payload {
                    payload_type: "transfer".to_string(),
                    data: vec![(i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8, 1, 2, 3],
                },
                auth: Authorization {
                    classical_sig: vec![1; 64],
                    pqc_sig: vec![2; 128],
                    public_key: HybridPublicKey {
                        classical: vec![3; 32],
                        pqc: vec![4; 64],
                    },
                    nonce: i as u64 + 1,
                    domain: DomainTag(zero_hash.clone()),
                },
                aux: AuxiliaryData {
                    data: vec![0xAA, 0xBB],
                },
            });
        }

        let mut aux = AuxiliaryComputation::empty();
        for i in 0..num_inputs {
            aux.add(format!("post_commitment_{}", i), vec![(i + 100) as u8; 32]);
            aux.add(format!("chain_hash_{}", i), vec![(i + 200) as u8; 32]);
        }

        Witness {
            intermediate_states: vec![],
            input_sequence: inputs,
            aux_computation: aux,
        }
    }

    /// Helper: create a simple ColumnMap for testing.
    fn test_column_map() -> ColumnMap {
        let mut witness_cols = HashMap::new();
        witness_cols.insert("x".to_string(), 0);
        witness_cols.insert("y".to_string(), 1);

        let mut public_cols = HashMap::new();
        public_cols.insert("root_init".to_string(), 2);

        let mut aux_cols = HashMap::new();
        aux_cols.insert("__constraint_satisfaction_flag".to_string(), 3);

        ColumnMap {
            witness_cols,
            public_cols,
            aux_cols,
            total_cols: 4,
        }
    }

    /// Helper: create a ColumnMap from a compiled VselAir.
    fn column_map_from_constraint_system() -> (ColumnMap, usize) {
        let mut cs = ConstraintSystem::new("1.0.0");
        cs.add_witness_variable(WitnessVariable {
            name: "x".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test variable x".to_string(),
        });
        cs.add_witness_variable(WitnessVariable {
            name: "y".to_string(),
            kind: WitnessVariableKind::Semantic,
            description: "test variable y".to_string(),
        });
        cs.add_public_input(PublicInput {
            name: "root_init".to_string(),
            description: "initial state commitment".to_string(),
        });
        cs.add_constraint(Constraint {
            id: ConstraintId(0),
            expr: ConstraintExpr::Eq(
                Box::new(ConstraintExpr::WitnessRef("x".to_string())),
                Box::new(ConstraintExpr::Constant(42)),
            ),
            category: ConstraintCategory::Structural,
            description: "x = 42".to_string(),
        });

        let air = VselAir::compile(&cs).expect("compilation should succeed");
        let total = air.trace_width();
        (air.col_map().clone(), total)
    }

    // -----------------------------------------------------------------------
    // Power-of-2 padding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(4), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(7), 8);
        assert_eq!(next_power_of_two(8), 8);
        assert_eq!(next_power_of_two(9), 16);
        assert_eq!(next_power_of_two(100), 128);
    }

    // -----------------------------------------------------------------------
    // Trace dimensions tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_trace_empty_witness() {
        let witness = Witness {
            intermediate_states: vec![],
            input_sequence: vec![],
            aux_computation: AuxiliaryComputation::empty(),
        };
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // Empty witness → 1 row (minimum), padded to 1 (already power of 2).
        assert_eq!(trace.height(), 1);
        assert_eq!(trace.width(), col_map.total_cols);
    }

    #[test]
    fn test_generate_trace_single_input() {
        let witness = test_witness(1);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 1 input → 1 row, padded to 1.
        assert_eq!(trace.height(), 1);
        assert_eq!(trace.width(), col_map.total_cols);
    }

    #[test]
    fn test_generate_trace_three_inputs_padded_to_four() {
        let witness = test_witness(3);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 3 inputs → padded to 4 (next power of 2).
        assert_eq!(trace.height(), 4);
        assert_eq!(trace.width(), col_map.total_cols);
    }

    #[test]
    fn test_generate_trace_four_inputs_exact_power_of_two() {
        let witness = test_witness(4);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 4 inputs → already power of 2, no padding needed.
        assert_eq!(trace.height(), 4);
    }

    #[test]
    fn test_generate_trace_five_inputs_padded_to_eight() {
        let witness = test_witness(5);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 5 inputs → padded to 8.
        assert_eq!(trace.height(), 8);
    }

    // -----------------------------------------------------------------------
    // Constraint satisfaction flag tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constraint_satisfaction_flag_active_rows() {
        let witness = test_witness(3);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        let flag_col = *col_map
            .aux_cols
            .get("__constraint_satisfaction_flag")
            .unwrap();

        // Active rows (0, 1, 2) should have flag = 1.
        for row in 0..3 {
            let val = trace.values[row * col_map.total_cols + flag_col];
            assert_eq!(
                val,
                Goldilocks::ONE,
                "row {} should have satisfaction flag = 1",
                row
            );
        }
    }

    #[test]
    fn test_constraint_satisfaction_flag_padding_rows() {
        let witness = test_witness(3);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        let flag_col = *col_map
            .aux_cols
            .get("__constraint_satisfaction_flag")
            .unwrap();

        // Padding row (3) should have flag = 0.
        let val = trace.values[3 * col_map.total_cols + flag_col];
        assert_eq!(val, Goldilocks::ZERO, "padding row should have flag = 0");
    }

    // -----------------------------------------------------------------------
    // Padding rows are zero tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_padding_rows_are_zero() {
        let witness = test_witness(3);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // Row 3 is a padding row — all columns should be zero.
        let padding_start = 3 * col_map.total_cols;
        for col in 0..col_map.total_cols {
            let val = trace.values[padding_start + col];
            assert_eq!(
                val,
                Goldilocks::ZERO,
                "padding row col {} should be zero",
                col
            );
        }
    }

    // -----------------------------------------------------------------------
    // Encoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_u64_zero() {
        let elem = encode_u64(0);
        assert_eq!(elem, Goldilocks::ZERO);
    }

    #[test]
    fn test_encode_u64_one() {
        let elem = encode_u64(1);
        assert_eq!(elem, Goldilocks::ONE);
    }

    #[test]
    fn test_encode_bytes_empty() {
        let elements = encode_bytes_as_field_elements(&[]);
        assert!(elements.is_empty());
    }

    #[test]
    fn test_encode_bytes_small() {
        let elements = encode_bytes_as_field_elements(&[1, 2, 3]);
        assert_eq!(elements.len(), 1);
        // 1 + 2*256 + 3*65536 = 1 + 512 + 196608 = 197121
        let expected = u64::from_le_bytes([1, 2, 3, 0, 0, 0, 0, 0]);
        assert_eq!(elements[0], encode_u64(expected));
    }

    #[test]
    fn test_encode_bytes_multiple_chunks() {
        // 14 bytes → 2 chunks of 7 bytes each.
        let data: Vec<u8> = (0..14).collect();
        let elements = encode_bytes_as_field_elements(&data);
        assert_eq!(elements.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Integration with VselAir column map
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_trace_with_compiled_column_map() {
        let (col_map, _total) = column_map_from_constraint_system();
        let witness = test_witness(2);
        let trace = generate_trace(&witness, &col_map);

        // 2 inputs → padded to 2 (already power of 2).
        assert_eq!(trace.height(), 2);
        assert_eq!(trace.width(), col_map.total_cols);

        // Both rows should have the satisfaction flag set.
        if let Some(&flag_col) = col_map.aux_cols.get("__constraint_satisfaction_flag") {
            for row in 0..2 {
                let val = trace.values[row * col_map.total_cols + flag_col];
                assert_eq!(val, Goldilocks::ONE);
            }
        }
    }

    #[test]
    fn test_generate_trace_large_witness_padding() {
        let witness = test_witness(100);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 100 inputs → padded to 128.
        assert_eq!(trace.height(), 128);

        // Verify all 100 active rows have flag = 1.
        let flag_col = *col_map
            .aux_cols
            .get("__constraint_satisfaction_flag")
            .unwrap();
        for row in 0..100 {
            let val = trace.values[row * col_map.total_cols + flag_col];
            assert_eq!(val, Goldilocks::ONE);
        }

        // Verify padding rows (100..128) have flag = 0.
        for row in 100..128 {
            let val = trace.values[row * col_map.total_cols + flag_col];
            assert_eq!(val, Goldilocks::ZERO);
        }
    }

    // -----------------------------------------------------------------------
    // Witness column filling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_witness_columns_filled_from_input() {
        // Create a column map with input-specific witness columns.
        let mut witness_cols = HashMap::new();
        witness_cols.insert("input_payload_0".to_string(), 0);
        witness_cols.insert("input_nonce".to_string(), 1);

        let mut aux_cols = HashMap::new();
        aux_cols.insert("__constraint_satisfaction_flag".to_string(), 2);

        let col_map = ColumnMap {
            witness_cols,
            public_cols: HashMap::new(),
            aux_cols,
            total_cols: 3,
        };

        let witness = test_witness(1);
        let trace = generate_trace(&witness, &col_map);

        // input_nonce should be 1 (first input's nonce).
        let nonce_val = trace.values[1]; // col 1
        assert_eq!(nonce_val, encode_u64(1));

        // input_payload_0 should be non-zero (encoded from payload data).
        let payload_val = trace.values[0]; // col 0
        assert_ne!(payload_val, Goldilocks::ZERO);
    }

    // -----------------------------------------------------------------------
    // Auxiliary column filling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auxiliary_columns_filled() {
        let mut aux_cols = HashMap::new();
        aux_cols.insert("post_commitment_0".to_string(), 0);
        aux_cols.insert("chain_hash_0".to_string(), 1);
        aux_cols.insert("__constraint_satisfaction_flag".to_string(), 2);

        let col_map = ColumnMap {
            witness_cols: HashMap::new(),
            public_cols: HashMap::new(),
            aux_cols,
            total_cols: 3,
        };

        let witness = test_witness(1);
        let trace = generate_trace(&witness, &col_map);

        // post_commitment_0 should be non-zero (filled from aux data).
        let post_val = trace.values[0]; // col 0
        assert_ne!(post_val, Goldilocks::ZERO);

        // chain_hash_0 should be non-zero.
        let chain_val = trace.values[1]; // col 1
        assert_ne!(chain_val, Goldilocks::ZERO);
    }

    // -----------------------------------------------------------------------
    // Matrix structure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trace_matrix_total_elements() {
        let witness = test_witness(3);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        // 4 rows × 4 cols = 16 elements.
        assert_eq!(trace.values.len(), 4 * 4);
    }

    #[test]
    fn test_trace_matrix_width_matches_column_map() {
        let witness = test_witness(2);
        let col_map = test_column_map();
        let trace = generate_trace(&witness, &col_map);

        assert_eq!(trace.width(), col_map.total_cols);
    }
}
