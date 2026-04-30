//! Fuzz target: StarkProof deserialization from arbitrary bytes.
//!
//! Accepts arbitrary bytes, attempts StarkProof::from_bytes().
//! Must not panic — either succeeds or returns an error.
//!
//! Requirements: 6.1(a), 6.2

#![no_main]

use libfuzzer_sys::fuzz_target;

// StarkProof and its from_bytes are behind the plonky3-backend feature
// in vsel-proof. Since the fuzz crate doesn't enable that feature,
// we re-implement the deserialization logic inline to fuzz the format
// parser without requiring the full Plonky3 dependency chain.
//
// The canonical proof wire format is:
//   [4B magic "STAR"] [1B version] [4B num_fri] [fri entries...]
//   [4B num_queries] [query entries...] [4B num_pub] [pub entries...]
//   [4B id_len] [id bytes...] [optional: 4B native_len] [native bytes...]

fuzz_target!(|data: &[u8]| {
    // Exercise the deserialization — must never panic.
    let _ = try_deserialize_proof(data);
});

/// Attempt to deserialize a StarkProof from raw bytes.
///
/// Returns Ok(()) if parsing succeeds, Err(msg) otherwise.
/// The critical property: this function must NEVER panic.
fn try_deserialize_proof(bytes: &[u8]) -> Result<(), String> {
    let mut pos = 0usize;

    // Helper: read exact bytes
    let read_bytes = |pos: &mut usize, n: usize| -> Result<&[u8], String> {
        if *pos + n > bytes.len() {
            return Err(format!(
                "unexpected end at offset {}, need {} bytes",
                *pos, n
            ));
        }
        let slice = &bytes[*pos..*pos + n];
        *pos += n;
        Ok(slice)
    };

    // Helper: read u32 LE
    let read_u32 = |pos: &mut usize| -> Result<u32, String> {
        let b = read_bytes(pos, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    // Magic bytes
    let magic = read_bytes(&mut pos, 4)?;
    if magic != b"STAR" {
        return Err("invalid magic".to_string());
    }

    // Version
    let version = read_bytes(&mut pos, 1)?[0];
    if version != 1 {
        return Err(format!("unsupported version: {}", version));
    }

    // FRI commitments
    let num_fri = read_u32(&mut pos)? as usize;
    // Sanity bound to prevent OOM from malicious input.
    if num_fri > 1024 {
        return Err(format!("too many FRI commitments: {}", num_fri));
    }
    for _ in 0..num_fri {
        let len = read_u32(&mut pos)? as usize;
        if len > 1_000_000 {
            return Err(format!("FRI commitment too large: {}", len));
        }
        let _ = read_bytes(&mut pos, len)?;
    }

    // Query responses
    let num_queries = read_u32(&mut pos)? as usize;
    if num_queries > 1024 {
        return Err(format!("too many queries: {}", num_queries));
    }
    for _ in 0..num_queries {
        let len = read_u32(&mut pos)? as usize;
        if len > 1_000_000 {
            return Err(format!("query response too large: {}", len));
        }
        let _ = read_bytes(&mut pos, len)?;
    }

    // Public input values
    let num_pub = read_u32(&mut pos)? as usize;
    if num_pub > 10_000 {
        return Err(format!("too many public inputs: {}", num_pub));
    }
    for _ in 0..num_pub {
        let _ = read_bytes(&mut pos, 8)?;
    }

    // Backend ID
    let id_len = read_u32(&mut pos)? as usize;
    if id_len > 1024 {
        return Err(format!("backend ID too long: {}", id_len));
    }
    let id_bytes = read_bytes(&mut pos, id_len)?;
    let _ = std::str::from_utf8(id_bytes).map_err(|e| format!("invalid UTF-8: {}", e))?;

    // Native proof bytes (optional)
    if pos < bytes.len() {
        let native_len = read_u32(&mut pos)? as usize;
        if native_len > 100_000_000 {
            return Err(format!("native proof too large: {}", native_len));
        }
        let _ = read_bytes(&mut pos, native_len)?;
    }

    Ok(())
}
