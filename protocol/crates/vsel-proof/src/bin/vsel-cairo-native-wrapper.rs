//! VSEL-aware native Cairo/STARK wrapper.
//!
//! The binary implements the command protocol consumed by `CommandCairoAdapter`.
//! It does not prove or verify by inspection of a VCAI envelope. It first binds
//! configured Cairo artifacts by SHA3-256, executes the configured native
//! verifier, and only then emits either canonical VCAI/v1 proof bytes or a
//! verifier certificate.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Sha3_256};
use vsel_core::types::Hash;
use vsel_proof::cairo_stark::{
    CairoExpectedStatement, CairoProgramCommitments, CairoStarkProof, CairoStatement,
    CairoVerifierCertificate,
};

const PROVE_HEADER: &str = "VSEL_CAIRO_PROVE_REQUEST_V1";
const VERIFY_HEADER: &str = "VSEL_CAIRO_VERIFY_REQUEST_V1";
const CERTIFICATE_HEADER: &str = "VSEL_CAIRO_VERIFIER_CERTIFICATE_V1";
const NATIVE_ATTESTATION_HEADER: &str = "VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1";
const SOURCE_MANIFEST_HEADER: &str = "VSEL_CAIRO_SOURCE_MANIFEST_V1";
const SEMANTIC_BINDING_HEADER: &str = "VSEL_CAIRO_SEMANTIC_BINDING_V1";

const ENV_NATIVE_PROVE_COMMAND: &str = "VSEL_CAIRO_NATIVE_PROVE_COMMAND";
const ENV_NATIVE_VERIFY_COMMAND: &str = "VSEL_CAIRO_NATIVE_VERIFY_COMMAND";
const ENV_NATIVE_WORKDIR: &str = "VSEL_CAIRO_NATIVE_WORKDIR";
const ENV_NATIVE_PROOF_PATH: &str = "VSEL_CAIRO_NATIVE_PROOF_PATH";
const ENV_NATIVE_TRACE_PATH: &str = "VSEL_CAIRO_NATIVE_TRACE_PATH";

const ENV_CAIRO_PROGRAM_PATH: &str = "VSEL_CAIRO_PROGRAM_PATH";
const ENV_SIERRA_PROGRAM_PATH: &str = "VSEL_CAIRO_SIERRA_PROGRAM_PATH";
const ENV_CASM_PROGRAM_PATH: &str = "VSEL_CAIRO_CASM_PROGRAM_PATH";
const ENV_EXECUTABLE_PROGRAM_PATH: &str = "VSEL_CAIRO_EXECUTABLE_PROGRAM_PATH";
const ENV_SEMANTIC_BINDING_PATH: &str = "VSEL_CAIRO_SEMANTIC_BINDING_PATH";

const ENV_VERIFIER_VERSION: &str = "VSEL_CAIRO_NATIVE_VERIFIER_VERSION";
const ENV_VERIFIER_HASH: &str = "VSEL_CAIRO_ADAPTER_VERIFIER_SHA3_256";

fn main() {
    if let Err(err) = run() {
        eprintln!("vsel-cairo-native-wrapper: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| format!("failed to read request from stdin: {}", e))?;

    let request = Request::parse(&stdin)?;
    match request.header.as_str() {
        PROVE_HEADER => prove(request),
        VERIFY_HEADER => verify(request),
        other => Err(format!("unsupported VSEL Cairo request header {}", other)),
    }
}

fn prove(request: Request) -> Result<(), String> {
    let expected = expected_from_request(&request)?;
    validate_program_artifacts(&expected.program)?;

    if env::var(ENV_NATIVE_PROVE_COMMAND).is_ok() {
        run_native_command_without_proof(ENV_NATIVE_PROVE_COMMAND, &expected, &request)?;
    }

    let trace_hash = hash_required_file(ENV_NATIVE_TRACE_PATH)?;
    let proof_bytes = read_required_file(ENV_NATIVE_PROOF_PATH)?;
    if proof_bytes.is_empty() {
        return Err(format!("{} must not be empty", ENV_NATIVE_PROOF_PATH));
    }

    let statement = CairoStatement::from_expected(&expected, trace_hash.clone());
    let statement_hash = statement.hash();
    let proof_hash = hash_domain_bytes(b"vsel-cairo-proof-bytes-v1", &proof_bytes);
    let native_context = run_native_verify(&proof_bytes, &statement, &proof_hash)?;
    let certificate = build_certificate(
        &statement,
        &statement_hash,
        &proof_hash,
        &proof_bytes,
        &native_context,
    )?;

    let proof = CairoStarkProof::new(
        expected.backend_id,
        expected.program,
        trace_hash,
        expected.public_input_hash,
        expected.constraint_commitment,
        proof_bytes,
        certificate,
    )
    .map_err(|e| format!("failed to construct canonical VCAI/v1 proof: {}", e))?;

    println!("proof_hex={}", hex_encode(&proof.to_bytes()));
    Ok(())
}

fn verify(request: Request) -> Result<(), String> {
    let expected = expected_from_request(&request)?;
    validate_program_artifacts(&expected.program)?;

    let proof_hex = request.required("proof_hex")?;
    let proof_bytes = hex_decode(proof_hex)?;
    let proof = CairoStarkProof::from_bytes(&proof_bytes)
        .map_err(|e| format!("invalid VCAI/v1 proof artifact: {}", e))?;
    proof
        .validate_against(&expected)
        .map_err(|e| format!("VCAI/v1 proof does not match verify request: {}", e))?;

    require_hash_field(
        &request,
        "statement_hash",
        &proof.statement_hash,
        "verify request statement_hash",
    )?;
    require_hash_field(
        &request,
        "proof_hash",
        &proof.proof_hash,
        "verify request proof_hash",
    )?;

    let trace_hash = hash_required_file(ENV_NATIVE_TRACE_PATH)?;
    if trace_hash != proof.cairo_trace_hash {
        return Err(format!(
            "{} does not match VCAI cairo_trace_hash: expected {}, got {}",
            ENV_NATIVE_TRACE_PATH,
            hex_hash(&proof.cairo_trace_hash),
            hex_hash(&trace_hash)
        ));
    }

    if let Ok(native_proof_path) = env::var(ENV_NATIVE_PROOF_PATH) {
        let configured = fs::read(&native_proof_path).map_err(|e| {
            format!(
                "{} '{}' cannot be read: {}",
                ENV_NATIVE_PROOF_PATH, native_proof_path, e
            )
        })?;
        if configured != proof.proof_bytes {
            return Err(format!(
                "{} bytes do not match embedded VCAI native proof bytes",
                ENV_NATIVE_PROOF_PATH
            ));
        }
    }

    let statement = CairoStatement::from_expected(&expected, proof.cairo_trace_hash.clone());
    let native_context = run_native_verify(&proof.proof_bytes, &statement, &proof.proof_hash)?;
    let certificate = build_certificate(
        &statement,
        &proof.statement_hash,
        &proof.proof_hash,
        &proof.proof_bytes,
        &native_context,
    )?;

    print!("{}", format_certificate(&certificate));
    Ok(())
}

#[derive(Debug)]
struct Request {
    header: String,
    fields: BTreeMap<String, String>,
}

impl Request {
    fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        let header = lines
            .next()
            .ok_or_else(|| "empty VSEL Cairo request".to_string())?
            .trim()
            .to_string();
        if header.is_empty() {
            return Err("empty VSEL Cairo request header".to_string());
        }

        let mut fields = BTreeMap::new();
        let mut saw_end = false;
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == "END" {
                saw_end = true;
                break;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("malformed request line '{}'", line));
            };
            if key.is_empty() || value.is_empty() {
                return Err(format!("malformed empty key/value in line '{}'", line));
            }
            if fields.insert(key.to_string(), value.to_string()).is_some() {
                return Err(format!("duplicate request field {}", key));
            }
        }

        if !saw_end {
            return Err("request missing END marker".to_string());
        }

        Ok(Self { header, fields })
    }

    fn required(&self, key: &str) -> Result<&str, String> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing request field {}", key))
    }
}

fn expected_from_request(request: &Request) -> Result<CairoExpectedStatement, String> {
    Ok(CairoExpectedStatement {
        backend_id: request.required("backend_id")?.to_string(),
        program: CairoProgramCommitments {
            cairo_program_hash: parse_hash_hex(request.required("cairo_program_hash")?)?,
            sierra_program_hash: parse_hash_hex(request.required("sierra_program_hash")?)?,
            casm_program_hash: parse_hash_hex(request.required("casm_program_hash")?)?,
            executable_program_hash: parse_hash_hex(request.required("executable_program_hash")?)?,
            semantic_binding_hash: parse_hash_hex(request.required("semantic_binding_hash")?)?,
        },
        public_input_hash: parse_hash_hex(request.required("public_input_hash")?)?,
        constraint_commitment: parse_hash_hex(request.required("constraint_commitment")?)?,
    })
}

fn validate_program_artifacts(program: &CairoProgramCommitments) -> Result<(), String> {
    require_file_hash(
        ENV_CAIRO_PROGRAM_PATH,
        &program.cairo_program_hash,
        "cairo_program_hash",
    )?;
    validate_cairo_source_manifest_artifact()?;
    require_file_hash(
        ENV_SIERRA_PROGRAM_PATH,
        &program.sierra_program_hash,
        "sierra_program_hash",
    )?;
    require_file_hash(
        ENV_CASM_PROGRAM_PATH,
        &program.casm_program_hash,
        "casm_program_hash",
    )?;
    require_file_hash(
        ENV_EXECUTABLE_PROGRAM_PATH,
        &program.executable_program_hash,
        "executable_program_hash",
    )?;
    require_file_hash(
        ENV_SEMANTIC_BINDING_PATH,
        &program.semantic_binding_hash,
        "semantic_binding_hash",
    )?;
    validate_cairo_semantic_binding_artifact()?;
    Ok(())
}

fn validate_cairo_source_manifest_artifact() -> Result<(), String> {
    let path = env::var(ENV_CAIRO_PROGRAM_PATH)
        .map_err(|_| format!("missing required {}", ENV_CAIRO_PROGRAM_PATH))?;
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "{} '{}' cannot be read as canonical Cairo source manifest: {}",
            ENV_CAIRO_PROGRAM_PATH, path, e
        )
    })?;

    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default().trim();
    if header != SOURCE_MANIFEST_HEADER {
        return Err(format!(
            "{} must start with {}",
            ENV_CAIRO_PROGRAM_PATH, SOURCE_MANIFEST_HEADER
        ));
    }

    let mut seen = BTreeMap::<String, ()>::new();
    let mut entries = 0usize;
    let mut has_semantic_core = false;
    let mut has_executable = false;
    let mut has_lockfile = false;

    for (index, raw_line) in lines.enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let path = parts.next().unwrap_or_default();
        let digest = parts.next().unwrap_or_default();
        if path.is_empty() || digest.is_empty() || parts.next().is_some() {
            return Err(format!(
                "malformed Cairo source manifest entry at line {}",
                index + 2
            ));
        }
        validate_manifest_path(path, index + 2)?;
        parse_hash_hex(digest).map_err(|e| {
            format!(
                "invalid Cairo source manifest digest at line {}: {}",
                index + 2,
                e
            )
        })?;
        if seen.insert(path.to_string(), ()).is_some() {
            return Err(format!("duplicate Cairo source manifest path {}", path));
        }

        entries += 1;
        has_semantic_core |= path.starts_with("semantic_core/");
        has_executable |= path.starts_with("executable/");
        has_lockfile |= path.ends_with("Scarb.lock");
    }

    if entries == 0 {
        return Err("Cairo source manifest must contain at least one entry".to_string());
    }
    if !has_semantic_core {
        return Err("Cairo source manifest must bind semantic_core sources".to_string());
    }
    if !has_executable {
        return Err("Cairo source manifest must bind executable proof-target sources".to_string());
    }
    if !has_lockfile {
        return Err("Cairo source manifest must bind Scarb.lock dependency resolution".to_string());
    }

    Ok(())
}

fn validate_manifest_path(path: &str, line_number: usize) -> Result<(), String> {
    if path.starts_with('/') || path.contains("..") || path.contains('\\') {
        return Err(format!(
            "unsafe Cairo source manifest path '{}' at line {}",
            path, line_number
        ));
    }
    if !path
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "Cairo source manifest path '{}' at line {} contains unsupported characters",
            path, line_number
        ));
    }
    Ok(())
}

fn validate_cairo_semantic_binding_artifact() -> Result<(), String> {
    let path = env::var(ENV_SEMANTIC_BINDING_PATH)
        .map_err(|_| format!("missing required {}", ENV_SEMANTIC_BINDING_PATH))?;
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "{} '{}' cannot be read as canonical Cairo semantic binding report: {}",
            ENV_SEMANTIC_BINDING_PATH, path, e
        )
    })?;

    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default().trim();
    if header != SEMANTIC_BINDING_HEADER {
        return Err(format!(
            "{} must start with {}",
            ENV_SEMANTIC_BINDING_PATH, SEMANTIC_BINDING_HEADER
        ));
    }

    let mut fields = BTreeMap::<String, String>::new();
    for (index, raw_line) in lines.enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "malformed Cairo semantic binding entry at line {}",
                index + 2
            ));
        };
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "empty Cairo semantic binding key/value at line {}",
                index + 2
            ));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate Cairo semantic binding field {}", key));
        }
    }

    for key in ["semantic_core", "contract_wrapper", "executable_entrypoint"] {
        let value = fields
            .get(key)
            .ok_or_else(|| format!("Cairo semantic binding missing field {}", key))?;
        validate_semantic_binding_file_field(key, value)?;
    }

    for key in [
        "core_apply_transition",
        "core_seal_transition",
        "core_invariant_predicate",
        "contract_uses_core_apply",
        "contract_uses_core_seal",
        "contract_uses_core_invariant",
        "executable_uses_core_apply",
    ] {
        let value = fields
            .get(key)
            .ok_or_else(|| format!("Cairo semantic binding missing field {}", key))?;
        if value != "true" {
            return Err(format!("Cairo semantic binding {} must be true", key));
        }
    }

    Ok(())
}

fn validate_semantic_binding_file_field(key: &str, value: &str) -> Result<(), String> {
    let mut parts = value.split_whitespace();
    let path = parts.next().unwrap_or_default();
    let digest = parts.next().unwrap_or_default();
    if path.is_empty() || digest.is_empty() || parts.next().is_some() {
        return Err(format!(
            "Cairo semantic binding field {} must contain '<path> <sha3-256>'",
            key
        ));
    }
    validate_manifest_path(path, 0)?;
    parse_hash_hex(digest)
        .map_err(|e| format!("Cairo semantic binding {} has invalid digest: {}", key, e))?;
    Ok(())
}

fn require_file_hash(env_key: &str, expected: &Hash, label: &str) -> Result<(), String> {
    let actual = hash_required_file(env_key)?;
    if &actual != expected {
        return Err(format!(
            "{} mismatch from {}: expected {}, got {}",
            label,
            env_key,
            hex_hash(expected),
            hex_hash(&actual)
        ));
    }
    Ok(())
}

fn require_hash_field(
    request: &Request,
    key: &str,
    expected: &Hash,
    label: &str,
) -> Result<(), String> {
    let actual = parse_hash_hex(request.required(key)?)?;
    if &actual != expected {
        return Err(format!(
            "{} mismatch: expected {}, got {}",
            label,
            hex_hash(expected),
            hex_hash(&actual)
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct NativeCommandContext {
    verify_command: String,
    workdir: Option<String>,
}

fn run_native_verify(
    proof_bytes: &[u8],
    statement: &CairoStatement,
    proof_hash: &Hash,
) -> Result<NativeCommandContext, String> {
    let verify_command = env::var(ENV_NATIVE_VERIFY_COMMAND)
        .map_err(|_| format!("missing required {}", ENV_NATIVE_VERIFY_COMMAND))?;
    if verify_command.trim().is_empty() {
        return Err(format!("{} must not be empty", ENV_NATIVE_VERIFY_COMMAND));
    }
    let workdir = env::var(ENV_NATIVE_WORKDIR).ok();
    let temp_proof = write_temp_proof(proof_bytes)?;

    let output = {
        let mut command = Command::new("sh");
        command.arg("-c").arg(&verify_command);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        if let Some(workdir) = &workdir {
            command.current_dir(workdir);
        }
        set_statement_env(&mut command, statement, proof_hash);
        command.env("VSEL_CAIRO_REQUEST_PROOF_PATH", &temp_proof);
        command.output()
    };

    let remove_result = fs::remove_file(&temp_proof);
    let output = output.map_err(|e| format!("failed to execute native verifier: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "native verifier rejected proof with status {}; stdout='{}'; stderr='{}'",
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    require_native_context_attestation(&stdout, statement, proof_hash)?;
    if let Err(err) = remove_result {
        return Err(format!(
            "native verifier accepted proof but temporary proof cleanup failed: {}",
            err
        ));
    }

    Ok(NativeCommandContext {
        verify_command,
        workdir,
    })
}

fn require_native_context_attestation(
    stdout: &str,
    statement: &CairoStatement,
    proof_hash: &Hash,
) -> Result<(), String> {
    let attestation = parse_native_attestation(stdout)?;
    require_attested_value(&attestation, "backend_id", &statement.backend_id)?;
    require_attested_hash(
        &attestation,
        "cairo_program_hash",
        &statement.program.cairo_program_hash,
    )?;
    require_attested_hash(
        &attestation,
        "sierra_program_hash",
        &statement.program.sierra_program_hash,
    )?;
    require_attested_hash(
        &attestation,
        "casm_program_hash",
        &statement.program.casm_program_hash,
    )?;
    require_attested_hash(
        &attestation,
        "executable_program_hash",
        &statement.program.executable_program_hash,
    )?;
    require_attested_hash(
        &attestation,
        "semantic_binding_hash",
        &statement.program.semantic_binding_hash,
    )?;
    require_attested_hash(
        &attestation,
        "cairo_trace_hash",
        &statement.cairo_trace_hash,
    )?;
    require_attested_hash(
        &attestation,
        "public_input_hash",
        &statement.public_input_hash,
    )?;
    require_attested_hash(
        &attestation,
        "constraint_commitment",
        &statement.constraint_commitment,
    )?;
    require_attested_hash(&attestation, "statement_hash", &statement.hash())?;
    require_attested_hash(&attestation, "proof_hash", proof_hash)?;
    require_attested_value(&attestation, "accepted", "true")?;
    Ok(())
}

fn parse_native_attestation(stdout: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    let mut saw_header = false;
    let mut saw_end = false;
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if !saw_header {
            if line == NATIVE_ATTESTATION_HEADER {
                saw_header = true;
            }
            continue;
        }
        if line == "END" {
            saw_end = true;
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "malformed native context attestation line '{}'",
                line
            ));
        };
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "empty key/value in native context attestation line '{}'",
                line
            ));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!(
                "duplicate native context attestation field {}",
                key
            ));
        }
    }

    if !saw_header {
        return Err(format!(
            "native verifier output missing {}",
            NATIVE_ATTESTATION_HEADER
        ));
    }
    if !saw_end {
        return Err("native verifier context attestation missing END marker".to_string());
    }
    Ok(fields)
}

fn require_attested_value(
    fields: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let actual = fields
        .get(key)
        .ok_or_else(|| format!("native context attestation missing field {}", key))?;
    if actual != expected {
        return Err(format!(
            "native context attestation {} mismatch: expected {}, got {}",
            key, expected, actual
        ));
    }
    Ok(())
}

fn require_attested_hash(
    fields: &BTreeMap<String, String>,
    key: &str,
    expected: &Hash,
) -> Result<(), String> {
    let actual = fields
        .get(key)
        .ok_or_else(|| format!("native context attestation missing field {}", key))
        .and_then(|value| parse_hash_hex(value))?;
    if &actual != expected {
        return Err(format!(
            "native context attestation {} mismatch: expected {}, got {}",
            key,
            hex_hash(expected),
            hex_hash(&actual)
        ));
    }
    Ok(())
}

fn run_native_command_without_proof(
    env_key: &str,
    expected: &CairoExpectedStatement,
    request: &Request,
) -> Result<(), String> {
    let command_text = env::var(env_key).map_err(|_| format!("missing {}", env_key))?;
    if command_text.trim().is_empty() {
        return Err(format!("{} must not be empty", env_key));
    }
    let mut command = Command::new("sh");
    command.arg("-c").arg(&command_text);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if let Ok(workdir) = env::var(ENV_NATIVE_WORKDIR) {
        command.current_dir(workdir);
    }
    set_expected_env(&mut command, expected);
    for key in ["witness_commitment", "constraint_system_commitment"] {
        if let Some(value) = request.fields.get(key) {
            command.env(
                format!("VSEL_CAIRO_REQUEST_{}", key.to_ascii_uppercase()),
                value,
            );
        }
    }

    let output = command
        .output()
        .map_err(|e| format!("failed to execute native prover command: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "native prover command failed with status {}; stdout='{}'; stderr='{}'",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn set_expected_env(command: &mut Command, expected: &CairoExpectedStatement) {
    command.env("VSEL_CAIRO_REQUEST_BACKEND_ID", &expected.backend_id);
    command.env(
        "VSEL_CAIRO_REQUEST_CAIRO_PROGRAM_HASH",
        hex_hash(&expected.program.cairo_program_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_SIERRA_PROGRAM_HASH",
        hex_hash(&expected.program.sierra_program_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_CASM_PROGRAM_HASH",
        hex_hash(&expected.program.casm_program_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_EXECUTABLE_PROGRAM_HASH",
        hex_hash(&expected.program.executable_program_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_SEMANTIC_BINDING_HASH",
        hex_hash(&expected.program.semantic_binding_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_PUBLIC_INPUT_HASH",
        hex_hash(&expected.public_input_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_CONSTRAINT_COMMITMENT",
        hex_hash(&expected.constraint_commitment),
    );
}

fn set_statement_env(command: &mut Command, statement: &CairoStatement, proof_hash: &Hash) {
    set_expected_env(
        command,
        &CairoExpectedStatement {
            backend_id: statement.backend_id.clone(),
            program: statement.program.clone(),
            public_input_hash: statement.public_input_hash.clone(),
            constraint_commitment: statement.constraint_commitment.clone(),
        },
    );
    command.env(
        "VSEL_CAIRO_REQUEST_CAIRO_TRACE_HASH",
        hex_hash(&statement.cairo_trace_hash),
    );
    command.env(
        "VSEL_CAIRO_REQUEST_STATEMENT_HASH",
        hex_hash(&statement.hash()),
    );
    command.env("VSEL_CAIRO_REQUEST_PROOF_HASH", hex_hash(proof_hash));
}

fn write_temp_proof(proof_bytes: &[u8]) -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before UNIX_EPOCH: {}", e))?
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "vsel-cairo-native-proof-{}-{}.bin",
        std::process::id(),
        nanos
    ));
    let mut file = fs::File::create(&path)
        .map_err(|e| format!("failed to create temporary native proof file: {}", e))?;
    file.write_all(proof_bytes)
        .map_err(|e| format!("failed to write temporary native proof file: {}", e))?;
    Ok(path)
}

#[derive(Debug)]
struct AdapterIdentity {
    adapter_id: String,
    verifier_version: String,
    verifier_binary_hash: Hash,
}

fn adapter_identity(backend_id: &str) -> Result<AdapterIdentity, String> {
    let adapter_id = backend_id
        .strip_prefix("cairo-stark/")
        .ok_or_else(|| {
            format!(
                "backend_id '{}' must use concrete cairo-stark/<adapter-id>",
                backend_id
            )
        })?
        .to_string();
    if adapter_id.is_empty() {
        return Err("adapter id must not be empty".to_string());
    }

    let parsed_version = parse_version_from_adapter_id(&adapter_id);
    let verifier_version = match (env::var(ENV_VERIFIER_VERSION).ok(), parsed_version) {
        (Some(configured), Some(parsed)) if configured != parsed => {
            return Err(format!(
                "{} '{}' does not match adapter id version '{}'",
                ENV_VERIFIER_VERSION, configured, parsed
            ));
        }
        (Some(configured), _) => configured,
        (None, Some(parsed)) => parsed,
        (None, None) => {
            return Err(format!(
                "cannot derive verifier version from adapter id {}; set {}",
                adapter_id, ENV_VERIFIER_VERSION
            ));
        }
    };

    let parsed_hash = parse_verifier_hash_from_adapter_id(&adapter_id)?;
    let verifier_binary_hash = match (env::var(ENV_VERIFIER_HASH).ok(), parsed_hash) {
        (Some(configured), Some(parsed)) => {
            let configured_hash = parse_hash_hex(&configured)?;
            if configured_hash != parsed {
                return Err(format!(
                    "{} does not match verifier hash encoded in adapter id",
                    ENV_VERIFIER_HASH
                ));
            }
            configured_hash
        }
        (Some(configured), None) => parse_hash_hex(&configured)?,
        (None, Some(parsed)) => parsed,
        (None, None) => {
            return Err(format!(
                "cannot derive verifier binary hash from adapter id {}; set {}",
                adapter_id, ENV_VERIFIER_HASH
            ));
        }
    };

    Ok(AdapterIdentity {
        adapter_id,
        verifier_version,
        verifier_binary_hash,
    })
}

fn parse_version_from_adapter_id(adapter_id: &str) -> Option<String> {
    for prefix in ["stone-", "stwo-", "scarb-"] {
        if let Some(rest) = adapter_id.strip_prefix(prefix) {
            if let Some((version, _)) = rest.split_once("-prover-") {
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    None
}

fn parse_verifier_hash_from_adapter_id(adapter_id: &str) -> Result<Option<Hash>, String> {
    let Some((_, hash_hex)) = adapter_id.rsplit_once("-verifier-") else {
        return Ok(None);
    };
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "verifier hash in adapter id must be a 64-character SHA3-256 hex digest: {}",
            hash_hex
        ));
    }
    Ok(Some(parse_hash_hex(hash_hex)?))
}

fn build_certificate(
    statement: &CairoStatement,
    statement_hash: &Hash,
    proof_hash: &Hash,
    proof_bytes: &[u8],
    native_context: &NativeCommandContext,
) -> Result<CairoVerifierCertificate, String> {
    let identity = adapter_identity(&statement.backend_id)?;
    let transcript_hash = transcript_hash(
        &identity,
        statement,
        statement_hash,
        proof_hash,
        proof_bytes,
        native_context,
    );

    Ok(CairoVerifierCertificate {
        adapter_id: identity.adapter_id,
        verifier_version: identity.verifier_version,
        verifier_binary_hash: identity.verifier_binary_hash,
        backend_id: statement.backend_id.clone(),
        program: statement.program.clone(),
        cairo_trace_hash: statement.cairo_trace_hash.clone(),
        public_input_hash: statement.public_input_hash.clone(),
        constraint_commitment: statement.constraint_commitment.clone(),
        statement_hash: statement_hash.clone(),
        proof_hash: proof_hash.clone(),
        transcript_hash,
        accepted: true,
    })
}

fn transcript_hash(
    identity: &AdapterIdentity,
    statement: &CairoStatement,
    statement_hash: &Hash,
    proof_hash: &Hash,
    proof_bytes: &[u8],
    native_context: &NativeCommandContext,
) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(b"vsel-cairo-native-wrapper-transcript-v1");
    update_string(&mut hasher, &identity.adapter_id);
    update_string(&mut hasher, &identity.verifier_version);
    update_hash(&mut hasher, &identity.verifier_binary_hash);
    update_string(&mut hasher, &statement.backend_id);
    update_hash(&mut hasher, &statement.program.cairo_program_hash);
    update_hash(&mut hasher, &statement.program.sierra_program_hash);
    update_hash(&mut hasher, &statement.program.casm_program_hash);
    update_hash(&mut hasher, &statement.program.executable_program_hash);
    update_hash(&mut hasher, &statement.program.semantic_binding_hash);
    update_hash(&mut hasher, &statement.cairo_trace_hash);
    update_hash(&mut hasher, &statement.public_input_hash);
    update_hash(&mut hasher, &statement.constraint_commitment);
    update_hash(&mut hasher, statement_hash);
    update_hash(&mut hasher, proof_hash);
    update_hash(&mut hasher, &sha3_256_hash(proof_bytes));
    update_string(&mut hasher, &native_context.verify_command);
    update_string(&mut hasher, native_context.workdir.as_deref().unwrap_or(""));
    finalize_hash(hasher)
}

fn format_certificate(certificate: &CairoVerifierCertificate) -> String {
    format!(
        "{CERTIFICATE_HEADER}\nadapter_id={}\nverifier_version={}\nverifier_binary_hash={}\nbackend_id={}\ncairo_program_hash={}\nsierra_program_hash={}\ncasm_program_hash={}\nexecutable_program_hash={}\nsemantic_binding_hash={}\ncairo_trace_hash={}\npublic_input_hash={}\nconstraint_commitment={}\nstatement_hash={}\nproof_hash={}\ntranscript_hash={}\naccepted={}\n",
        certificate.adapter_id,
        certificate.verifier_version,
        hex_hash(&certificate.verifier_binary_hash),
        certificate.backend_id,
        hex_hash(&certificate.program.cairo_program_hash),
        hex_hash(&certificate.program.sierra_program_hash),
        hex_hash(&certificate.program.casm_program_hash),
        hex_hash(&certificate.program.executable_program_hash),
        hex_hash(&certificate.program.semantic_binding_hash),
        hex_hash(&certificate.cairo_trace_hash),
        hex_hash(&certificate.public_input_hash),
        hex_hash(&certificate.constraint_commitment),
        hex_hash(&certificate.statement_hash),
        hex_hash(&certificate.proof_hash),
        hex_hash(&certificate.transcript_hash),
        if certificate.accepted { "true" } else { "false" },
    )
}

fn read_required_file(env_key: &str) -> Result<Vec<u8>, String> {
    let path = env::var(env_key).map_err(|_| format!("missing required {}", env_key))?;
    fs::read(&path).map_err(|e| format!("{} '{}' cannot be read: {}", env_key, path, e))
}

fn hash_required_file(env_key: &str) -> Result<Hash, String> {
    let bytes = read_required_file(env_key)?;
    Ok(sha3_256_hash(&bytes))
}

fn sha3_256_hash(bytes: &[u8]) -> Hash {
    let digest = Sha3_256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash(out)
}

fn hash_domain_bytes(domain: &[u8], data: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    finalize_hash(hasher)
}

fn update_hash(hasher: &mut Sha3_256, hash: &Hash) {
    hasher.update(&hash.0);
}

fn update_string(hasher: &mut Sha3_256, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn finalize_hash(hasher: Sha3_256) -> Hash {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash(out)
}

fn parse_hash_hex(value: &str) -> Result<Hash, String> {
    let raw = hex_decode(value)?;
    if raw.len() != 32 {
        return Err(format!(
            "hash hex must decode to exactly 32 bytes, got {}",
            raw.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(Hash(out))
}

fn hex_hash(hash: &Hash) -> String {
    hex_encode(&hash.0)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[i])?;
        let low = hex_nibble(bytes[i + 1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_string()),
    }
}
