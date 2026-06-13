#![cfg(feature = "cairo-stark-backend")]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Sha3_256};
use vsel_constraints::ConstraintSystem;
use vsel_core::observable::Observable;
use vsel_core::transition::TransitionClass;
use vsel_core::types::{DomainTag, Hash, OutputEvent, ProtocolVersion};
use vsel_crypto::domain::{domain_hash, proof_tag};
use vsel_proof::backend::ZkBackend;
use vsel_proof::cairo_native::{NativeCairoBackendKind, NativeCairoCommandConfig};
use vsel_proof::cairo_stark::{CairoProgramCommitments, CairoStarkBackend};
use vsel_proof::public_inputs::PublicInputs;
use vsel_proof::witness::{AuxiliaryComputation, Witness};

const ENV_NATIVE_VERIFY_COMMAND: &str = "VSEL_CAIRO_NATIVE_VERIFY_COMMAND";
const ENV_NATIVE_PROOF_PATH: &str = "VSEL_CAIRO_NATIVE_PROOF_PATH";
const ENV_NATIVE_TRACE_PATH: &str = "VSEL_CAIRO_NATIVE_TRACE_PATH";
const ENV_CAIRO_PROGRAM_PATH: &str = "VSEL_CAIRO_PROGRAM_PATH";
const ENV_SIERRA_PROGRAM_PATH: &str = "VSEL_CAIRO_SIERRA_PROGRAM_PATH";
const ENV_CASM_PROGRAM_PATH: &str = "VSEL_CAIRO_CASM_PROGRAM_PATH";
const ENV_EXECUTABLE_PROGRAM_PATH: &str = "VSEL_CAIRO_EXECUTABLE_PROGRAM_PATH";
const ENV_SEMANTIC_BINDING_PATH: &str = "VSEL_CAIRO_SEMANTIC_BINDING_PATH";
const ATTESTING_VERIFY_COMMAND: &str = r#"test -s "$VSEL_CAIRO_REQUEST_PROOF_PATH" && printf 'VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1
backend_id=%s
cairo_program_hash=%s
sierra_program_hash=%s
casm_program_hash=%s
executable_program_hash=%s
semantic_binding_hash=%s
cairo_trace_hash=%s
public_input_hash=%s
constraint_commitment=%s
statement_hash=%s
proof_hash=%s
accepted=true
END
' "$VSEL_CAIRO_REQUEST_BACKEND_ID" "$VSEL_CAIRO_REQUEST_CAIRO_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_SIERRA_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_CASM_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_EXECUTABLE_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_SEMANTIC_BINDING_HASH" "$VSEL_CAIRO_REQUEST_CAIRO_TRACE_HASH" "$VSEL_CAIRO_REQUEST_PUBLIC_INPUT_HASH" "$VSEL_CAIRO_REQUEST_CONSTRAINT_COMMITMENT" "$VSEL_CAIRO_REQUEST_STATEMENT_HASH" "$VSEL_CAIRO_REQUEST_PROOF_HASH""#;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn native_wrapper_packages_vcai_only_after_native_acceptance() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_source_manifest_artifact(&temp);
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_semantic_binding_artifact(&temp);
    let native_proof = write_artifact(&temp, "proof.json", b"accepted native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"accepted native trace");

    let _guard = EnvGuard::set(&[
        (ENV_NATIVE_VERIFY_COMMAND, ATTESTING_VERIFY_COMMAND),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let constraint_version = "native-wrapper-test";
    let constraints = ConstraintSystem::new(constraint_version);
    let witness = Witness {
        intermediate_states: Vec::new(),
        input_sequence: Vec::new(),
        aux_computation: AuxiliaryComputation::empty(),
    };
    let public_inputs = public_inputs();

    let proof = CairoStarkBackend::new(
        program.clone(),
        config.clone().into_adapter().expect("native adapter"),
    )
    .prove(&witness, &constraints, &public_inputs)
    .expect("wrapper must package verified native proof as VCAI/v1");

    assert!(proof.backend_id.starts_with("cairo-stark/scarb-2.16.0-"));
    assert_eq!(
        proof.verifier_certificate.adapter_id,
        proof.backend_id.trim_start_matches("cairo-stark/")
    );
    assert_eq!(proof.verifier_certificate.verifier_version, "2.16.0");

    let verifier = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"));
    let commitment = empty_constraint_commitment(constraint_version);
    assert!(
        verifier.verify(&proof, &public_inputs, &commitment),
        "wrapper verifier certificate must match packaged VCAI/v1 proof"
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn native_wrapper_fails_closed_when_native_verifier_rejects() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper-reject");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_source_manifest_artifact(&temp);
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_semantic_binding_artifact(&temp);
    let native_proof = write_artifact(&temp, "proof.json", b"rejected native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"native trace");

    let _guard = EnvGuard::set(&[
        (ENV_NATIVE_VERIFY_COMMAND, "false"),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let err = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"))
        .prove(
            &Witness {
                intermediate_states: Vec::new(),
                input_sequence: Vec::new(),
                aux_computation: AuxiliaryComputation::empty(),
            },
            &ConstraintSystem::new("native-wrapper-test"),
            &public_inputs(),
        )
        .expect_err("native verifier rejection must block VCAI/v1 packaging");

    assert!(
        err.to_string().contains("native verifier rejected proof"),
        "unexpected wrapper error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn native_wrapper_rejects_malformed_cairo_source_manifest() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper-bad-source-manifest");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_artifact(&temp, "cairo-source-manifest.txt", b"not a manifest\n");
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_semantic_binding_artifact(&temp);
    let native_proof = write_artifact(&temp, "proof.json", b"accepted native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"accepted native trace");

    let _guard = EnvGuard::set(&[
        (ENV_NATIVE_VERIFY_COMMAND, ATTESTING_VERIFY_COMMAND),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let err = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"))
        .prove(
            &Witness {
                intermediate_states: Vec::new(),
                input_sequence: Vec::new(),
                aux_computation: AuxiliaryComputation::empty(),
            },
            &ConstraintSystem::new("native-wrapper-test"),
            &public_inputs(),
        )
        .expect_err("malformed Cairo source manifest must fail before VCAI/v1 packaging");

    assert!(
        err.to_string().contains("VSEL_CAIRO_SOURCE_MANIFEST_V1"),
        "unexpected wrapper error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn native_wrapper_rejects_malformed_cairo_semantic_binding() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper-bad-semantic-binding");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_source_manifest_artifact(&temp);
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_artifact(&temp, "cairo-semantic-binding.txt", b"not a binding\n");
    let native_proof = write_artifact(&temp, "proof.json", b"accepted native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"accepted native trace");

    let _guard = EnvGuard::set(&[
        (ENV_NATIVE_VERIFY_COMMAND, ATTESTING_VERIFY_COMMAND),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let err = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"))
        .prove(
            &Witness {
                intermediate_states: Vec::new(),
                input_sequence: Vec::new(),
                aux_computation: AuxiliaryComputation::empty(),
            },
            &ConstraintSystem::new("native-wrapper-test"),
            &public_inputs(),
        )
        .expect_err("malformed Cairo semantic binding must fail before VCAI/v1 packaging");

    assert!(
        err.to_string().contains("VSEL_CAIRO_SEMANTIC_BINDING_V1"),
        "unexpected wrapper error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn native_wrapper_rejects_native_acceptance_without_context_attestation() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper-missing-attestation");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_source_manifest_artifact(&temp);
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_semantic_binding_artifact(&temp);
    let native_proof = write_artifact(&temp, "proof.json", b"accepted native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"accepted native trace");

    let _guard = EnvGuard::set(&[
        (
            ENV_NATIVE_VERIFY_COMMAND,
            "test -s \"$VSEL_CAIRO_REQUEST_PROOF_PATH\"",
        ),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let err = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"))
        .prove(
            &Witness {
                intermediate_states: Vec::new(),
                input_sequence: Vec::new(),
                aux_computation: AuxiliaryComputation::empty(),
            },
            &ConstraintSystem::new("native-wrapper-test"),
            &public_inputs(),
        )
        .expect_err("native verifier output without VSEL context attestation must fail closed");

    assert!(
        err.to_string()
            .contains("native verifier output missing VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1"),
        "unexpected wrapper error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn native_wrapper_rejects_mismatched_native_context_attestation() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("native-wrapper-bad-attestation");
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program = write_source_manifest_artifact(&temp);
    let sierra_program = write_artifact(&temp, "program.sierra.json", b"sierra artifact");
    let casm_program = write_artifact(&temp, "program.casm.json", b"casm artifact");
    let executable_program = write_artifact(&temp, "program.executable.json", b"exec artifact");
    let semantic_binding = write_semantic_binding_artifact(&temp);
    let native_proof = write_artifact(&temp, "proof.json", b"accepted native proof");
    let native_trace = write_artifact(&temp, "prover_input.json", b"accepted native trace");
    let bad_attestation = ATTESTING_VERIFY_COMMAND.replace(
        "proof_hash=%s",
        "proof_hash=0000000000000000000000000000000000000000000000000000000000000000",
    );

    let _guard = EnvGuard::set(&[
        (ENV_NATIVE_VERIFY_COMMAND, bad_attestation.as_str()),
        (
            ENV_NATIVE_PROOF_PATH,
            native_proof.to_str().expect("proof path"),
        ),
        (
            ENV_NATIVE_TRACE_PATH,
            native_trace.to_str().expect("trace path"),
        ),
        (
            ENV_CAIRO_PROGRAM_PATH,
            cairo_program.to_str().expect("program path"),
        ),
        (
            ENV_SIERRA_PROGRAM_PATH,
            sierra_program.to_str().expect("sierra path"),
        ),
        (
            ENV_CASM_PROGRAM_PATH,
            casm_program.to_str().expect("casm path"),
        ),
        (
            ENV_EXECUTABLE_PROGRAM_PATH,
            executable_program.to_str().expect("executable path"),
        ),
        (
            ENV_SEMANTIC_BINDING_PATH,
            semantic_binding.to_str().expect("semantic binding path"),
        ),
    ]);

    let program = CairoProgramCommitments::new(
        sha3_256_file(&cairo_program),
        sha3_256_file(&sierra_program),
        sha3_256_file(&casm_program),
        sha3_256_file(&executable_program),
        sha3_256_file(&semantic_binding),
    );
    let config = NativeCairoCommandConfig {
        kind: NativeCairoBackendKind::Scarb,
        version: "2.16.0".to_string(),
        prover_command: wrapper.clone(),
        prover_sha3_256: wrapper_hash.clone(),
        verifier_command: wrapper,
        verifier_sha3_256: wrapper_hash,
    };

    let err = CairoStarkBackend::new(program, config.into_adapter().expect("native adapter"))
        .prove(
            &Witness {
                intermediate_states: Vec::new(),
                input_sequence: Vec::new(),
                aux_computation: AuxiliaryComputation::empty(),
            },
            &ConstraintSystem::new("native-wrapper-test"),
            &public_inputs(),
        )
        .expect_err("native verifier context attestation mismatch must fail closed");

    assert!(
        err.to_string()
            .contains("native context attestation proof_hash mismatch"),
        "unexpected wrapper error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

fn public_inputs() -> PublicInputs {
    PublicInputs {
        root_init: Hash([0x10; 32]),
        root_final: Hash([0x11; 32]),
        observables: vec![Observable {
            transition_class: TransitionClass::Update,
            outputs: vec![OutputEvent {
                event_type: "native_wrapper_event".to_string(),
                data: vec![1, 2, 3],
            }],
            gas_used: 777,
            status: vsel_core::observable::TransitionStatus::Success,
        }],
        domain: DomainTag(Hash([0x12; 32])),
        version: ProtocolVersion::default(),
    }
}

fn write_artifact(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write artifact");
    path
}

fn write_source_manifest_artifact(dir: &Path) -> PathBuf {
    write_artifact(
        dir,
        "cairo-source-manifest.txt",
        deterministic_source_manifest().as_bytes(),
    )
}

fn write_semantic_binding_artifact(dir: &Path) -> PathBuf {
    write_artifact(
        dir,
        "cairo-semantic-binding.txt",
        deterministic_semantic_binding().as_bytes(),
    )
}

fn deterministic_source_manifest() -> String {
    [
        "VSEL_CAIRO_SOURCE_MANIFEST_V1",
        "Scarb.lock 1111111111111111111111111111111111111111111111111111111111111111",
        "semantic_core/src/lib.cairo 2222222222222222222222222222222222222222222222222222222222222222",
        "src/reference_contract.cairo 3333333333333333333333333333333333333333333333333333333333333333",
        "executable/src/lib.cairo 4444444444444444444444444444444444444444444444444444444444444444",
        "",
    ]
    .join("\n")
}

fn deterministic_semantic_binding() -> String {
    [
        "VSEL_CAIRO_SEMANTIC_BINDING_V1",
        "semantic_core=semantic_core/src/lib.cairo 2222222222222222222222222222222222222222222222222222222222222222",
        "contract_wrapper=src/reference_contract.cairo 3333333333333333333333333333333333333333333333333333333333333333",
        "executable_entrypoint=executable/src/lib.cairo 4444444444444444444444444444444444444444444444444444444444444444",
        "core_apply_transition=true",
        "core_seal_transition=true",
        "core_invariant_predicate=true",
        "contract_uses_core_apply=true",
        "contract_uses_core_seal=true",
        "contract_uses_core_invariant=true",
        "executable_uses_core_apply=true",
        "",
    ]
    .join("\n")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = env::temp_dir().join(format!("vsel-{}-{}-{}", name, std::process::id(), nanos));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn sha3_256_file(path: &Path) -> Hash {
    Hash(sha3_256(&fs::read(path).expect("read artifact")))
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    hex_encode(&sha3_256(bytes))
}

fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

fn empty_constraint_commitment(version: &str) -> Hash {
    let mut data = Vec::new();
    encode_string(&mut data, version);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    domain_hash(&proof_tag(), &data)
}

fn encode_string(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

struct EnvGuard {
    previous: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(values: &[(&'static str, &str)]) -> Self {
        let previous = values
            .iter()
            .map(|(key, _)| (*key, env::var(key).ok()))
            .collect::<Vec<_>>();
        for (key, value) in values {
            env::set_var(key, value);
        }
        Self { previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.previous.iter().rev() {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
    }
}
