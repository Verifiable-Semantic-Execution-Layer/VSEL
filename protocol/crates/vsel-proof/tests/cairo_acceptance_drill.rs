#![cfg(feature = "cairo-stark-backend")]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Sha3_256};
use vsel_constraints::{
    Constraint, ConstraintCategory, ConstraintExpr, ConstraintId, ConstraintSystem,
};
use vsel_core::input::{Authorization, Input};
use vsel_core::observable::obs;
use vsel_core::state::{
    derive, derive_economic, AccountData, CanonicalState, Environment, State, TraceMetadata,
};
use vsel_core::transition::apply;
use vsel_core::types::{
    AccountId, AuxiliaryData, DomainTag, Hash, HybridPublicKey, Payload, ProtocolVersion,
    SystemData,
};
use vsel_proof::cairo_native::{NativeCairoBackendKind, NativeCairoCommandConfig};
use vsel_proof::cairo_stark::{CairoProgramCommitments, CairoStarkBackend};
use vsel_proof::prover::{BackendProver, Prover};
use vsel_proof::verifier::{
    BackendCryptographicVerifier, CryptographicVerifier, Lean4SemanticVerifier,
    SemanticVerificationResult, VerificationPipeline,
};
use vsel_proof::witness::construct_witness;
use vsel_trace::engine::{Trace, TraceEngine};

const ENV_NATIVE_VERIFY_COMMAND: &str = "VSEL_CAIRO_NATIVE_VERIFY_COMMAND";
const ENV_NATIVE_WORKDIR: &str = "VSEL_CAIRO_NATIVE_WORKDIR";
const ENV_NATIVE_PROOF_PATH: &str = "VSEL_CAIRO_NATIVE_PROOF_PATH";
const ENV_NATIVE_TRACE_PATH: &str = "VSEL_CAIRO_NATIVE_TRACE_PATH";
const ENV_CAIRO_PROGRAM_PATH: &str = "VSEL_CAIRO_PROGRAM_PATH";
const ENV_SIERRA_PROGRAM_PATH: &str = "VSEL_CAIRO_SIERRA_PROGRAM_PATH";
const ENV_CASM_PROGRAM_PATH: &str = "VSEL_CAIRO_CASM_PROGRAM_PATH";
const ENV_EXECUTABLE_PROGRAM_PATH: &str = "VSEL_CAIRO_EXECUTABLE_PROGRAM_PATH";
const ENV_CAIRO_SOURCE_MANIFEST_PATH: &str = "VSEL_CAIRO_SOURCE_MANIFEST_PATH";
const ENV_CAIRO_SEMANTIC_BINDING_PATH: &str = "VSEL_CAIRO_SEMANTIC_BINDING_PATH";
const REQUIRE_REAL_SCARB_ACCEPTANCE: &str = "VSEL_REQUIRE_REAL_SCARB_ACCEPTANCE";

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn deterministic_fixture_reaches_vcai_backend_strict_trace_and_lean_certificate() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("cairo-acceptance-fixture");
    let fixture = deterministic_fixture(&temp);

    let result = run_acceptance_drill(&fixture).expect("deterministic acceptance drill");

    assert!(
        result.fully_verified,
        "deterministic fixture must reach VSEL final acceptance"
    );
    assert!(result.crypto_verified);
    assert!(result.constraint_witness_verified);
    assert!(result
        .semantic_checks
        .contains(&"lean:certificate_checker".to_string()));
    assert!(result
        .semantic_checks
        .contains(&"cairo:native_verifier_success".to_string()));

    fs::remove_dir_all(temp).ok();
}

#[test]
fn deterministic_fixture_rejects_stale_native_trace_binding() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("cairo-acceptance-stale-trace");
    let mut fixture = deterministic_fixture(&temp);
    let proof = produce_vcai_proof(&fixture).expect("produce baseline VCAI proof");

    let stale_trace = write_artifact(&temp, "stale_prover_input.json", b"stale native trace");
    fixture.native_trace_path = stale_trace;

    let _guard = fixture.install_env();
    let verifier = BackendCryptographicVerifier::new(
        ProtocolVersion::default(),
        CairoStarkBackend::new(fixture.program.clone(), fixture.native_adapter()),
    );
    let result = verifier.verify_cryptographic(&proof, &proof.public_inputs);
    assert!(
        result.is_failed(),
        "stale configured native trace must fail during backend verification"
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn deterministic_fixture_rejects_stale_native_proof_binding() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("cairo-acceptance-stale-proof");
    let mut fixture = deterministic_fixture(&temp);
    let proof = produce_vcai_proof(&fixture).expect("produce baseline VCAI proof");

    let stale_proof = write_artifact(&temp, "stale_proof.json", b"stale native proof bytes");
    fixture.native_proof_path = stale_proof;

    let _guard = fixture.install_env();
    let verifier = BackendCryptographicVerifier::new(
        ProtocolVersion::default(),
        CairoStarkBackend::new(fixture.program.clone(), fixture.native_adapter()),
    );
    let result = verifier.verify_cryptographic(&proof, &proof.public_inputs);
    assert!(
        result.is_failed(),
        "stale configured native proof bytes must fail during backend verification"
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn deterministic_fixture_rejects_mutated_executable_artifact() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("cairo-acceptance-mutated-executable");
    let fixture = deterministic_fixture(&temp);

    fs::write(
        &fixture.executable_program_path,
        b"mutated executable after commitment",
    )
    .expect("mutate executable artifact");

    let err = produce_vcai_proof(&fixture)
        .expect_err("mutated executable artifact must fail before VCAI packaging");
    assert!(
        err.contains("executable_program_hash mismatch"),
        "unexpected executable artifact error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn deterministic_fixture_rejects_mutated_semantic_binding_artifact() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let temp = unique_temp_dir("cairo-acceptance-mutated-semantic-binding");
    let fixture = deterministic_fixture(&temp);

    fs::write(
        &fixture.semantic_binding_path,
        b"mutated semantic binding after commitment",
    )
    .expect("mutate semantic binding artifact");

    let err = produce_vcai_proof(&fixture)
        .expect_err("mutated semantic binding artifact must fail before VCAI packaging");
    assert!(
        err.contains("semantic_binding_hash mismatch"),
        "unexpected semantic binding artifact error: {}",
        err
    );

    fs::remove_dir_all(temp).ok();
}

#[test]
fn scarb_execution_fixture_reaches_full_vsel_acceptance_when_available() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let execution_id = env::var("VSEL_SCARB_EXECUTION_ID").unwrap_or_else(|_| "6".to_string());
    let Some(fixture) = scarb_execution_fixture(&execution_id) else {
        if env::var(REQUIRE_REAL_SCARB_ACCEPTANCE).as_deref() == Ok("1") {
            panic!(
                "Scarb native acceptance drill is required but execution{} fixture or scarb binary is unavailable",
                execution_id
            );
        }
        eprintln!(
            "skipping Scarb native acceptance drill: execution{} fixture or scarb binary is unavailable",
            execution_id
        );
        return;
    };

    let result = run_acceptance_drill(&fixture).expect("Scarb execution acceptance drill");

    assert!(result.fully_verified, "{:?}", result);
    assert!(result.crypto_verified);
    assert!(result.constraint_witness_verified);
    assert!(result
        .semantic_checks
        .contains(&"lean:certificate_checker".to_string()));
    assert!(result
        .semantic_checks
        .contains(&"cairo:native_verifier_success".to_string()));
}

#[derive(Debug)]
struct DrillResult {
    fully_verified: bool,
    crypto_verified: bool,
    constraint_witness_verified: bool,
    semantic_checks: Vec<String>,
}

#[derive(Clone)]
struct AcceptanceFixture {
    program: CairoProgramCommitments,
    wrapper: PathBuf,
    wrapper_hash: String,
    native_verify_command: String,
    native_workdir: Option<PathBuf>,
    native_proof_path: PathBuf,
    native_trace_path: PathBuf,
    cairo_program_path: PathBuf,
    sierra_program_path: PathBuf,
    casm_program_path: PathBuf,
    executable_program_path: PathBuf,
    semantic_binding_path: PathBuf,
}

impl AcceptanceFixture {
    fn native_adapter(&self) -> vsel_proof::cairo_native::ScarbCairoAdapter {
        NativeCairoCommandConfig {
            kind: NativeCairoBackendKind::Scarb,
            version: "2.16.0".to_string(),
            prover_command: self.wrapper.clone(),
            prover_sha3_256: self.wrapper_hash.clone(),
            verifier_command: self.wrapper.clone(),
            verifier_sha3_256: self.wrapper_hash.clone(),
        }
        .into_adapter()
        .expect("pinned Scarb adapter")
    }

    fn install_env(&self) -> EnvGuard {
        let mut values = vec![
            (
                ENV_NATIVE_VERIFY_COMMAND,
                self.native_verify_command.clone(),
            ),
            (
                ENV_NATIVE_PROOF_PATH,
                self.native_proof_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_NATIVE_TRACE_PATH,
                self.native_trace_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_CAIRO_PROGRAM_PATH,
                self.cairo_program_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_SIERRA_PROGRAM_PATH,
                self.sierra_program_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_CASM_PROGRAM_PATH,
                self.casm_program_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_EXECUTABLE_PROGRAM_PATH,
                self.executable_program_path.to_string_lossy().into_owned(),
            ),
            (
                ENV_CAIRO_SEMANTIC_BINDING_PATH,
                self.semantic_binding_path.to_string_lossy().into_owned(),
            ),
        ];
        if let Some(workdir) = &self.native_workdir {
            values.push((ENV_NATIVE_WORKDIR, workdir.to_string_lossy().into_owned()));
        }
        EnvGuard::set(values)
    }
}

fn run_acceptance_drill(fixture: &AcceptanceFixture) -> Result<DrillResult, String> {
    let proof = produce_vcai_proof(fixture)?;
    let trace = executable_trace();
    let constraints = covered_constraint_system();
    let witness = construct_witness(&trace);

    let _guard = fixture.install_env();
    let crypto_verifier = BackendCryptographicVerifier::new(
        ProtocolVersion::default(),
        CairoStarkBackend::new(fixture.program.clone(), fixture.native_adapter()),
    );
    let crypto = crypto_verifier.verify_cryptographic(&proof, &proof.public_inputs);
    if !crypto.is_consistent() {
        return Err(format!(
            "backend cryptographic verification failed: {:?}",
            crypto
        ));
    }

    let pipeline = VerificationPipeline::new(
        BackendCryptographicVerifier::new(
            ProtocolVersion::default(),
            CairoStarkBackend::new(fixture.program.clone(), fixture.native_adapter()),
        ),
        Lean4SemanticVerifier::new(ProtocolVersion::default())
            .with_formal_spec_path(formal_spec_path())
            .with_timeout(120_000)
            .requiring_stark_proof_system(),
    );
    let result =
        pipeline.verify_strict_trace(&proof, &proof.public_inputs, &witness, &constraints, &trace);

    let semantic_checks = match &result.semantic {
        SemanticVerificationResult::Valid { passed_checks, .. } => passed_checks.clone(),
        other => {
            return Err(format!(
                "strict trace semantic verification failed: {:?}",
                other
            ))
        }
    };

    Ok(DrillResult {
        fully_verified: result.is_fully_verified(),
        crypto_verified: result.is_cryptographically_verified(),
        constraint_witness_verified: result.is_constraint_witness_verified(),
        semantic_checks,
    })
}

fn produce_vcai_proof(fixture: &AcceptanceFixture) -> Result<vsel_proof::prover::Proof, String> {
    let trace = executable_trace();
    let constraints = covered_constraint_system();
    let _guard = fixture.install_env();
    BackendProver::new(
        "cairo-native-acceptance-drill",
        CairoStarkBackend::new(fixture.program.clone(), fixture.native_adapter()),
    )
    .prove(&trace, &constraints)
    .map_err(|err| err.to_string())
}

fn deterministic_fixture(temp: &Path) -> AcceptanceFixture {
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));

    let cairo_program_path = write_artifact(
        temp,
        "cairo-source-manifest.txt",
        deterministic_source_manifest().as_bytes(),
    );
    let sierra_program_path = write_artifact(temp, "program.sierra.json", b"sierra fixture");
    let casm_program_path = write_artifact(temp, "program.casm.json", b"casm fixture");
    let executable_program_path =
        write_artifact(temp, "program.executable.json", b"executable fixture");
    let semantic_binding_path = write_artifact(
        temp,
        "cairo-semantic-binding.txt",
        deterministic_semantic_binding().as_bytes(),
    );
    let native_proof_path = write_artifact(temp, "proof.json", b"deterministic native proof");
    let native_trace_path = write_artifact(temp, "prover_input.json", b"deterministic trace");

    let program = program_commitments(
        &cairo_program_path,
        &sierra_program_path,
        &casm_program_path,
        &executable_program_path,
        &semantic_binding_path,
    );
    let trace_hash = sha3_256_hex(&fs::read(&native_trace_path).expect("read native trace"));
    let native_verify_script = write_native_verify_script(
        temp,
        "deterministic-native-verify.sh",
        None,
        &native_proof_path,
        &trace_hash,
    );

    AcceptanceFixture {
        program,
        wrapper,
        wrapper_hash,
        native_verify_command: native_verify_script.to_string_lossy().into_owned(),
        native_workdir: None,
        native_proof_path,
        native_trace_path,
        cairo_program_path,
        sierra_program_path,
        casm_program_path,
        executable_program_path,
        semantic_binding_path,
    }
}

fn scarb_execution_fixture(execution_id: &str) -> Option<AcceptanceFixture> {
    if command_path("scarb").is_none() {
        return None;
    }

    let repo = repo_root();
    let reference = repo.join("examples/cairo/reference_state_machine");
    let executable_dir = reference.join("executable");
    let native_proof_path = executable_dir.join(format!(
        "target/execute/vsel_reference_state_machine_exec/execution{}/proof/proof.json",
        execution_id
    ));
    let native_trace_path = executable_dir.join(format!(
        "target/execute/vsel_reference_state_machine_exec/execution{}/prover_input.json",
        execution_id
    ));
    let sierra_program_path = reference
        .join("target/dev/vsel_reference_state_machine_ReferenceStateMachine.contract_class.json");
    let casm_program_path = reference
        .join("target/dev/vsel_reference_state_machine_ReferenceStateMachine.compiled_contract_class.json");
    let executable_program_path =
        executable_dir.join("target/dev/vsel_reference_state_machine_exec.executable.json");

    for path in [
        &native_proof_path,
        &native_trace_path,
        &sierra_program_path,
        &casm_program_path,
        &executable_program_path,
    ] {
        if !path.exists() {
            return None;
        }
    }

    let temp = unique_temp_dir("cairo-acceptance-scarb");
    let cairo_program_path = cairo_source_manifest_from_env(&reference)
        .unwrap_or_else(|| write_cairo_source_manifest(&temp, &reference));
    let semantic_binding_path = cairo_semantic_binding_from_env(&reference)
        .unwrap_or_else(|| write_cairo_semantic_binding(&temp, &reference));
    let program = program_commitments(
        &cairo_program_path,
        &sierra_program_path,
        &casm_program_path,
        &executable_program_path,
        &semantic_binding_path,
    );
    let wrapper = PathBuf::from(env!("CARGO_BIN_EXE_vsel-cairo-native-wrapper"));
    let wrapper_hash = sha3_256_hex(&fs::read(&wrapper).expect("read wrapper binary"));
    let trace_hash = sha3_256_hex(&fs::read(&native_trace_path).expect("read native trace"));
    let native_verify = format!("scarb verify --execution-id {} >/dev/null", execution_id);
    let native_verify_script = write_native_verify_script(
        &temp,
        "scarb-execution-native-verify.sh",
        Some(native_verify.as_str()),
        &native_proof_path,
        &trace_hash,
    );

    Some(AcceptanceFixture {
        program,
        wrapper,
        wrapper_hash,
        native_verify_command: native_verify_script.to_string_lossy().into_owned(),
        native_workdir: Some(executable_dir),
        native_proof_path,
        native_trace_path,
        cairo_program_path,
        sierra_program_path,
        casm_program_path,
        executable_program_path,
        semantic_binding_path,
    })
}

fn write_native_verify_script(
    dir: &Path,
    name: &str,
    native_verify: Option<&str>,
    expected_proof_path: &Path,
    expected_trace_hash: &str,
) -> PathBuf {
    let path = dir.join(name);
    let native_verify = native_verify.unwrap_or(":");
    let script = format!(
        r#"#!/bin/sh
set -eu
{native_verify}
cmp "$VSEL_CAIRO_REQUEST_PROOF_PATH" "{proof_path}" >/dev/null
test "$VSEL_CAIRO_REQUEST_CAIRO_TRACE_HASH" = "{trace_hash}"
printf 'VSEL_CAIRO_NATIVE_CONTEXT_ATTESTATION_V1
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
' "$VSEL_CAIRO_REQUEST_BACKEND_ID" "$VSEL_CAIRO_REQUEST_CAIRO_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_SIERRA_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_CASM_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_EXECUTABLE_PROGRAM_HASH" "$VSEL_CAIRO_REQUEST_SEMANTIC_BINDING_HASH" "$VSEL_CAIRO_REQUEST_CAIRO_TRACE_HASH" "$VSEL_CAIRO_REQUEST_PUBLIC_INPUT_HASH" "$VSEL_CAIRO_REQUEST_CONSTRAINT_COMMITMENT" "$VSEL_CAIRO_REQUEST_STATEMENT_HASH" "$VSEL_CAIRO_REQUEST_PROOF_HASH"
"#,
        proof_path = expected_proof_path.display(),
        trace_hash = expected_trace_hash,
    );
    fs::write(&path, script).expect("write native verify script");
    make_executable(&path);
    path
}

fn write_cairo_source_manifest(dir: &Path, reference: &Path) -> PathBuf {
    let manifest = cairo_source_manifest_text(reference);
    write_artifact(dir, "cairo-source-manifest.txt", manifest.as_bytes())
}

fn write_cairo_semantic_binding(dir: &Path, reference: &Path) -> PathBuf {
    let binding = cairo_semantic_binding_text(reference);
    write_artifact(dir, "cairo-semantic-binding.txt", binding.as_bytes())
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

fn cairo_source_manifest_from_env(reference: &Path) -> Option<PathBuf> {
    let path = env::var_os(ENV_CAIRO_SOURCE_MANIFEST_PATH).map(PathBuf::from)?;
    let actual = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} points to unreadable manifest {}: {}",
            ENV_CAIRO_SOURCE_MANIFEST_PATH,
            path.display(),
            err
        )
    });
    let expected = cairo_source_manifest_text(reference);
    assert_eq!(
        actual, expected,
        "{} must point to the canonical VSEL_CAIRO_SOURCE_MANIFEST_V1 for the reference example",
        ENV_CAIRO_SOURCE_MANIFEST_PATH
    );
    Some(path)
}

fn cairo_semantic_binding_from_env(reference: &Path) -> Option<PathBuf> {
    let path = env::var_os(ENV_CAIRO_SEMANTIC_BINDING_PATH).map(PathBuf::from)?;
    let actual = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} points to unreadable binding {}: {}",
            ENV_CAIRO_SEMANTIC_BINDING_PATH,
            path.display(),
            err
        )
    });
    let expected = cairo_semantic_binding_text(reference);
    assert_eq!(
        actual, expected,
        "{} must point to the canonical VSEL_CAIRO_SEMANTIC_BINDING_V1 for the reference example",
        ENV_CAIRO_SEMANTIC_BINDING_PATH
    );
    Some(path)
}

fn cairo_source_manifest_text(reference: &Path) -> String {
    let files = [
        "Scarb.toml",
        "Scarb.lock",
        "semantic_core/Scarb.toml",
        "semantic_core/Scarb.lock",
        "semantic_core/src/lib.cairo",
        "src/lib.cairo",
        "src/reference_contract.cairo",
        "executable/Scarb.toml",
        "executable/Scarb.lock",
        "executable/src/lib.cairo",
        "executable/inputs/valid_transition.json",
    ];
    let mut manifest = String::from("VSEL_CAIRO_SOURCE_MANIFEST_V1\n");
    for file in files {
        let path = reference.join(file);
        let bytes = fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "read Cairo source manifest input {}: {}",
                path.display(),
                err
            )
        });
        manifest.push_str(file);
        manifest.push(' ');
        manifest.push_str(&sha3_256_hex(&bytes));
        manifest.push('\n');
    }
    manifest
}

fn cairo_semantic_binding_text(reference: &Path) -> String {
    let core = reference.join("semantic_core/src/lib.cairo");
    let contract = reference.join("src/reference_contract.cairo");
    let executable = reference.join("executable/src/lib.cairo");
    let core_bytes = fs::read(&core).unwrap_or_else(|err| {
        panic!(
            "read Cairo semantic binding input {}: {}",
            core.display(),
            err
        )
    });
    let contract_bytes = fs::read(&contract).unwrap_or_else(|err| {
        panic!(
            "read Cairo semantic binding input {}: {}",
            contract.display(),
            err
        )
    });
    let executable_bytes = fs::read(&executable).unwrap_or_else(|err| {
        panic!(
            "read Cairo semantic binding input {}: {}",
            executable.display(),
            err
        )
    });

    [
        "VSEL_CAIRO_SEMANTIC_BINDING_V1".to_string(),
        format!(
            "semantic_core=semantic_core/src/lib.cairo {}",
            sha3_256_hex(&core_bytes)
        ),
        format!(
            "contract_wrapper=src/reference_contract.cairo {}",
            sha3_256_hex(&contract_bytes)
        ),
        format!(
            "executable_entrypoint=executable/src/lib.cairo {}",
            sha3_256_hex(&executable_bytes)
        ),
        "core_apply_transition=true".to_string(),
        "core_seal_transition=true".to_string(),
        "core_invariant_predicate=true".to_string(),
        "contract_uses_core_apply=true".to_string(),
        "contract_uses_core_seal=true".to_string(),
        "contract_uses_core_invariant=true".to_string(),
        "executable_uses_core_apply=true".to_string(),
        String::new(),
    ]
    .join("\n")
}

fn executable_trace() -> Trace {
    let initial_state = executable_state();
    let input = executable_input();
    let post_state = apply(&initial_state, &input);
    let observable = obs(&initial_state, &input, &post_state);
    let mut engine = TraceEngine::new();
    let entry = engine.record_transition(&initial_state, &input, &post_state, &observable);
    Trace {
        entries: vec![entry.clone()],
        initial_state,
        commitment: entry.chain_hash,
    }
}

fn executable_state() -> State {
    let mut accounts = BTreeMap::new();
    accounts.insert(
        AccountId([0x11; 32]),
        AccountData {
            balance: 1_000,
            nonce: 0,
            data: Vec::new(),
        },
    );
    let canonical = CanonicalState {
        accounts,
        storage: BTreeMap::new(),
        system_data: SystemData {
            protocol_version: ProtocolVersion::default(),
            total_supply: 1_000,
            parameters: BTreeMap::new(),
        },
    };
    let environment = Environment {
        timestamp: 1_000,
        block_height: 1,
        execution_domain: DomainTag(hash(0x33)),
    };
    State {
        derived: derive(&canonical),
        economic: derive_economic(&canonical, &environment),
        canonical,
        environment,
        metadata: TraceMetadata {
            sequence_index: 0,
            previous_commitment: Hash([0u8; 32]),
            epoch: 0,
            timestamp: 1_000,
        },
    }
}

fn executable_input() -> Input {
    Input {
        payload: Payload {
            payload_type: "init".to_string(),
            data: vec![1],
        },
        auth: Authorization {
            classical_sig: vec![1; 64],
            pqc_sig: vec![2; 128],
            public_key: HybridPublicKey {
                classical: vec![3; 32],
                pqc: vec![4; 64],
            },
            nonce: 1,
            domain: DomainTag(hash(0x33)),
        },
        aux: AuxiliaryData { data: Vec::new() },
    }
}

fn covered_constraint_system() -> ConstraintSystem {
    let mut constraints = ConstraintSystem::new("cairo-native-acceptance-drill");
    constraints.add(Constraint {
        id: ConstraintId(10),
        expr: ConstraintExpr::Eq(
            Box::new(ConstraintExpr::WitnessRef("input_count".to_string())),
            Box::new(ConstraintExpr::Constant(1)),
        ),
        category: ConstraintCategory::Semantic,
        description: "semantic input count binding".to_string(),
    });
    constraints.add(Constraint {
        id: ConstraintId(11),
        expr: ConstraintExpr::Eq(
            Box::new(ConstraintExpr::PublicInputRef(
                "observables_count".to_string(),
            )),
            Box::new(ConstraintExpr::Constant(1)),
        ),
        category: ConstraintCategory::Invariant,
        description: "invariant observable count binding".to_string(),
    });
    constraints
}

fn program_commitments(
    cairo_program_path: &Path,
    sierra_program_path: &Path,
    casm_program_path: &Path,
    executable_program_path: &Path,
    semantic_binding_path: &Path,
) -> CairoProgramCommitments {
    CairoProgramCommitments::new(
        sha3_256_file(cairo_program_path),
        sha3_256_file(sierra_program_path),
        sha3_256_file(casm_program_path),
        sha3_256_file(executable_program_path),
        sha3_256_file(semantic_binding_path),
    )
}

fn formal_spec_path() -> String {
    repo_root()
        .join("formal")
        .canonicalize()
        .expect("formal spec path")
        .to_string_lossy()
        .into_owned()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

fn command_path(command: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(command))
        .find(|path| path.is_file())
}

fn write_artifact(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write artifact");
    path
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

fn hash(byte: u8) -> Hash {
    Hash([byte; 32])
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod script");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

struct EnvGuard {
    previous: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn set(values: Vec<(&'static str, String)>) -> Self {
        let previous = values
            .iter()
            .map(|(key, _)| ((*key).to_string(), env::var(key).ok()))
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
