//! Fail-closed constructors for native Cairo/STARK command adapters.
//!
//! The `cairo-stark-backend` feature exposes configuration glue only. It does
//! not vendor Stone/Stwo and it does not create a mock verifier. A configured
//! command must be a VSEL-aware adapter around the native prover/verifier: it
//! receives the canonical request format from [`crate::cairo_stark`] and emits
//! VCAI/v1 proof material or a verifier certificate only after the native
//! Cairo/STARK verifier accepted the proof.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use sha3::{Digest, Sha3_256};
use vsel_core::types::Hash;

use crate::cairo_stark::{
    CairoProofAdapter, CairoProveRequest, CairoStarkError, CairoStarkProof,
    CairoVerifierCertificate, CairoVerifyRequest, CommandCairoAdapter,
};

const HEX_LEN_SHA3_256: usize = 64;

/// Supported native Cairo/STARK command families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCairoBackendKind {
    Stone,
    Stwo,
}

impl NativeCairoBackendKind {
    pub fn adapter_name(self) -> &'static str {
        match self {
            Self::Stone => "stone",
            Self::Stwo => "stwo",
        }
    }

    fn env_prefix(self) -> &'static str {
        match self {
            Self::Stone => "VSEL_STONE_CAIRO",
            Self::Stwo => "VSEL_STWO_CAIRO",
        }
    }
}

/// Fully pinned native Cairo/STARK adapter configuration.
///
/// `prover_command` and `verifier_command` are expected to be VSEL adapter
/// commands around the selected native backend. They must speak the command
/// protocol implemented by `CommandCairoAdapter`; raw Stone/Stwo binaries are
/// acceptable only if they implement that exact stdin/stdout contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCairoCommandConfig {
    pub kind: NativeCairoBackendKind,
    pub version: String,
    pub prover_command: PathBuf,
    pub prover_sha3_256: String,
    pub verifier_command: PathBuf,
    pub verifier_sha3_256: String,
}

impl NativeCairoCommandConfig {
    pub fn stone_from_env() -> Result<Self, CairoStarkError> {
        Self::from_env(NativeCairoBackendKind::Stone)
    }

    pub fn stwo_from_env() -> Result<Self, CairoStarkError> {
        Self::from_env(NativeCairoBackendKind::Stwo)
    }

    /// Load a pinned command adapter configuration from environment variables.
    ///
    /// For Stone:
    ///
    /// * `VSEL_STONE_CAIRO_VERSION`
    /// * `VSEL_STONE_CAIRO_PROVER`
    /// * `VSEL_STONE_CAIRO_PROVER_SHA3_256`
    /// * `VSEL_STONE_CAIRO_VERIFIER`
    /// * `VSEL_STONE_CAIRO_VERIFIER_SHA3_256`
    ///
    /// For Stwo, replace `STONE` with `STWO`.
    pub fn from_env(kind: NativeCairoBackendKind) -> Result<Self, CairoStarkError> {
        let prefix = kind.env_prefix();
        Self::from_env_prefix(kind, prefix)
    }

    fn from_env_prefix(
        kind: NativeCairoBackendKind,
        prefix: &str,
    ) -> Result<Self, CairoStarkError> {
        Ok(Self {
            kind,
            version: read_env(prefix, "VERSION")?,
            prover_command: PathBuf::from(read_env(prefix, "PROVER")?),
            prover_sha3_256: read_env(prefix, "PROVER_SHA3_256")?,
            verifier_command: PathBuf::from(read_env(prefix, "VERIFIER")?),
            verifier_sha3_256: read_env(prefix, "VERIFIER_SHA3_256")?,
        })
    }

    /// Validate path existence, version syntax, and exact binary digests.
    pub fn validate(&self) -> Result<(), CairoStarkError> {
        validate_id_component("version", &self.version)?;
        validate_sha3_256_hex("prover_sha3_256", &self.prover_sha3_256)?;
        validate_sha3_256_hex("verifier_sha3_256", &self.verifier_sha3_256)?;
        validate_command_digest("prover", &self.prover_command, &self.prover_sha3_256)?;
        validate_command_digest("verifier", &self.verifier_command, &self.verifier_sha3_256)?;
        Ok(())
    }

    /// Adapter id bound into `cairo-stark/<adapter-id>` metadata.
    ///
    /// The id includes backend family, explicit version, and full command
    /// digests, forcing proof metadata and verifier certificates to bind the
    /// exact native command artifacts used by the adapter.
    pub fn adapter_id(&self) -> Result<String, CairoStarkError> {
        self.validate()?;
        Ok(format!(
            "{}-{}-prover-{}-verifier-{}",
            self.kind.adapter_name(),
            self.version,
            self.prover_sha3_256.to_ascii_lowercase(),
            self.verifier_sha3_256.to_ascii_lowercase()
        ))
    }

    pub fn into_adapter(self) -> Result<PinnedNativeCairoAdapter, CairoStarkError> {
        let adapter_id = self.adapter_id()?;
        let verifier_binary_hash = sha3_256_hash_from_hex(&self.verifier_sha3_256)?;
        let command_adapter = CommandCairoAdapter::new(
            adapter_id.clone(),
            Some(self.prover_command),
            self.verifier_command,
        );
        Ok(PinnedNativeCairoAdapter::new(
            adapter_id,
            self.version,
            verifier_binary_hash,
            command_adapter,
        ))
    }
}

/// Native Cairo/STARK adapter with certificate-level pin enforcement.
///
/// The inner command is still responsible for invoking Stone/Stwo and emitting
/// VCAI/v1 material. This wrapper enforces that every returned verifier
/// certificate carries the exact verifier version and binary digest already
/// validated by [`NativeCairoCommandConfig`].
pub struct PinnedNativeCairoAdapter {
    adapter_id: String,
    verifier_version: String,
    verifier_binary_hash: Hash,
    inner: CommandCairoAdapter,
}

impl PinnedNativeCairoAdapter {
    fn new(
        adapter_id: String,
        verifier_version: String,
        verifier_binary_hash: Hash,
        inner: CommandCairoAdapter,
    ) -> Self {
        Self {
            adapter_id,
            verifier_version,
            verifier_binary_hash,
            inner,
        }
    }

    fn validate_certificate(
        &self,
        certificate: &CairoVerifierCertificate,
    ) -> Result<(), CairoStarkError> {
        if certificate.adapter_id != self.adapter_id {
            return Err(CairoStarkError::VerificationFailed(format!(
                "native Cairo certificate adapter mismatch: expected {}, got {}",
                self.adapter_id, certificate.adapter_id
            )));
        }
        if certificate.verifier_version != self.verifier_version {
            return Err(CairoStarkError::VerificationFailed(format!(
                "native Cairo certificate verifier version mismatch: expected {}, got {}",
                self.verifier_version, certificate.verifier_version
            )));
        }
        if certificate.verifier_binary_hash != self.verifier_binary_hash {
            return Err(CairoStarkError::VerificationFailed(
                "native Cairo certificate verifier binary hash mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

impl CairoProofAdapter for PinnedNativeCairoAdapter {
    fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    fn prove(&self, request: &CairoProveRequest) -> Result<CairoStarkProof, CairoStarkError> {
        let proof = self.inner.prove(request)?;
        self.validate_certificate(&proof.verifier_certificate)?;
        Ok(proof)
    }

    fn verify(
        &self,
        request: &CairoVerifyRequest,
    ) -> Result<CairoVerifierCertificate, CairoStarkError> {
        let certificate = self.inner.verify(request)?;
        self.validate_certificate(&certificate)?;
        Ok(certificate)
    }
}

pub type StoneCairoAdapter = PinnedNativeCairoAdapter;
pub type StwoCairoAdapter = PinnedNativeCairoAdapter;

pub fn stone_adapter_from_env() -> Result<StoneCairoAdapter, CairoStarkError> {
    NativeCairoCommandConfig::stone_from_env()?.into_adapter()
}

pub fn stwo_adapter_from_env() -> Result<StwoCairoAdapter, CairoStarkError> {
    NativeCairoCommandConfig::stwo_from_env()?.into_adapter()
}

fn read_env(prefix: &str, suffix: &str) -> Result<String, CairoStarkError> {
    let key = format!("{}_{}", prefix, suffix);
    env::var(&key).map_err(|_| {
        CairoStarkError::CommandFailed(format!(
            "missing required native Cairo/STARK adapter env var {}",
            key
        ))
    })
}

fn validate_id_component(name: &str, value: &str) -> Result<(), CairoStarkError> {
    if value.is_empty() {
        return Err(CairoStarkError::CommandFailed(format!(
            "{} must be non-empty",
            name
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CairoStarkError::CommandFailed(format!(
            "{} contains characters outside [A-Za-z0-9._-]",
            name
        )));
    }
    Ok(())
}

fn validate_sha3_256_hex(name: &str, value: &str) -> Result<(), CairoStarkError> {
    if value.len() != HEX_LEN_SHA3_256 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CairoStarkError::CommandFailed(format!(
            "{} must be a 64-character SHA3-256 hex digest",
            name
        )));
    }
    Ok(())
}

fn sha3_256_hash_from_hex(value: &str) -> Result<Hash, CairoStarkError> {
    validate_sha3_256_hex("verifier_sha3_256", value)?;
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for i in 0..32 {
        let high = hex_nibble(bytes[i * 2])?;
        let low = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (high << 4) | low;
    }
    Ok(Hash(out))
}

fn hex_nibble(byte: u8) -> Result<u8, CairoStarkError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CairoStarkError::CommandFailed(
            "invalid SHA3-256 hex character".to_string(),
        )),
    }
}

fn validate_command_digest(
    label: &str,
    path: &Path,
    expected_hex: &str,
) -> Result<(), CairoStarkError> {
    let metadata = fs::metadata(path).map_err(|e| {
        CairoStarkError::CommandFailed(format!(
            "{} command '{}' is unavailable: {}",
            label,
            path.display(),
            e
        ))
    })?;
    if !metadata.is_file() {
        return Err(CairoStarkError::CommandFailed(format!(
            "{} command '{}' is not a regular file",
            label,
            path.display()
        )));
    }

    let bytes = fs::read(path).map_err(|e| {
        CairoStarkError::CommandFailed(format!(
            "{} command '{}' cannot be read for digest pinning: {}",
            label,
            path.display(),
            e
        ))
    })?;
    let actual = sha3_256_hex(&bytes);
    if actual != expected_hex.to_ascii_lowercase() {
        return Err(CairoStarkError::CommandFailed(format!(
            "{} command '{}' digest mismatch: expected {}, got {}",
            label,
            path.display(),
            expected_hex,
            actual
        )));
    }
    Ok(())
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    let digest = Sha3_256::digest(bytes);
    let mut out = String::with_capacity(HEX_LEN_SHA3_256);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cairo_stark::{
        CairoProgramCommitments, CairoProofAdapter, CairoVerifierCertificate,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "vsel-{}-{}-{}-{}",
            name,
            std::process::id(),
            nanos,
            id
        ))
    }

    fn write_temp_command(name: &str, bytes: &[u8]) -> PathBuf {
        let path = unique_temp_path(name);
        fs::write(&path, bytes).expect("write temp command");
        path
    }

    #[test]
    fn native_config_builds_adapter_id_from_pinned_command_hashes() {
        let prover = write_temp_command("prover", b"native prover adapter");
        let verifier = write_temp_command("verifier", b"native verifier adapter");
        let prover_hash = sha3_256_hex(b"native prover adapter");
        let verifier_hash = sha3_256_hex(b"native verifier adapter");

        let config = NativeCairoCommandConfig {
            kind: NativeCairoBackendKind::Stone,
            version: "1.2.3".to_string(),
            prover_command: prover.clone(),
            prover_sha3_256: prover_hash.clone(),
            verifier_command: verifier.clone(),
            verifier_sha3_256: verifier_hash.clone(),
        };

        let adapter_id = config.adapter_id().expect("valid adapter id");
        assert_eq!(
            adapter_id,
            format!(
                "stone-1.2.3-prover-{}-verifier-{}",
                prover_hash, verifier_hash
            )
        );
        let adapter = config.into_adapter().expect("adapter");
        assert_eq!(adapter.adapter_id(), adapter_id);

        fs::remove_file(prover).ok();
        fs::remove_file(verifier).ok();
    }

    #[test]
    fn pinned_adapter_rejects_certificate_version_or_hash_drift() {
        let adapter_id = "stone-1.2.3-prover-aa-verifier-bb".to_string();
        let verifier_binary_hash = Hash([0x22; 32]);
        let adapter = PinnedNativeCairoAdapter::new(
            adapter_id.clone(),
            "1.2.3".to_string(),
            verifier_binary_hash.clone(),
            CommandCairoAdapter::new(adapter_id.clone(), None, unique_temp_path("unused")),
        );
        let certificate = CairoVerifierCertificate {
            adapter_id,
            verifier_version: "1.2.3".to_string(),
            verifier_binary_hash,
            backend_id: "cairo-stark/stone-1.2.3-prover-aa-verifier-bb".to_string(),
            program: CairoProgramCommitments::new(
                Hash([0x01; 32]),
                Hash([0x02; 32]),
                Hash([0x03; 32]),
                Hash([0x04; 32]),
            ),
            cairo_trace_hash: Hash([0x05; 32]),
            public_input_hash: Hash([0x06; 32]),
            constraint_commitment: Hash([0x07; 32]),
            statement_hash: Hash([0x08; 32]),
            proof_hash: Hash([0x09; 32]),
            transcript_hash: Hash([0x0a; 32]),
            accepted: true,
        };

        adapter
            .validate_certificate(&certificate)
            .expect("matching certificate pins");

        let mut wrong_version = certificate.clone();
        wrong_version.verifier_version = "1.2.4".to_string();
        assert!(adapter.validate_certificate(&wrong_version).is_err());

        let mut wrong_hash = certificate.clone();
        wrong_hash.verifier_binary_hash = Hash([0x23; 32]);
        assert!(adapter.validate_certificate(&wrong_hash).is_err());

        let mut wrong_adapter = certificate;
        wrong_adapter.adapter_id = "stwo-1.2.3-prover-aa-verifier-bb".to_string();
        assert!(adapter.validate_certificate(&wrong_adapter).is_err());
    }

    #[test]
    fn native_config_rejects_missing_command_before_adapter_construction() {
        let missing = unique_temp_path("missing-prover");
        let verifier = write_temp_command("verifier", b"native verifier adapter");
        let config = NativeCairoCommandConfig {
            kind: NativeCairoBackendKind::Stwo,
            version: "0.13.0".to_string(),
            prover_command: missing,
            prover_sha3_256: "00".repeat(32),
            verifier_command: verifier.clone(),
            verifier_sha3_256: sha3_256_hex(b"native verifier adapter"),
        };

        let err = match config.into_adapter() {
            Ok(_) => panic!("missing prover must fail closed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unavailable"));

        fs::remove_file(verifier).ok();
    }

    #[test]
    fn native_config_rejects_digest_mismatch() {
        let prover = write_temp_command("prover", b"native prover adapter");
        let verifier = write_temp_command("verifier", b"native verifier adapter");
        let config = NativeCairoCommandConfig {
            kind: NativeCairoBackendKind::Stone,
            version: "1.2.3".to_string(),
            prover_command: prover.clone(),
            prover_sha3_256: "11".repeat(32),
            verifier_command: verifier.clone(),
            verifier_sha3_256: sha3_256_hex(b"native verifier adapter"),
        };

        let err = match config.into_adapter() {
            Ok(_) => panic!("digest mismatch must fail closed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("digest mismatch"));

        fs::remove_file(prover).ok();
        fs::remove_file(verifier).ok();
    }

    #[test]
    fn native_config_rejects_ambiguous_version_component() {
        let prover = write_temp_command("prover", b"native prover adapter");
        let verifier = write_temp_command("verifier", b"native verifier adapter");
        let config = NativeCairoCommandConfig {
            kind: NativeCairoBackendKind::Stone,
            version: "1.2.3\naccepted=true".to_string(),
            prover_command: prover.clone(),
            prover_sha3_256: sha3_256_hex(b"native prover adapter"),
            verifier_command: verifier.clone(),
            verifier_sha3_256: sha3_256_hex(b"native verifier adapter"),
        };

        let err = match config.into_adapter() {
            Ok(_) => panic!("ambiguous adapter id must fail closed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("outside [A-Za-z0-9._-]"));

        fs::remove_file(prover).ok();
        fs::remove_file(verifier).ok();
    }
}
