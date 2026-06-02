//! NIST compliance control definitions.
//!
//! Maps NIST SSDF SP 800-218 practices and NIST CSF functions to
//! VSEL implementation artifacts.
//!
//! Requirements: 16.2, 16.3, 16.4

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// NIST control framework
// ---------------------------------------------------------------------------

/// NIST compliance framework identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NistFramework {
    /// NIST Secure Software Development Framework SP 800-218.
    Ssdf,
    /// NIST Cybersecurity Framework.
    Csf,
}

impl std::fmt::Display for NistFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NistFramework::Ssdf => write!(f, "NIST SSDF SP 800-218"),
            NistFramework::Csf => write!(f, "NIST CSF"),
        }
    }
}

/// A NIST control definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NistControl {
    /// Control identifier (e.g., "PO.1", "PR.DS").
    pub id: String,
    /// Framework this control belongs to.
    pub framework: NistFramework,
    /// Short title.
    pub title: String,
    /// Description of the control.
    pub description: String,
    /// VSEL implementation artifacts that satisfy this control.
    pub vsel_implementations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Standard NIST controls registry
// ---------------------------------------------------------------------------

/// Build the standard NIST controls registry.
///
/// Returns a map from control ID to control definition.
pub fn standard_nist_controls() -> BTreeMap<String, NistControl> {
    let mut controls = BTreeMap::new();

    // -----------------------------------------------------------------------
    // NIST SSDF SP 800-218 practices
    // -----------------------------------------------------------------------

    controls.insert(
        "PO.1".to_string(),
        NistControl {
            id: "PO.1".to_string(),
            framework: NistFramework::Ssdf,
            title: "Security Requirements".to_string(),
            description: "Define security requirements for software development".to_string(),
            vsel_implementations: vec![
                "Requirements document".to_string(),
                "Threat model (docs/THREAT_MODEL.md)".to_string(),
                "Formal specification (formal/VSEL/)".to_string(),
            ],
        },
    );

    controls.insert(
        "PS.1".to_string(),
        NistControl {
            id: "PS.1".to_string(),
            framework: NistFramework::Ssdf,
            title: "Protect Software".to_string(),
            description: "Protect all forms of code from unauthorized access and tampering"
                .to_string(),
            vsel_implementations: vec![
                "Hybrid crypto (vsel-crypto)".to_string(),
                "Key management (vsel-crypto/keys.rs)".to_string(),
                "Domain separation (vsel-crypto/domain.rs)".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.1".to_string(),
        NistControl {
            id: "PW.1".to_string(),
            framework: NistFramework::Ssdf,
            title: "Design Software".to_string(),
            description: "Design software to meet security requirements and reduce attack surface"
                .to_string(),
            vsel_implementations: vec![
                "Design document".to_string(),
                "Lean 4 formal specification".to_string(),
                "Invariant system (vsel-invariants)".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.4".to_string(),
        NistControl {
            id: "PW.4".to_string(),
            framework: NistFramework::Ssdf,
            title: "Review Design".to_string(),
            description:
                "Review the software design to verify compliance with security requirements"
                    .to_string(),
            vsel_implementations: vec![
                "Phase audit gates".to_string(),
                "Lean 4 proof checking (lake build)".to_string(),
                "TLA+ model checking".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.5".to_string(),
        NistControl {
            id: "PW.5".to_string(),
            framework: NistFramework::Ssdf,
            title: "Reuse Software".to_string(),
            description: "Reuse existing well-secured software when feasible".to_string(),
            vsel_implementations: vec![
                "Rust crates: ed25519-dalek, sha3, blake3".to_string(),
                "proptest for property-based testing".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.6".to_string(),
        NistControl {
            id: "PW.6".to_string(),
            framework: NistFramework::Ssdf,
            title: "Create Source Code".to_string(),
            description: "Create source code by adhering to secure coding practices".to_string(),
            vsel_implementations: vec![
                "Rust Cargo workspace (protocol/)".to_string(),
                "Lean 4 library (formal/VSEL/)".to_string(),
                "TLA+ models (tla/)".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.7".to_string(),
        NistControl {
            id: "PW.7".to_string(),
            framework: NistFramework::Ssdf,
            title: "Configure Software".to_string(),
            description: "Configure software to have secure settings by default".to_string(),
            vsel_implementations: vec![
                "Deterministic builds".to_string(),
                "Version pinning (Cargo.lock)".to_string(),
                "Lean toolchain pinning".to_string(),
            ],
        },
    );

    controls.insert(
        "PW.8".to_string(),
        NistControl {
            id: "PW.8".to_string(),
            framework: NistFramework::Ssdf,
            title: "Test Software".to_string(),
            description: "Test software for compliance with security requirements".to_string(),
            vsel_implementations: vec![
                "proptest property-based testing".to_string(),
                "Differential testing (Rust vs SIR)".to_string(),
                "Adversarial test suite".to_string(),
                "TLA+ model checking".to_string(),
                "Invalid witness suite (W1-W8)".to_string(),
            ],
        },
    );

    controls.insert(
        "RV.1".to_string(),
        NistControl {
            id: "RV.1".to_string(),
            framework: NistFramework::Ssdf,
            title: "Identify Vulnerabilities".to_string(),
            description: "Identify and confirm vulnerabilities on an ongoing basis".to_string(),
            vsel_implementations: vec![
                "CodeQL SAST".to_string(),
                "Dependency scanning".to_string(),
                "Underconstraint analysis (U1-U8)".to_string(),
                "Constraint coverage matrix".to_string(),
            ],
        },
    );

    controls.insert(
        "RV.2".to_string(),
        NistControl {
            id: "RV.2".to_string(),
            framework: NistFramework::Ssdf,
            title: "Assess Vulnerabilities".to_string(),
            description: "Assess, prioritize, and remediate vulnerabilities".to_string(),
            vsel_implementations: vec![
                "Severity classification (Catastrophic→Informational)".to_string(),
                "Audit evidence model (CAT-1 through CAT-6)".to_string(),
                "Phase-gated audit gates".to_string(),
            ],
        },
    );

    controls.insert(
        "RV.3".to_string(),
        NistControl {
            id: "RV.3".to_string(),
            framework: NistFramework::Ssdf,
            title: "Remediate Vulnerabilities".to_string(),
            description: "Remediate vulnerabilities to reduce the window of opportunity"
                .to_string(),
            vsel_implementations: vec![
                "Evidence lifecycle (Discovery→Closure)".to_string(),
                "Regression testing".to_string(),
                "Remediation verification".to_string(),
            ],
        },
    );

    // -----------------------------------------------------------------------
    // NIST CSF functions
    // -----------------------------------------------------------------------

    controls.insert(
        "ID".to_string(),
        NistControl {
            id: "ID".to_string(),
            framework: NistFramework::Csf,
            title: "Identify".to_string(),
            description: "Develop organizational understanding to manage cybersecurity risk"
                .to_string(),
            vsel_implementations: vec![
                "Asset management (state model)".to_string(),
                "Risk assessment (threat model)".to_string(),
                "Formal specification (Lean 4)".to_string(),
            ],
        },
    );

    controls.insert(
        "PR".to_string(),
        NistControl {
            id: "PR".to_string(),
            framework: NistFramework::Csf,
            title: "Protect".to_string(),
            description: "Develop and implement appropriate safeguards".to_string(),
            vsel_implementations: vec![
                "Access control (authorization model)".to_string(),
                "Data security (hybrid crypto)".to_string(),
                "Domain separation".to_string(),
                "Invariant enforcement".to_string(),
            ],
        },
    );

    controls.insert(
        "DE".to_string(),
        NistControl {
            id: "DE".to_string(),
            framework: NistFramework::Csf,
            title: "Detect".to_string(),
            description: "Develop and implement activities to identify cybersecurity events"
                .to_string(),
            vsel_implementations: vec![
                "Anomaly detection (invariant violations)".to_string(),
                "Trace monitoring (commitment chain)".to_string(),
                "Underconstraint detection (U1-U8)".to_string(),
            ],
        },
    );

    controls.insert(
        "RS".to_string(),
        NistControl {
            id: "RS".to_string(),
            framework: NistFramework::Csf,
            title: "Respond".to_string(),
            description:
                "Develop and implement activities to take action regarding detected events"
                    .to_string(),
            vsel_implementations: vec![
                "Incident response (error states)".to_string(),
                "Halt on invariant violation".to_string(),
                "Audit evidence generation".to_string(),
            ],
        },
    );

    controls.insert(
        "RC".to_string(),
        NistControl {
            id: "RC".to_string(),
            framework: NistFramework::Csf,
            title: "Recover".to_string(),
            description:
                "Develop and implement activities to maintain resilience and restore capabilities"
                    .to_string(),
            vsel_implementations: vec![
                "Recovery planning (trace reconstruction)".to_string(),
                "Cryptographic migration (vsel-crypto/migration.rs)".to_string(),
                "Witness archival for re-proving".to_string(),
            ],
        },
    );

    controls
}
