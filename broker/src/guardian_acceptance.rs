//! Offline bridge between Android diagnostic export and independent certificate verifier.
//! A passing bridge result never implies production enrollment or device recovery.
use crate::{attestation, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    status: String,
    detail: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostics {
    schema: String,
    version: String,
    created_unix: u64,
    production_eligible: bool,
    private_keys_exported: bool,
    external_attestation_challenge_required: bool,
    checks: BTreeMap<String, Check>,
}
#[derive(Serialize)]
pub struct Acceptance {
    pub schema: &'static str,
    pub diagnostic_version: String,
    pub local_checks_passed: usize,
    pub attestation_chain_verified_against_supplied_pin: bool,
    pub challenge_matches: bool,
    pub candidate_binding_verified: bool,
    pub independent_application_identity_verified: bool,
    pub revocation_verified: bool,
    pub recovery_operational: bool,
    pub production_eligible: bool,
    pub verdict: &'static str,
}
pub fn verify(
    diagnostic_json: &[u8],
    attestation_json: &[u8],
    challenge: &[u8],
    root_pin: &[u8],
    binding_json: &[u8],
    expected_package: &str,
    expected_signer_digest: &[u8],
) -> Result<Acceptance> {
    if diagnostic_json.len() > 70000 {
        return Err("diagnostic exceeds allowed size".into());
    }
    let d: Diagnostics = serde_json::from_slice(diagnostic_json)?;
    if d.schema != "frequency-guardian-diagnostics/v3"
        || !(d.version == "0.3.0" || d.version == "0.4.0")
        || d.created_unix == 0
        || d.production_eligible
        || d.private_keys_exported
        || !d.external_attestation_challenge_required
    {
        return Err("diagnostic security contract violation".into());
    }
    const NAMES: [&str; 10] = [
        "hardware",
        "ecdsa",
        "tampering",
        "nonce",
        "expiry",
        "identity_continuity",
        "strongbox",
        "attestation_certificate_status",
        "recovery_readiness",
        "update",
    ];
    if d.checks.len() != NAMES.len() || NAMES.iter().any(|n| !d.checks.contains_key(*n)) {
        return Err("missing or unexpected diagnostics".into());
    }
    for check in d.checks.values() {
        if !["pass", "fail", "pending"].contains(&check.status.as_str())
            || check.detail.len() > 4096
        {
            return Err("invalid check".into());
        }
    }
    for n in [
        "hardware",
        "ecdsa",
        "tampering",
        "nonce",
        "expiry",
        "strongbox",
    ] {
        if d.checks[n].status != "pass" {
            return Err("required local check is not passed".into());
        }
    }
    for n in [
        "identity_continuity",
        "attestation_certificate_status",
        "recovery_readiness",
        "update",
    ] {
        if d.checks[n].status == "fail" {
            return Err("local acceptance failure".into());
        }
    }
    let a = attestation::verify_export(attestation_json, challenge, root_pin)?;
    if !a.chain_signatures_verified_against_supplied_pin || !a.challenge_matches || !a.p256 {
        return Err("incomplete certificate verification".into());
    }
    attestation::verify_application_id(attestation_json, expected_package, expected_signer_digest)?;
    let spki = attestation::candidate_spki(attestation_json)?;
    crate::guardian_binding::verify_binding(binding_json, challenge, &spki)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    Ok(Acceptance {
        schema: "frequency-guardian-independent-acceptance/v1",
        diagnostic_version: d.version,
        local_checks_passed: 6,
        attestation_chain_verified_against_supplied_pin: true,
        challenge_matches: true,
        candidate_binding_verified: true,
        independent_application_identity_verified: true,
        revocation_verified: false,
        recovery_operational: false,
        production_eligible: false,
        verdict: "PENDING_INDEPENDENT_TRUST",
    })
}
