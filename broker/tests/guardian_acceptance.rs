use driftguard_broker::guardian_acceptance::verify;
use serde_json::json;
fn diagnostic() -> Vec<u8> {
    let mut checks = serde_json::Map::new();
    for n in [
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
    ] {
        checks.insert(n.into(),json!({"status":if ["identity_continuity","attestation_certificate_status","recovery_readiness","update"].contains(&n){"pending"}else{"pass"},"detail":"observed"}));
    }
    serde_json::to_vec(&json!({"schema":"frequency-guardian-diagnostics/v3","version":"0.3.0","created_unix":1792729087u64,"production_eligible":false,"private_keys_exported":false,"external_attestation_challenge_required":true,"checks":checks})).unwrap()
}
#[test]
fn refuses_unverified_or_forged_inputs() {
    let diag = diagnostic();
    let fake = b"{}";
    assert!(verify(
        &diag,
        fake,
        &[3; 32],
        &[4; 32],
        b"{}",
        "dev.frequency.guardian",
        &[5; 32]
    )
    .is_err());
    let mut d: serde_json::Value = serde_json::from_slice(&diag).unwrap();
    d["production_eligible"] = json!(true);
    assert!(verify(
        &serde_json::to_vec(&d).unwrap(),
        fake,
        &[3; 32],
        &[4; 32],
        b"{}",
        "dev.frequency.guardian",
        &[5; 32],
    )
    .is_err());
    d["production_eligible"] = json!(false);
    d["checks"]["hardware"]["status"] = json!("fail");
    assert!(verify(
        &serde_json::to_vec(&d).unwrap(),
        fake,
        &[3; 32],
        &[4; 32],
        b"{}",
        "dev.frequency.guardian",
        &[5; 32],
    )
    .is_err());
    d["checks"]["hardware"]["status"] = json!("pass");
    d["checks"].as_object_mut().unwrap().remove("update");
    assert!(verify(
        &serde_json::to_vec(&d).unwrap(),
        fake,
        &[3; 32],
        &[4; 32],
        b"{}",
        "dev.frequency.guardian",
        &[5; 32],
    )
    .is_err());
}
