use base64::{engine::general_purpose::STANDARD, Engine};
use driftguard_broker::guardian_binding::{signed_bytes, verify_binding};
use serde_json::json;
use std::process::Command;
#[test]
fn valid_signature_and_all_negative_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let result = Command::new("openssl")
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        "old.pem",
    ]);
    run(&[
        "pkey", "-in", "old.pem", "-pubout", "-outform", "DER", "-out", "old.der",
    ]);
    run(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        "new.pem",
    ]);
    run(&[
        "pkey", "-in", "new.pem", "-pubout", "-outform", "DER", "-out", "new.der",
    ]);
    let old = std::fs::read(dir.path().join("old.der")).unwrap();
    let new = std::fs::read(dir.path().join("new.der")).unwrap();
    let challenge = [7u8; 32];
    std::fs::write(
        dir.path().join("payload"),
        signed_bytes(&challenge, &old, &new).unwrap(),
    )
    .unwrap();
    run(&[
        "pkeyutl", "-sign", "-inkey", "old.pem", "-in", "payload", "-rawin", "-digest", "sha256",
        "-out", "sig",
    ]);
    let sig = std::fs::read(dir.path().join("sig")).unwrap();
    let valid = json!({"schema":"frequency-guardian-candidate-binding/v1","old_public_key_spki_b64":STANDARD.encode(&old),"candidate_public_key_spki_b64":STANDARD.encode(&new),"challenge_hex":hex::encode(challenge),"signature_der_b64":STANDARD.encode(&sig),"production_eligible":false});
    let encode = |v: &serde_json::Value| serde_json::to_vec(v).unwrap();
    assert!(verify_binding(&encode(&valid), &challenge, &new).is_ok());
    let mut changed = valid.clone();
    changed["challenge_hex"] = json!(hex::encode([8u8; 32]));
    assert!(verify_binding(&encode(&changed), &challenge, &new).is_err());
    let mut changed = valid.clone();
    changed["signature_der_b64"] = json!(STANDARD.encode([4u8; 70]));
    assert!(verify_binding(&encode(&changed), &challenge, &new).is_err());
    let mut changed = valid.clone();
    changed["production_eligible"] = json!(true);
    assert!(verify_binding(&encode(&changed), &challenge, &new).is_err());
    assert!(verify_binding(&encode(&valid), &challenge, &old).is_err());
    assert!(verify_binding(&encode(&valid), &[9u8; 32], &new).is_err());
}
