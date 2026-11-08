use driftguard_broker::recovery::{signed_payload, verify, RecoveryRequest};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
fn fixture() -> (Vec<u8>, Vec<u8>) {
    let keys: Vec<_> = (1..=3).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let policy = json!({"schema":"frequency-guardian-recovery-policy/v1","threshold":2,"authority_public_keys_hex":keys.iter().map(|k|hex::encode(k.verifying_key().to_bytes())).collect::<Vec<_>>()});
    let mut req = json!({"schema":"frequency-guardian-recovery/v1","existing_identity_sha256":hex::encode([4;32]),"replacement_identity_sha256":hex::encode([5;32]),"nonce_hex":hex::encode([6;32]),"expires_unix":1200,"signatures":[]});
    let typed: RecoveryRequest = serde_json::from_value(req.clone()).unwrap();
    let msg = signed_payload(&typed).unwrap();
    req["signatures"]=Value::Array(keys[0..2].iter().map(|key|json!({"authority_public_key_hex":hex::encode(key.verifying_key().to_bytes()),"signature_hex":hex::encode(key.sign(&msg).to_bytes())})).collect());
    (
        serde_json::to_vec(&policy).unwrap(),
        serde_json::to_vec(&req).unwrap(),
    )
}
#[test]
fn quorum_and_negative_cases() {
    let (policy, req) = fixture();
    let accepted = verify(&policy, &req, 1000).unwrap();
    assert!(accepted.authorization_verified);
    assert_eq!(accepted.distinct_authorities, 2);
    assert!(!accepted.device_key_replaced);
    assert!(!accepted.production_eligible);
    assert!(verify(&policy, &req, 1200).is_err());
    assert!(verify(&policy, &req, 100).is_err());
    let mut r: Value = serde_json::from_slice(&req).unwrap();
    r["replacement_identity_sha256"] = json!(hex::encode([7; 32]));
    assert!(verify(&policy, &serde_json::to_vec(&r).unwrap(), 1000).is_err());
    let mut r: Value = serde_json::from_slice(&req).unwrap();
    r["signatures"][1] = r["signatures"][0].clone();
    assert!(verify(&policy, &serde_json::to_vec(&r).unwrap(), 1000).is_err());
    let mut r: Value = serde_json::from_slice(&req).unwrap();
    r["signatures"].as_array_mut().unwrap().pop();
    assert!(verify(&policy, &serde_json::to_vec(&r).unwrap(), 1000).is_err());
    let mut p: Value = serde_json::from_slice(&policy).unwrap();
    p["threshold"] = json!(1);
    assert!(verify(&serde_json::to_vec(&p).unwrap(), &req, 1000).is_err());
    let mut r: Value = serde_json::from_slice(&req).unwrap();
    r["nonce_hex"] = json!(hex::encode([0; 32]));
    assert!(verify(&policy, &serde_json::to_vec(&r).unwrap(), 1000).is_err());
}

#[cfg(unix)]
#[test]
fn durable_one_use_nonce_rejects_replay_and_unsafe_ledger() {
    use std::os::unix::fs::PermissionsExt;
    let (policy, req) = fixture();
    assert!(verify(&policy, &req, 1000).is_ok());
    let base = tempfile::tempdir().unwrap();
    let ledger = base.path().join("ledger");
    std::fs::create_dir(&ledger).unwrap();
    std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(driftguard_broker::recovery::consume_nonce(&ledger, &req).is_ok());
    assert!(driftguard_broker::recovery::consume_nonce(&ledger, &req).is_err());
    let unsafe_ledger = base.path().join("unsafe");
    std::fs::create_dir(&unsafe_ledger).unwrap();
    std::fs::set_permissions(&unsafe_ledger, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(driftguard_broker::recovery::consume_nonce(&unsafe_ledger, &req).is_err());
    let fake = base.path().join("link");
    std::os::unix::fs::symlink(&ledger, &fake).unwrap();
    assert!(driftguard_broker::recovery::consume_nonce(&fake, &req).is_err());
}
