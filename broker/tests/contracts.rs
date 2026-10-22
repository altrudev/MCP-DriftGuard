use base64::{engine::general_purpose::STANDARD, Engine};
use driftguard_broker::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::Arc,
};
fn fixture() -> (Policy, SigningKey) {
    (
        Policy {
            schema: "mcpdrift-operator-policy/v2".into(),
            endpoint: "http://127.0.0.1:8080/mcp".into(),
            binary_sha256: digest(b"binary"),
            baseline_sha256: digest(b"baseline"),
            authorization_id: "0123456789abcdef0123456789abcdef".into(),
            issued_at: 1000,
            expires_at: 1300,
        },
        SigningKey::from_bytes(&[42; 32]),
    )
}
fn sign<T: serde::Serialize>(p: &T, k: &SigningKey) -> Envelope {
    Envelope {
        algorithm: "Ed25519".into(),
        signature: STANDARD.encode(k.sign(&canonical(p).unwrap()).to_bytes()),
    }
}
#[test]
fn signed_policy_and_independent_evidence() {
    let (p, k) = fixture();
    let sig = sign(&p, &k);
    let key = k.verifying_key().to_bytes();
    let mut e = check(&p, &sig, &key, b"binary", b"baseline", 1000).unwrap();
    let evidence_key = SigningKey::from_bytes(&[99; 32]);
    let es = sign(&e, &evidence_key);
    verify_evidence(&e, &es, &evidence_key.verifying_key().to_bytes(), &p).unwrap();
    assert!(verify_evidence(&e, &es, &key, &p).is_err());
    e.consumed = true;
    assert!(verify_evidence(&e, &es, &evidence_key.verifying_key().to_bytes(), &p).is_err());
    assert!(check(&p, &sig, &key, b"changed", b"baseline", 1001).is_err());
    assert!(check(&p, &sig, &[0; 32], b"binary", b"baseline", 1001).is_err());
}
#[test]
fn mutation_and_time_boundaries() {
    let (p, k) = fixture();
    let sig = sign(&p, &k);
    let key = k.verifying_key().to_bytes();
    for now in [0, 999, 1300, u64::MAX] {
        assert!(check(&p, &sig, &key, b"binary", b"baseline", now).is_err());
    }
    assert!(p.validate(1299).is_ok());
    let mut q = p.clone();
    q.endpoint.push_str("/changed");
    assert!(check(&q, &sig, &key, b"binary", b"baseline", 1001).is_err());
    for expiry in [999, 1000, 1301, u64::MAX] {
        q = p.clone();
        q.expires_at = expiry;
        assert!(q.validate(1000).is_err());
    }
    q = p.clone();
    q.authorization_id = "../escape".into();
    assert!(q.validate(1000).is_err());
    q = p.clone();
    q.binary_sha256 = "A".repeat(64);
    assert!(q.validate(1000).is_err());
}
#[test]
fn strict_json_and_endpoint_contract() {
    let (p, _) = fixture();
    let json = String::from_utf8(canonical(&p).unwrap()).unwrap();
    for bad in [
        json.replace("1000", "true"),
        json.replace("1000", "1000.0"),
        json.replace("1000", "-1"),
        json.replace("1000", "1e3"),
        json.replace("{", "{\"extra\":1,"),
        json.replace("{", "{\"schema\":\"duplicate\","),
    ] {
        assert!(serde_json::from_str::<Policy>(&bad).is_err(), "{bad}");
    }
    for ep in [
        "https://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1.evil",
        "http://127.0.0.1@evil",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1/#x",
        "http://127.0.0.1/\n",
        "http://127.0.0.1\\evil",
    ] {
        assert!(!endpoint_valid(ep), "{ep}");
    }
    assert!(endpoint_valid("http://127.0.0.1:8080/mcp?q=1"));
    assert!(json.starts_with("{\"authorization_id\":"));
}
#[test]
fn exclusive_replay_concurrency_and_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (p, k) = fixture();
    let key = k.verifying_key().to_bytes();
    let shared = Arc::new(dir);
    let threads: Vec<_> = (0..12)
        .map(|_| {
            let d = shared.clone();
            let p = p.clone();
            let sig = sign(&p, &k);
            std::thread::spawn(move || {
                consume(d.path(), &p, &sig, &key, b"binary", b"baseline", 1001).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(shared.path().join(&p.authorization_id)).unwrap(),
        format!("{}\n", digest(&canonical(&p).unwrap()))
    );
    let mut q = p.clone();
    q.endpoint.push_str("/different");
    assert!(consume(
        shared.path(),
        &q,
        &sign(&q, &k),
        &key,
        b"binary",
        b"baseline",
        1001
    )
    .is_err());
    let other = tempfile::tempdir().unwrap();
    symlink("/does-not-exist", other.path().join(&p.authorization_id)).unwrap();
    assert!(consume(
        other.path(),
        &p,
        &sign(&p, &k),
        &key,
        b"binary",
        b"baseline",
        1001
    )
    .is_err());
    std::fs::set_permissions(other.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(consume(
        other.path(),
        &p,
        &sign(&p, &k),
        &key,
        b"binary",
        b"baseline",
        1001
    )
    .is_err());
}
#[test]
fn invalid_signature_never_burns() {
    let dir = tempfile::tempdir().unwrap();
    let (p, k) = fixture();
    let mut sig = sign(&p, &k);
    sig.algorithm = "other".into();
    assert!(consume(
        dir.path(),
        &p,
        &sig,
        &k.verifying_key().to_bytes(),
        b"binary",
        b"baseline",
        1001
    )
    .is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn python_generated_signature_and_exact_canonical_bytes() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        policy: Policy,
        canonical: String,
        key_hex: String,
        envelope: Envelope,
    }
    let f: Fixture = serde_json::from_str(include_str!("fixtures/python-policy.json")).unwrap();
    let key: [u8; 32] = hex::decode(f.key_hex).unwrap().try_into().unwrap();
    assert_eq!(canonical(&f.policy).unwrap(), f.canonical.as_bytes());
    check(&f.policy, &f.envelope, &key, b"binary", b"baseline", 1001).unwrap();
}
#[test]
fn cli_denies_invalid_invocation_and_malformed_policy() {
    let exe = env!("CARGO_BIN_EXE_driftguard-broker");
    let out = std::process::Command::new(exe).output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("policy.json");
    std::fs::write(&path, b"{}").unwrap();
    let out = std::process::Command::new(exe)
        .arg("check")
        .arg(&path)
        .args(["missing", "missing", "missing", "http://127.0.0.1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn signed_but_inconsistent_evidence_and_invalid_envelopes_fail() {
    let (p, k) = fixture();
    let key = k.verifying_key().to_bytes();
    let sig = sign(&p, &k);
    let mut e = check(&p, &sig, &key, b"binary", b"baseline", 1001).unwrap();
    e.policy_sha256 = "0".repeat(64);
    assert!(verify_evidence(&e, &sign(&e, &k), &key, &p).is_err());
    for text in ["!", "", "AAAA", "AA==\n"] {
        let s = Envelope {
            algorithm: "Ed25519".into(),
            signature: text.into(),
        };
        assert!(verify_signature(&p, &s, &key).is_err());
    }
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("oversized");
    std::fs::write(&f, vec![b' '; 65537]).unwrap();
    assert!(read_json::<Policy>(&f).is_err());
}
