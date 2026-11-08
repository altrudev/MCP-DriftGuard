use base64::{engine::general_purpose::STANDARD, Engine};
use driftguard_broker::attestation::verify_export;
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Stdio},
};
fn der(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.extend([0x81, value.len() as u8]);
    }
    out.extend(value);
    out
}
fn description(level: u8, challenge: &[u8]) -> Vec<u8> {
    let mut hw = Vec::new();
    for (tag, value) in [
        (vec![0xa2], vec![2]),
        (vec![0xa3], vec![1, 0]),
        (vec![0xaa], vec![1]),
        (vec![0xbf, 0x85, 0x3e], vec![0]),
    ] {
        hw.extend(der(&tag, &der(&[2], &value)));
    }
    let mut fields = Vec::new();
    for (tag, value) in [
        (2, vec![4]),
        (10, vec![level]),
        (2, vec![4]),
        (10, vec![level]),
        (4, challenge.to_vec()),
        (4, vec![]),
        (0x30, vec![]),
        (0x30, hw),
    ] {
        fields.extend(der(&[tag], &value));
    }
    der(&[0x30], &fields)
}
fn openssl(dir: &std::path::Path, args: &[&str]) {
    assert!(Command::new("/usr/bin/openssl")
        .env_clear()
        .env("OPENSSL_CONF", "/dev/null")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
}
#[test]
fn pinned_chain_challenge_properties_and_signature() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    openssl(
        p,
        &[
            "req",
            "-new",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Disposable Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    openssl(
        p,
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=Diagnostic Test Leaf",
        ],
    );
    openssl(
        p,
        &[
            "x509", "-in", "root.pem", "-outform", "DER", "-out", "root.der",
        ],
    );
    let root = fs::read(p.join("root.der")).unwrap();
    let pin = Sha256::digest(&root);
    let challenge = [42; 32];
    for level in [1, 2, 0] {
        let ext = hex::encode(description(level, &challenge));
        fs::write(p.join("ext.cnf"),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n1.3.6.1.4.1.11129.2.1.17=DER:{ext}\n")).unwrap();
        openssl(
            p,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "root.key",
                "-set_serial",
                "2",
                "-out",
                "leaf.pem",
                "-days",
                "1",
                "-extfile",
                "ext.cnf",
            ],
        );
        openssl(
            p,
            &[
                "x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der",
            ],
        );
        let leaf = fs::read(p.join("leaf.der")).unwrap();
        let export = |leaf: &[u8]| {
            serde_json::to_vec(&serde_json::json!({"schema":"frequency-guardian-attestation/v2","purpose":"diagnostic-only","production_eligible":false,"attestation_verified":false,"certificates_der_b64":[STANDARD.encode(leaf), STANDARD.encode(&root)]})).unwrap()
        };
        let result = verify_export(&export(&leaf), &challenge, &pin);
        if level == 0 {
            assert!(result.is_err());
            continue;
        }
        let report = result.unwrap();
        assert!(report.chain_signatures_verified_against_supplied_pin);
        assert!(!report.production_eligible);
        assert!(!report.enrollment_enabled);
        assert!(verify_export(&export(&leaf), &[43; 32], &pin).is_err());
        assert!(verify_export(&export(&leaf), &challenge, &[0; 32]).is_err());
        let mut corrupt = leaf.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify_export(&export(&corrupt), &challenge, &pin).is_err());
    }
}
