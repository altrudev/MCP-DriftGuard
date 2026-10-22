use base64::{engine::general_purpose::STANDARD, Engine};
use driftguard_broker::{runner::*, *};
use ed25519_dalek::{Signer, SigningKey};
use std::{path::Path, time::Duration};

fn setup(dir: &Path) -> (ApprovedVerifier, Policy, Envelope, [u8; 32]) {
    // Inert bytes deliberately cannot be launched. No real keys or endpoints are accessed.
    std::fs::write(dir.join("verifier"), b"disposable Go binary stand-in").unwrap();
    std::fs::write(dir.join("baseline"), b"disposable baseline").unwrap();
    let p = Policy {
        schema: "mcpdrift-operator-policy/v2".into(),
        endpoint: "http://127.0.0.1:8080/mcp".into(),
        binary_sha256: digest(b"disposable Go binary stand-in"),
        baseline_sha256: digest(b"disposable baseline"),
        authorization_id: "0123456789abcdef0123456789abcdef".into(),
        issued_at: 1000,
        expires_at: 1300,
    };
    let k = SigningKey::from_bytes(&[13; 32]);
    let sig = Envelope {
        algorithm: "Ed25519".into(),
        signature: STANDARD.encode(k.sign(&canonical(&p).unwrap()).to_bytes()),
    };
    let a =
        ApprovedVerifier::load(&dir.join("verifier"), &dir.join("baseline"), &p.endpoint).unwrap();
    (a, p, sig, k.verifying_key().to_bytes())
}
fn capture(
    dir: &Path,
    exit: i32,
    stdout: &str,
    stderr: &str,
    delay_ms: u64,
) -> std::result::Result<OfflineReplay, OperationalError> {
    let path = dir.join("capture.json");
    std::fs::write(
        &path,
        serde_json::to_vec(
            &serde_json::json!({"exit":exit,"stdout":stdout,"stderr":stderr,"delay_ms":delay_ms}),
        )
        .unwrap(),
    )
    .unwrap();
    OfflineReplay::load(&path, Duration::from_millis(50))
}
const MATCH: &str = r#"{"match":true,"risk":"NONE","score":0,"changes":null}"#;
#[test]
fn go_contract_verdicts_and_operational_errors() {
    let d = tempfile::tempdir().unwrap();
    let (a, p, s, k) = setup(d.path());
    assert_eq!(
        a.argv(),
        [
            "/verifier",
            "verify",
            "--baseline",
            "/baseline.json",
            "--format",
            "json",
            &p.endpoint
        ]
    );
    for (exit, report, expected) in [
        (0, MATCH, Verdict::Match),
        (
            1,
            r#"{"match":false,"risk":"LOW","score":5,"changes":[{}]}"#,
            Verdict::Drift { score: 5 },
        ),
        (
            2,
            r#"{"match":false,"risk":"CRITICAL","score":70,"changes":[{}]}"#,
            Verdict::Drift { score: 70 },
        ),
    ] {
        let out = capture(d.path(), exit, report, "", 0)
            .unwrap()
            .run(&a, &p, &s, &k, 1001)
            .unwrap();
        assert_eq!(out.verdict, expected);
        assert_eq!(out.provenance, "offline-replay/v1");
    }
    for exit in [3, 4, 5, 6, -1, 127] {
        assert_eq!(
            capture(d.path(), exit, MATCH, "probe failed", 0)
                .unwrap()
                .run(&a, &p, &s, &k, 1001),
            Err(OperationalError::Exit(exit))
        );
    }
    for (exit, report) in [
        (1, MATCH),
        (0, "{}"),
        (0, "not json"),
        (
            2,
            r#"{"match":false,"risk":"HIGH","score":20,"changes":[{}]}"#,
        ),
    ] {
        assert_eq!(
            capture(d.path(), exit, report, "", 0)
                .unwrap()
                .run(&a, &p, &s, &k, 1001),
            Err(OperationalError::Report)
        );
    }
}
#[test]
fn tampering_endpoint_expiry_and_live_authorization_deny() {
    let d = tempfile::tempdir().unwrap();
    let (a, mut p, s, k) = setup(d.path());
    let r = capture(d.path(), 0, MATCH, "", 0).unwrap();
    assert_eq!(
        r.run(&a, &p, &s, &k, 1300),
        Err(OperationalError::Authorization)
    );
    p.endpoint.push_str("/other");
    assert_eq!(r.run(&a, &p, &s, &k, 1001), Err(OperationalError::Endpoint));
    let (_, p, s, k) = setup(d.path());
    for name in ["verifier", "baseline"] {
        setup(d.path());
        std::fs::write(d.path().join(name), b"tampered").unwrap();
        let changed = ApprovedVerifier::load(
            &d.path().join("verifier"),
            &d.path().join("baseline"),
            &p.endpoint,
        )
        .unwrap();
        assert_eq!(
            r.run(&changed, &p, &s, &k, 1001),
            Err(OperationalError::Authorization)
        );
    }
    assert_eq!(
        BubblewrapRunner.run(&a, &p, &s, &k, 1300),
        Err(OperationalError::Authorization)
    );
    assert!(ApprovedVerifier::load(
        &d.path().join("verifier"),
        &d.path().join("baseline"),
        "stdio"
    )
    .is_err());
}
#[test]
fn bounded_streams_deadline_and_nonregular_inputs() {
    let d = tempfile::tempdir().unwrap();
    let (a, p, s, k) = setup(d.path());
    assert_eq!(
        capture(d.path(), 0, MATCH, "", 1000)
            .unwrap()
            .run(&a, &p, &s, &k, 1001),
        Err(OperationalError::Deadline)
    );
    assert!(capture(d.path(), 0, &"x".repeat(65537), "", 0).is_err());
    assert!(capture(d.path(), 0, MATCH, &"x".repeat(65537), 0).is_err());
    let link = d.path().join("link");
    std::os::unix::fs::symlink(d.path().join("verifier"), &link).unwrap();
    assert!(ApprovedVerifier::load(&link, &d.path().join("baseline"), &p.endpoint).is_err());
    assert!(OfflineReplay::load(d.path(), Duration::from_secs(1)).is_err());
    assert!(OfflineReplay::load(&link, Duration::from_secs(1)).is_err());
}

/// Requires cc and static libc. Set DRIFTGUARD_REQUIRE_LIVE=1 to make unavailable
/// kernel namespaces a test failure instead of a reported skip.
#[test]
#[cfg(target_os = "linux")]
fn live_namespace_contract() {
    let d = tempfile::tempdir().unwrap();
    let binary = d.path().join("live-verifier");
    assert!(std::process::Command::new("cc")
        .args(["-static", "-O2", "tests/fixtures/verifier.c", "-o"])
        .arg(&binary)
        .status()
        .unwrap()
        .success());
    let bytes = std::fs::read(&binary).unwrap();
    for (mode, expected) in [
        (b'm', Ok(Verdict::Match)),
        (b'd', Ok(Verdict::Drift { score: 5 })),
        (b'x', Err(OperationalError::Exit(7))),
        (b'b', Err(OperationalError::Report)),
        (b'o', Err(OperationalError::Capture)),
        (b'e', Err(OperationalError::Capture)),
        (b't', Err(OperationalError::Deadline)),
    ] {
        let (_, mut p, _, _) = setup(d.path());
        std::fs::write(&binary, &bytes).unwrap();
        std::fs::write(d.path().join("baseline"), [mode]).unwrap();
        p.binary_sha256 = digest(&bytes);
        p.baseline_sha256 = digest(&[mode]);
        let key = SigningKey::from_bytes(&[13; 32]);
        let s = Envelope {
            algorithm: "Ed25519".into(),
            signature: STANDARD.encode(key.sign(&canonical(&p).unwrap()).to_bytes()),
        };
        let a = ApprovedVerifier::load(&binary, &d.path().join("baseline"), &p.endpoint).unwrap();
        // Replacement after load cannot change the authorized launch snapshots.
        std::fs::write(&binary, b"replaced").unwrap();
        std::fs::write(d.path().join("baseline"), b"replaced").unwrap();
        assert_eq!(
            BubblewrapRunner.run(&a, &p, &s, &key.verifying_key().to_bytes(), 1300),
            Err(OperationalError::Authorization)
        );
        let out = BubblewrapRunner.run(&a, &p, &s, &key.verifying_key().to_bytes(), 1001);
        if mode == b'm' && out == Err(OperationalError::IsolationUnavailable) {
            assert!(
                std::env::var_os("DRIFTGUARD_REQUIRE_LIVE").is_none(),
                "live namespaces required but unavailable"
            );
            eprintln!("SKIP live execution: Bubblewrap namespaces unavailable");
            return;
        }
        match out {
            Ok(out) => {
                assert_eq!(Ok(out.verdict), expected);
                assert_eq!(out.provenance, "bubblewrap-live/v1");
            }
            Err(err) => assert_eq!(Err(err), expected),
        }
    }
}
