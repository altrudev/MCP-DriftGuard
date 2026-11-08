//! One-time live execution coordination. Records are unsigned, never signed evidence.
use crate::{canonical, consume, digest, fixed_key, runner::*, Envelope, Policy, APPROVAL_KEY};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Immutable authorization bound to the retained artifact snapshots.
/// Construction checks the signature, endpoint, artifacts and current time.
pub struct ValidatedAuthorization<'a> {
    approved: &'a ApprovedVerifier,
    policy: Policy,
    signature: Envelope,
    key: [u8; 32],
}
impl<'a> ValidatedAuthorization<'a> {
    /// Uses only the administrator-provisioned approval public key.
    pub fn validate(
        approved: &'a ApprovedVerifier,
        policy: &Policy,
        signature: &Envelope,
    ) -> crate::Result<Self> {
        Self::validate_at(
            approved,
            policy,
            signature,
            fixed_key(APPROVAL_KEY)?,
            now()?,
        )
    }
    fn validate_at(
        approved: &'a ApprovedVerifier,
        policy: &Policy,
        signature: &Envelope,
        key: [u8; 32],
        now: u64,
    ) -> crate::Result<Self> {
        approved
            .authorize(policy, signature, &key, now)
            .map_err(|e| format!("authorization: {e:?}"))?;
        Ok(Self {
            approved,
            policy: policy.clone(),
            signature: signature.clone(),
            key,
        })
    }
}
fn now() -> crate::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Debug, Serialize)]
pub struct ExecutionRecord {
    pub schema: &'static str,
    pub policy_sha256: String,
    pub authorization_id: String,
    pub consumed_at: u64,
    pub consumed: bool,
    /// Present only when the runner returned a validated verifier report.
    pub verdict: Option<Verdict>,
    pub provenance: &'static str,
    pub failure_class: Option<OperationalError>,
}

/// The embedding service must select one protected, permanent ledger at startup.
/// No ledger is created and no fallback directory is used.
pub struct Coordinator {
    ledger: PathBuf,
}
impl Coordinator {
    pub fn new(ledger: &Path) -> Self {
        Self {
            ledger: ledger.into(),
        }
    }
    pub fn execute(
        &self,
        authorization: ValidatedAuthorization<'_>,
    ) -> crate::Result<ExecutionRecord> {
        self.execute_at(authorization, now()?, &BubblewrapRunner)
    }
    // Runner injection and clock injection are private; production always uses Bubblewrap.
    fn execute_at(
        &self,
        a: ValidatedAuthorization<'_>,
        now: u64,
        runner: &impl ExecutionRunner,
    ) -> crate::Result<ExecutionRecord> {
        let policy_sha256 = digest(&canonical(&a.policy)?);
        // Revalidate expiry and durably win exclusive creation BEFORE any runner call.
        // Any error here denies execution; a partially written marker stays burned.
        consume(
            &self.ledger,
            &a.policy,
            &a.signature,
            &a.key,
            &a.approved.binary,
            &a.approved.baseline,
            now,
        )?;
        let result = runner.run(a.approved, &a.policy, &a.signature, &a.key, now);
        let (verdict, provenance, failure_class) = match result {
            Ok(out) => (Some(out.verdict), out.provenance, None),
            Err(error) => (None, "bubblewrap-attempt/v1", Some(error)),
        };
        Ok(ExecutionRecord {
            schema: "mcpdrift-unsigned-execution/v1",
            policy_sha256,
            authorization_id: a.policy.authorization_id,
            consumed_at: now,
            consumed: true,
            verdict,
            provenance,
            failure_class,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use std::{cell::Cell, os::unix::fs::PermissionsExt};

    struct Fixture {
        dir: tempfile::TempDir,
        approved: ApprovedVerifier,
        policy: Policy,
        signature: Envelope,
        key: [u8; 32],
    }
    impl Fixture {
        fn new(live: bool) -> Self {
            Self::with_mode(live, b'm')
        }
        fn with_mode(live: bool, mode: u8) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let binary = dir.path().join("verifier");
            if live {
                assert!(std::process::Command::new("cc")
                    .args(["-static", "-O2", "tests/fixtures/verifier.c", "-o"])
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success());
            } else {
                std::fs::write(&binary, b"inert").unwrap();
            }
            let baseline = dir.path().join("baseline");
            std::fs::write(&baseline, [mode]).unwrap();
            let ledger = dir.path().join("ledger");
            std::fs::create_dir(&ledger).unwrap();
            std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(0o700)).unwrap();
            let policy = Policy {
                schema: "mcpdrift-operator-policy/v2".into(),
                endpoint: "http://127.0.0.1:8080/mcp".into(),
                binary_sha256: digest(&std::fs::read(&binary).unwrap()),
                baseline_sha256: digest(&[mode]),
                authorization_id: "0123456789abcdef0123456789abcdef".into(),
                issued_at: 1000,
                expires_at: 1300,
            };
            let key = SigningKey::from_bytes(&[71; 32]);
            let signature = Envelope {
                algorithm: "Ed25519".into(),
                signature: STANDARD.encode(key.sign(&canonical(&policy).unwrap()).to_bytes()),
            };
            let approved = ApprovedVerifier::load(&binary, &baseline, &policy.endpoint).unwrap();
            Self {
                dir,
                approved,
                policy,
                signature,
                key: key.verifying_key().to_bytes(),
            }
        }
        fn authorization(&self) -> ValidatedAuthorization<'_> {
            ValidatedAuthorization::validate_at(
                &self.approved,
                &self.policy,
                &self.signature,
                self.key,
                1001,
            )
            .unwrap()
        }
        fn coordinator(&self) -> Coordinator {
            Coordinator::new(&self.dir.path().join("ledger"))
        }
    }
    struct Failing<'a> {
        marker: PathBuf,
        calls: &'a Cell<u32>,
    }
    impl ExecutionRunner for Failing<'_> {
        fn run(
            &self,
            _: &ApprovedVerifier,
            _: &Policy,
            _: &Envelope,
            _: &[u8; 32],
            _: u64,
        ) -> Result<Outcome, OperationalError> {
            assert!(self.marker.exists(), "consumption must precede invocation");
            self.calls.set(self.calls.get() + 1);
            Err(OperationalError::Exit(7))
        }
    }
    #[test]
    fn failure_burns_id_and_record_binds_exact_policy() {
        let f = Fixture::new(false);
        let calls = Cell::new(0);
        let runner = Failing {
            marker: f.dir.path().join("ledger").join(&f.policy.authorization_id),
            calls: &calls,
        };
        let c = f.coordinator();
        let r = c.execute_at(f.authorization(), 1002, &runner).unwrap();
        assert_eq!(r.policy_sha256, digest(&canonical(&f.policy).unwrap()));
        assert_eq!(r.authorization_id, f.policy.authorization_id);
        assert_eq!(r.failure_class, Some(OperationalError::Exit(7)));
        assert_eq!(r.verdict, None);
        assert_eq!(r.provenance, "bubblewrap-attempt/v1");
        assert_eq!(
            std::fs::read_to_string(&runner.marker).unwrap(),
            format!("{}\n", r.policy_sha256)
        );
        assert!(c.execute_at(f.authorization(), 1002, &runner).is_err());
        assert_eq!(calls.get(), 1);
        assert!(serde_json::to_value(&r).unwrap().get("signature").is_none());
    }
    #[test]
    fn successful_record_preserves_observed_verdict_and_provenance() {
        struct Observed;
        impl ExecutionRunner for Observed {
            fn run(
                &self,
                _: &ApprovedVerifier,
                _: &Policy,
                _: &Envelope,
                _: &[u8; 32],
                _: u64,
            ) -> Result<Outcome, OperationalError> {
                Ok(Outcome {
                    verdict: Verdict::Drift { score: 5 },
                    provenance: "test-observation/v1",
                })
            }
        }
        let f = Fixture::new(false);
        let r = f
            .coordinator()
            .execute_at(f.authorization(), 1002, &Observed)
            .unwrap();
        assert_eq!(r.verdict, Some(Verdict::Drift { score: 5 }));
        assert_eq!(r.provenance, "test-observation/v1");
        assert_eq!(r.failure_class, None);
    }
    #[test]
    fn invalid_signature_expiry_missing_and_unsafe_ledger_deny_before_runner() {
        let mut f = Fixture::new(false);
        f.signature.signature = STANDARD.encode([0; 64]);
        assert!(ValidatedAuthorization::validate_at(
            &f.approved,
            &f.policy,
            &f.signature,
            f.key,
            1001
        )
        .is_err());
        let f = Fixture::new(false);
        assert!(ValidatedAuthorization::validate_at(
            &f.approved,
            &f.policy,
            &f.signature,
            f.key,
            1300
        )
        .is_err());
        let calls = Cell::new(0);
        let runner = Failing {
            marker: f.dir.path().join("ledger").join(&f.policy.authorization_id),
            calls: &calls,
        };
        assert!(f
            .coordinator()
            .execute_at(f.authorization(), 1300, &runner)
            .is_err());
        assert!(!runner.marker.exists());
        let missing = Coordinator::new(&f.dir.path().join("missing"));
        assert!(missing
            .execute_at(f.authorization(), 1002, &runner)
            .is_err());
        let link = f.dir.path().join("link");
        std::os::unix::fs::symlink(f.dir.path().join("ledger"), &link).unwrap();
        assert!(Coordinator::new(&link)
            .execute_at(f.authorization(), 1002, &runner)
            .is_err());
        std::fs::set_permissions(
            f.dir.path().join("ledger"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(f
            .coordinator()
            .execute_at(f.authorization(), 1002, &runner)
            .is_err());
        assert_eq!(calls.get(), 0);
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn live_coordinator_failed_fixture_burns_id() {
        let f = Fixture::with_mode(true, b'x');
        let c = f.coordinator();
        let r = c
            .execute_at(f.authorization(), 1002, &BubblewrapRunner)
            .unwrap();
        assert!(c
            .execute_at(f.authorization(), 1002, &BubblewrapRunner)
            .is_err());
        if r.failure_class == Some(OperationalError::IsolationUnavailable) {
            assert!(
                std::env::var_os("DRIFTGUARD_REQUIRE_LIVE").is_none(),
                "live namespaces required but unavailable"
            );
            eprintln!("SKIP live failed fixture: namespaces unavailable; ID still burned");
            return;
        }
        assert_eq!(r.failure_class, Some(OperationalError::Exit(7)));
        assert_eq!(r.verdict, None);
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn live_coordinator_authorized_fixture_execution() {
        let f = Fixture::new(true);
        let c = f.coordinator();
        let r = c
            .execute_at(f.authorization(), 1002, &BubblewrapRunner)
            .unwrap();
        assert!(c
            .execute_at(f.authorization(), 1002, &BubblewrapRunner)
            .is_err());
        if r.failure_class == Some(OperationalError::IsolationUnavailable) {
            assert!(
                std::env::var_os("DRIFTGUARD_REQUIRE_LIVE").is_none(),
                "live namespaces required but unavailable"
            );
            eprintln!("SKIP live coordinator: namespaces unavailable; ID still burned");
            return;
        }
        assert_eq!(r.failure_class, None);
        assert_eq!(r.verdict, Some(Verdict::Match));
        assert_eq!(r.provenance, "bubblewrap-live/v1");
    }
}
