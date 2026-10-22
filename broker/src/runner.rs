//! Separate execution boundary. Replay never launches a process or contacts an endpoint.
use crate::{check, endpoint_valid, Envelope, Policy};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};

const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
const CAPTURE_LIMIT: usize = 64 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum OperationalError {
    Authorization,
    Artifact,
    Endpoint,
    Capture,
    Deadline,
    Report,
    Exit(i32),
    IsolationUnavailable,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Match,
    Drift { score: u8 },
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    /// Replay is diagnostic input, never evidence of live execution.
    pub provenance: &'static str,
}
/// Administrator-selected configuration; no command, shell, arguments or environment input.
/// The executable bytes are authorized but never executed by this offline implementation.
pub struct ApprovedVerifier {
    binary: Vec<u8>,
    baseline: Vec<u8>,
    endpoint: String,
}
fn artifact(path: &Path) -> Result<Vec<u8>, OperationalError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| OperationalError::Artifact)?;
    let meta = file.metadata().map_err(|_| OperationalError::Artifact)?;
    if !meta.is_file() || meta.len() > ARTIFACT_LIMIT {
        return Err(OperationalError::Artifact);
    }
    let mut bytes = Vec::new();
    file.take(ARTIFACT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OperationalError::Artifact)?;
    if bytes.len() as u64 > ARTIFACT_LIMIT {
        return Err(OperationalError::Artifact);
    }
    Ok(bytes)
}
impl ApprovedVerifier {
    pub fn load(
        binary: &Path,
        baseline: &Path,
        approved_endpoint: &str,
    ) -> Result<Self, OperationalError> {
        if !endpoint_valid(approved_endpoint) {
            return Err(OperationalError::Endpoint);
        }
        Ok(Self {
            binary: artifact(binary)?,
            baseline: artifact(baseline)?,
            endpoint: approved_endpoint.into(),
        })
    }
    /// Fixed invocation contract for a future isolated implementation. Paths inside the
    /// namespace are constants; no caller-provided command can enter this vector.
    pub fn argv(&self) -> [&str; 7] {
        [
            "/verifier",
            "verify",
            "--baseline",
            "/baseline.json",
            "--format",
            "json",
            &self.endpoint,
        ]
    }
    pub fn authorize(
        &self,
        policy: &Policy,
        signature: &Envelope,
        key: &[u8; 32],
        now: u64,
    ) -> Result<(), OperationalError> {
        if policy.endpoint != self.endpoint {
            return Err(OperationalError::Endpoint);
        }
        check(policy, signature, key, &self.binary, &self.baseline, now)
            .map_err(|_| OperationalError::Authorization)?;
        Ok(())
    }
}
/// No public arbitrary-command transport. Live isolation is intentionally unavailable.
pub trait ExecutionRunner {
    fn run(
        &self,
        approved: &ApprovedVerifier,
        policy: &Policy,
        signature: &Envelope,
        key: &[u8; 32],
        now: u64,
    ) -> Result<Outcome, OperationalError>;
}
pub struct BubblewrapRunner;
impl ExecutionRunner for BubblewrapRunner {
    fn run(
        &self,
        _: &ApprovedVerifier,
        _: &Policy,
        _: &Envelope,
        _: &[u8; 32],
        _: u64,
    ) -> Result<Outcome, OperationalError> {
        // Never fall back to direct execution, sudo, setuid, or host networking.
        Err(OperationalError::IsolationUnavailable)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    exit: i32,
    stdout: String,
    stderr: String,
    delay_ms: u64,
}
/// Disposable regular-file capture. Delay simulates a stalled transport for deadline tests.
/// Contains no executable path and cannot launch the approved verifier.
pub struct OfflineReplay {
    capture: Capture,
    deadline: Duration,
}
impl OfflineReplay {
    pub fn load(path: &Path, deadline: Duration) -> Result<Self, OperationalError> {
        if deadline.is_zero() || deadline > Duration::from_secs(30) {
            return Err(OperationalError::Deadline);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| OperationalError::Capture)?;
        if !file
            .metadata()
            .map_err(|_| OperationalError::Capture)?
            .is_file()
        {
            return Err(OperationalError::Capture);
        }
        // JSON escapes can expand capture size, but the wire and each decoded stream are bounded.
        let mut bytes = Vec::new();
        file.take((CAPTURE_LIMIT * 16 + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| OperationalError::Capture)?;
        if bytes.len() > CAPTURE_LIMIT * 16 {
            return Err(OperationalError::Capture);
        }
        let capture: Capture =
            serde_json::from_slice(&bytes).map_err(|_| OperationalError::Capture)?;
        if capture.stdout.len() > CAPTURE_LIMIT || capture.stderr.len() > CAPTURE_LIMIT {
            return Err(OperationalError::Capture);
        }
        Ok(Self { capture, deadline })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    r#match: bool,
    risk: String,
    score: u8,
    changes: Option<Vec<serde_json::Value>>,
}
impl ExecutionRunner for OfflineReplay {
    fn run(
        &self,
        approved: &ApprovedVerifier,
        policy: &Policy,
        signature: &Envelope,
        key: &[u8; 32],
        now: u64,
    ) -> Result<Outcome, OperationalError> {
        let started = Instant::now();
        approved.authorize(policy, signature, key, now)?;
        let delay = Duration::from_millis(self.capture.delay_ms);
        let remaining = self.deadline.saturating_sub(started.elapsed());
        std::thread::sleep(delay.min(remaining));
        if started.elapsed() >= self.deadline {
            return Err(OperationalError::Deadline);
        }
        if !(0..=2).contains(&self.capture.exit) {
            return Err(OperationalError::Exit(self.capture.exit));
        }
        let r: Report =
            serde_json::from_str(&self.capture.stdout).map_err(|_| OperationalError::Report)?;
        let changes = r.changes.as_deref().unwrap_or_default();
        let risk = match r.score {
            0 => "NONE",
            1..=14 => "LOW",
            15..=34 => "MEDIUM",
            35..=69 => "HIGH",
            _ => "CRITICAL",
        };
        if r.score > 100
            || r.r#match != (self.capture.exit == 0)
            || (r.r#match && (r.score != 0 || !changes.is_empty()))
            || (!r.r#match && (changes.is_empty() || (r.score >= 35) != (self.capture.exit == 2)))
            || r.risk != risk
        {
            return Err(OperationalError::Report);
        }
        if started.elapsed() >= self.deadline {
            return Err(OperationalError::Deadline);
        }
        Ok(Outcome {
            verdict: if r.r#match {
                Verdict::Match
            } else {
                Verdict::Drift { score: r.score }
            },
            provenance: "offline-replay/v1",
        })
    }
}
