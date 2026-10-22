//! Experimental execution boundary. Replay never launches a process.
use crate::{check, endpoint_valid, Envelope, Policy};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};

const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
const CAPTURE_LIMIT: usize = 64 * 1024;
#[derive(Debug, PartialEq, Eq, Serialize)]
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
#[derive(Debug, PartialEq, Eq, Serialize)]
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
/// Artifact bytes are retained so launch never reopens caller-selected paths.
pub struct ApprovedVerifier {
    pub(crate) binary: Vec<u8>,
    pub(crate) baseline: Vec<u8>,
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
    /// Fixed invocation contract. Paths inside the
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
/// No public arbitrary-command transport.
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
        approved: &ApprovedVerifier,
        policy: &Policy,
        signature: &Envelope,
        key: &[u8; 32],
        now: u64,
    ) -> Result<Outcome, OperationalError> {
        approved.authorize(policy, signature, key, now)?;
        live::run(approved)
    }
}

#[cfg(target_os = "linux")]
mod live {
    use super::*;
    use std::{
        fs::File,
        io::{Seek, Write},
        os::fd::{AsRawFd, FromRawFd},
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };

    // Never print artifact bytes, endpoint, or environment. Debug escaping keeps
    // bounded child diagnostics on one line, even for control characters.
    fn diagnostic(stage: &str, detail: &str) {
        eprintln!("driftguard isolation failure: stage={stage}; detail={detail:?}");
    }

    // Sealing prevents mutation after authorization, including through another fd.
    fn snapshot(bytes: &[u8], mode: u32) -> Result<File, OperationalError> {
        let fd = unsafe {
            libc::memfd_create(
                c"driftguard".as_ptr(),
                libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
            )
        };
        if fd < 0 {
            diagnostic("memfd_create", &std::io::Error::last_os_error().to_string());
            return Err(OperationalError::IsolationUnavailable);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .map_err(|_| OperationalError::Artifact)?;
        if unsafe { libc::fchmod(fd, mode) } != 0
            || unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } < 0
        {
            return Err(OperationalError::Artifact);
        }
        // Data options consume the descriptor from its current offset.
        file.rewind().map_err(|_| OperationalError::Artifact)?;
        Ok(file)
    }

    // This runs after fork in a potentially threaded broker: only raw syscalls,
    // fcntl and errno conversion are allowed (no allocation, locks or /proc walk).
    fn inherit_snapshots(fds: [i32; 2]) -> std::io::Result<()> {
        // Deny inheritance of *all* other host descriptors, even if their owner
        // forgot CLOEXEC. Mark rather than close: Rust's spawn error pipe must
        // remain usable until exec. Fail closed on kernels without close_range.
        if unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for fd in fds {
            if fd < 3 {
                return Err(std::io::Error::from_raw_os_error(libc::EBADF));
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[test]
    fn data_snapshot_starts_at_zero_and_rejects_mutation() {
        let mut file = snapshot(b"approved bytes", 0o500).unwrap();
        assert_eq!(file.stream_position().unwrap(), 0);
        assert!(file.write_all(b"replacement").is_err());
        assert!(file.set_len(0).is_err());
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"approved bytes");
    }

    #[test]
    fn sealed_snapshots_survive_only_explicit_child_exec() {
        let binary = snapshot(b"binary snapshot", 0o500).unwrap();
        let baseline = snapshot(b"baseline snapshot", 0o400).unwrap();
        let fds = [binary.as_raw_fd(), baseline.as_raw_fd()];
        let paths = fds.map(|fd| format!("/proc/self/fd/{fd}"));
        let denied = Command::new("/bin/cat").args(&paths).output().unwrap();
        assert!(
            !denied.status.success(),
            "CLOEXEC must prevent implicit inheritance"
        );
        let mut cmd = Command::new("/bin/cat");
        cmd.args(&paths);
        unsafe {
            cmd.pre_exec(move || inherit_snapshots(fds));
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, b"binary snapshotbaseline snapshot");
        for fd in fds {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            assert_eq!(seals & required, required);
        }
    }

    #[test]
    fn child_exec_excludes_unrelated_non_cloexec_host_descriptor() {
        let binary = snapshot(b"binary snapshot", 0o500).unwrap();
        let baseline = snapshot(b"baseline snapshot", 0o400).unwrap();
        // Disposable canary only; never open actual host credentials.
        let mut canary = tempfile::tempfile().unwrap();
        canary.write_all(b"disposable host secret").unwrap();
        let raw = unsafe { libc::fcntl(canary.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(raw >= 64);
        let secret = unsafe { File::from_raw_fd(raw) };
        let fds = [binary.as_raw_fd(), baseline.as_raw_fd()];
        let mut cmd = Command::new("/bin/cat");
        for fd in [fds[0], fds[1], secret.as_raw_fd()] {
            cmd.arg(format!("/proc/self/fd/{fd}"));
        }
        unsafe {
            cmd.pre_exec(move || inherit_snapshots(fds));
        }
        let output = cmd.output().unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stdout, b"binary snapshotbaseline snapshot");
        // Child changes must never alter the broker's descriptor flags.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, 0);
        for fd in fds {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }

    pub(super) fn run(approved: &ApprovedVerifier) -> Result<Outcome, OperationalError> {
        if unsafe { libc::geteuid() } == 0 {
            diagnostic("identity", "live execution requires a non-root uid");
            return Err(OperationalError::IsolationUnavailable);
        }
        let binary = snapshot(&approved.binary, 0o500)?;
        let baseline = snapshot(&approved.baseline, 0o400)?;
        let mut cmd = Command::new("/usr/bin/bwrap");
        cmd.env_clear().args([
            // Require every isolation boundary explicitly. --unshare-all uses
            // best-effort cgroup/user flags on some Bubblewrap versions.
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--chdir",
            "/",
        ]);
        // Runtime only: never expose host root, home, /etc, sockets or credentials.
        for path in ["/usr/lib", "/usr/lib64", "/lib", "/lib64"] {
            if Path::new(path).exists() {
                cmd.args(["--ro-bind", path, path]);
            }
        }
        // Copy sealed, approved bytes directly from the inherited descriptors.
        // Unlike --ro-bind-fd, this does not resolve /proc/self/fd after bwrap
        // has rearranged its mount namespace. Explicit modes are needed because
        // data mounts do not inherit the source memfd permissions.
        cmd.args([
            "--perms",
            "0500",
            "--ro-bind-data",
            &binary.as_raw_fd().to_string(),
            "/verifier",
            "--perms",
            "0400",
            "--ro-bind-data",
            &baseline.as_raw_fd().to_string(),
            "/baseline.json",
            "--remount-ro",
            "/",
            "--",
        ]);
        cmd.args(approved.argv())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let snapshot_fds = [binary.as_raw_fd(), baseline.as_raw_fd()];
        // A separate process group provides an additional cleanup boundary. PID namespace
        // teardown kills descendants even when they create a new session.
        unsafe {
            cmd.pre_exec(move || {
                // Keep snapshots CLOEXEC in the broker so concurrent launches
                // cannot inherit them. Only this fork's copy survives exec of
                // bwrap; bwrap closes setup descriptors before the verifier.
                inherit_snapshots(snapshot_fds)?;
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|error| {
            diagnostic("spawn/pre_exec", &error.to_string());
            OperationalError::IsolationUnavailable
        })?;
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let result = (|| {
            for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
                if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                    return Err(OperationalError::Capture);
                }
            }
            let started = Instant::now();
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut eof = [false; 2];
            loop {
                if started.elapsed() >= Duration::from_secs(2) {
                    return Err(OperationalError::Deadline);
                }
                for (index, reader, buf) in [
                    (0, &mut stdout as &mut dyn Read, &mut out),
                    (1, &mut stderr as &mut dyn Read, &mut err),
                ] {
                    let mut chunk = [0; 4096];
                    match reader.read(&mut chunk) {
                        Ok(0) => eof[index] = true,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.len() > CAPTURE_LIMIT {
                                return Err(OperationalError::Capture);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                        Err(_) => return Err(OperationalError::Capture),
                    }
                }
                if let Some(status) = child.try_wait().map_err(|_| OperationalError::Capture)? {
                    if eof.iter().all(|v| *v) {
                        let exit = status.code().unwrap_or(-1);
                        // Bubblewrap setup failures and verifier operational exits both deny.
                        if out.is_empty() && exit == 1 && err.starts_with(b"bwrap:") {
                            diagnostic(
                                "bwrap setup (required user,ipc,pid,net,uts,cgroup namespaces)",
                                &String::from_utf8_lossy(&err),
                            );
                            return Err(OperationalError::IsolationUnavailable);
                        }
                        let stdout =
                            String::from_utf8(out).map_err(|_| OperationalError::Report)?;
                        return report(exit, &stdout, "bubblewrap-live/v1");
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })();
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let until = Instant::now() + Duration::from_secs(1);
        while child.try_wait().ok().flatten().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        if child.try_wait().ok().flatten().is_none() {
            return Err(OperationalError::Capture);
        }
        result
    }
}
#[cfg(not(target_os = "linux"))]
mod live {
    use super::*;
    pub(super) fn run(_: &ApprovedVerifier) -> Result<Outcome, OperationalError> {
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
        let result = report(self.capture.exit, &self.capture.stdout, "offline-replay/v1");
        if started.elapsed() >= self.deadline {
            return Err(OperationalError::Deadline);
        }
        result
    }
}
fn report(exit: i32, stdout: &str, provenance: &'static str) -> Result<Outcome, OperationalError> {
    if !(0..=2).contains(&exit) {
        return Err(OperationalError::Exit(exit));
    }
    let r: Report = serde_json::from_str(stdout).map_err(|_| OperationalError::Report)?;
    let changes = r.changes.as_deref().unwrap_or_default();
    let risk = match r.score {
        0 => "NONE",
        1..=14 => "LOW",
        15..=34 => "MEDIUM",
        35..=69 => "HIGH",
        _ => "CRITICAL",
    };
    if r.score > 100
        || r.r#match != (exit == 0)
        || (r.r#match && (r.score != 0 || !changes.is_empty()))
        || (!r.r#match && (changes.is_empty() || (r.score >= 35) != (exit == 2)))
        || r.risk != risk
    {
        return Err(OperationalError::Report);
    }
    Ok(Outcome {
        verdict: if r.r#match {
            Verdict::Match
        } else {
            Verdict::Drift { score: r.score }
        },
        provenance,
    })
}
