pub mod attestation;
pub mod guardian_acceptance;
pub mod guardian_binding;
pub mod guardian_challenge;
pub mod recovery;
// Experimental offline authorization and constrained verifier replay. No key generation.
pub mod coordinator;
pub mod runner;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const APPROVAL_KEY: &str = "/etc/mcpdrift/trust/operator-approval-ed25519.pub.hex";
pub const EVIDENCE_KEY: &str = "/etc/mcpdrift/trust/operator-evidence-ed25519.pub.hex";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub endpoint: String,
    pub binary_sha256: String,
    pub baseline_sha256: String,
    pub authorization_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub algorithm: String,
    pub signature: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub policy_sha256: String,
    pub authorization_id: String,
    pub endpoint: String,
    pub binary_sha256: String,
    pub baseline_sha256: String,
    pub checked_at: u64,
    pub authorization_expires_at: u64,
    pub consumed: bool,
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Sorted compact UTF-8 JSON. Schemas contain only strings, booleans and u64s;
/// floats, arbitrary maps and Unicode property names are deliberately absent.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn endpoint_valid(endpoint: &str) -> bool {
    // Preserve the signed spelling; reject parser normalization and ambiguous hosts.
    let Some(rest) = endpoint.strip_prefix("http://127.0.0.1") else {
        return false;
    };
    if endpoint
        .bytes()
        .any(|b| b <= 32 || b >= 127 || b == b'\\' || b == b'#')
    {
        return false;
    }
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') {
        return true;
    }
    let Some(port_tail) = rest.strip_prefix(':') else {
        return false;
    };
    let port = port_tail.split(['/', '?']).next().unwrap_or("");
    !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}
impl Policy {
    pub fn validate(&self, now: u64) -> Result<()> {
        require(
            self.schema == "mcpdrift-operator-policy/v2",
            "policy schema",
        )?;
        require(endpoint_valid(&self.endpoint), "endpoint")?;
        require(
            lower_hex(&self.binary_sha256, 64) && lower_hex(&self.baseline_sha256, 64),
            "digest format",
        )?;
        require(lower_hex(&self.authorization_id, 32), "authorization ID")?;
        require(
            self.issued_at <= now
                && now < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|n| n > 0 && n <= 300),
            "authorization time",
        )
    }
}
pub fn verify_signature<T: Serialize>(
    document: &T,
    envelope: &Envelope,
    key: &[u8; 32],
) -> Result<()> {
    require(envelope.algorithm == "Ed25519", "signature algorithm")?;
    let bytes = STANDARD.decode(&envelope.signature)?;
    require(
        STANDARD.encode(&bytes) == envelope.signature,
        "noncanonical base64",
    )?;
    let signature = Signature::from_slice(&bytes)?;
    VerifyingKey::from_bytes(key)?.verify_strict(&canonical(document)?, &signature)?;
    Ok(())
}
pub fn check(
    policy: &Policy,
    signature: &Envelope,
    key: &[u8; 32],
    binary: &[u8],
    baseline: &[u8],
    now: u64,
) -> Result<Evidence> {
    policy.validate(now)?;
    verify_signature(policy, signature, key)?;
    require(
        digest(binary) == policy.binary_sha256 && digest(baseline) == policy.baseline_sha256,
        "artifact digest mismatch",
    )?;
    Ok(Evidence {
        schema: "mcpdrift-offline-check/v1".into(),
        policy_sha256: digest(&canonical(policy)?),
        authorization_id: policy.authorization_id.clone(),
        endpoint: policy.endpoint.clone(),
        binary_sha256: policy.binary_sha256.clone(),
        baseline_sha256: policy.baseline_sha256.clone(),
        checked_at: now,
        authorization_expires_at: policy.expires_at,
        consumed: false,
    })
}
/// Caller must protect the parent path and retain this ledger permanently.
/// Descriptor-relative exclusive creation prevents marker symlink following/races.
pub fn consume(
    directory: &Path,
    policy: &Policy,
    signature: &Envelope,
    key: &[u8; 32],
    binary: &[u8],
    baseline: &[u8],
    now: u64,
) -> Result<()> {
    check(policy, signature, key, binary, baseline, now)?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)?;
    let meta = dir.metadata()?;
    require(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "ledger must be owned by current user and private",
    )?;
    let name = std::ffi::CString::new(policy.authorization_id.as_str())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut marker = unsafe { File::from_raw_fd(fd) };
    writeln!(marker, "{}", digest(&canonical(policy)?))?;
    marker.sync_all()?;
    dir.sync_all()?;
    Ok(())
}
pub fn verify_evidence(
    e: &Evidence,
    sig: &Envelope,
    key: &[u8; 32],
    policy: &Policy,
) -> Result<()> {
    verify_signature(e, sig, key)?;
    policy.validate(e.checked_at)?;
    require(
        e.schema == "mcpdrift-offline-check/v1"
            && e.policy_sha256 == digest(&canonical(policy)?)
            && e.authorization_id == policy.authorization_id
            && e.endpoint == policy.endpoint
            && e.binary_sha256 == policy.binary_sha256
            && e.baseline_sha256 == policy.baseline_sha256
            && e.authorization_expires_at == policy.expires_at,
        "evidence binding",
    )
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    require(bytes.len() <= 65536, "JSON too large")?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn fixed_key(path: &str) -> Result<[u8; 32]> {
    // This executable trusts only administrator-provisioned fixed key paths.
    let path = Path::new(path);
    require(path.is_absolute(), "key path must be absolute")?;
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        require(
            m.uid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink(),
            "unsafe key custody",
        )?;
        require(
            if ancestor == path {
                m.is_file()
            } else {
                m.is_dir()
            },
            "key path type",
        )?;
    }
    let data = fs::read_to_string(path)?;
    let s = data.strip_suffix('\n').unwrap_or(&data);
    require(lower_hex(s, 64), "public key must be lowercase raw hex")?;
    Ok(hex::decode(s)?
        .try_into()
        .map_err(|_| "public key length")?)
}
