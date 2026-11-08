//! One-use verifier-issued challenge store. Do not accept device-selected challenges.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema: String,
    pub challenge_hex: String,
    pub issued_unix: u64,
    pub expires_unix: u64,
}
fn verify_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let m = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !m.file_type().is_dir() || m.permissions().mode() & 0o077 != 0 {
        return Err("private non-symlink directory with mode 0700 required".into());
    }
    Ok(())
}
fn name(hex: &str) -> String {
    format!("{}.json", hex::encode(Sha256::digest(hex.as_bytes())))
}
#[cfg(unix)]
pub fn issue(dir: &Path, now: u64) -> Result<Challenge, String> {
    use std::os::unix::fs::OpenOptionsExt;
    verify_dir(dir)?;
    let mut random = [0u8; 32];
    FileRandom::fill(&mut random)?;
    let c = Challenge {
        schema: "frequency-guardian-verifier-challenge/v1".into(),
        challenge_hex: hex::encode(random),
        issued_unix: now,
        expires_unix: now.checked_add(300).ok_or("time overflow")?,
    };
    let path = dir.join(name(&c.challenge_hex));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(&serde_json::to_vec(&c).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::File::open(dir)
        .and_then(|x| x.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(c)
}
struct FileRandom;
impl FileRandom {
    fn fill(buf: &mut [u8]) -> Result<(), String> {
        fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .map_err(|e| e.to_string())
    }
}
#[cfg(unix)]
pub fn consume(dir: &Path, challenge_hex: &str, now: u64) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    verify_dir(dir)?;
    if challenge_hex.len() != 64 || !challenge_hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid challenge".into());
    }
    let normalized = challenge_hex.to_ascii_lowercase();
    let path = dir.join(name(&normalized));
    let m = fs::symlink_metadata(&path).map_err(|_| "unissued challenge")?;
    if !m.file_type().is_file() || m.len() > 512 {
        return Err("invalid challenge record".into());
    }
    let record: Challenge = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if record.schema != "frequency-guardian-verifier-challenge/v1"
        || record.challenge_hex != normalized
        || now < record.issued_unix
        || now >= record.expires_unix
        || record.expires_unix - record.issued_unix != 300
    {
        return Err("expired or inconsistent challenge".into());
    }
    let used = dir.join(format!("{}.used", name(&normalized)));
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(used)
        .map_err(|_| "challenge already consumed")?;
    marker.write_all(b"consumed\n").map_err(|e| e.to_string())?;
    marker.sync_all().map_err(|e| e.to_string())?;
    fs::File::open(dir)
        .and_then(|x| x.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}
