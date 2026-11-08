//! Cryptographic proof that the previously installed signing key authorized association
//! with an independently attested candidate. This is NOT hardware attestation of the old key.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Stdio},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: String,
    old_public_key_spki_b64: String,
    candidate_public_key_spki_b64: String,
    challenge_hex: String,
    signature_der_b64: String,
    production_eligible: bool,
}
pub fn signed_bytes(
    challenge: &[u8],
    old_spki: &[u8],
    candidate_spki: &[u8],
) -> Result<Vec<u8>, String> {
    if challenge.len() != 32
        || old_spki.len() > 512
        || candidate_spki.len() > 512
        || old_spki.len() < 64
        || candidate_spki.len() < 64
    {
        return Err("binding bounds".into());
    }
    let mut out = b"frequency-guardian/attested-candidate-binding/v1\0".to_vec();
    out.extend_from_slice(challenge);
    out.extend_from_slice(&Sha256::digest(old_spki));
    out.extend_from_slice(&Sha256::digest(candidate_spki));
    Ok(out)
}
pub fn verify_binding(
    json: &[u8],
    challenge: &[u8],
    attested_leaf_spki: &[u8],
) -> Result<String, String> {
    if json.len() > 4096 {
        return Err("oversized binding".into());
    }
    let b: Binding = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    if b.schema != "frequency-guardian-candidate-binding/v1"
        || b.production_eligible
        || hex::decode(&b.challenge_hex).map_err(|e| e.to_string())? != challenge
    {
        return Err("binding contract or challenge mismatch".into());
    }
    let old = STANDARD
        .decode(&b.old_public_key_spki_b64)
        .map_err(|e| e.to_string())?;
    let candidate = STANDARD
        .decode(&b.candidate_public_key_spki_b64)
        .map_err(|e| e.to_string())?;
    if candidate != attested_leaf_spki || old == candidate {
        return Err("candidate not independently attested or equals prior key".into());
    }
    let sig = STANDARD
        .decode(&b.signature_der_b64)
        .map_err(|e| e.to_string())?;
    if sig.len() > 128 || sig.len() < 64 {
        return Err("invalid signature size".into());
    }
    let msg = signed_bytes(challenge, &old, &candidate)?;
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    fs::write(tmp.path().join("old.der"), &old).map_err(|e| e.to_string())?;
    fs::write(tmp.path().join("data"), msg).map_err(|e| e.to_string())?;
    fs::write(tmp.path().join("sig"), sig).map_err(|e| e.to_string())?;
    let ok = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("OPENSSL_CONF", "/dev/null")
        .current_dir(tmp.path())
        .args([
            "pkeyutl", "-verify", "-pubin", "-inkey", "old.der", "-keyform", "DER", "-sigfile",
            "sig", "-in", "data", "-rawin", "-digest", "sha256",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !ok.success() {
        return Err("old device signature invalid".into());
    }
    Ok(hex::encode(Sha256::digest(&old)))
}
