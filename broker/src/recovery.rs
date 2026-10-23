//! Offline recovery authorization validation. Verification is NOT key replacement.
//! Independently provision authority keys through a separate trusted channel.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    pub schema: String,
    pub threshold: usize,
    pub authority_public_keys_hex: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub schema: String,
    pub existing_identity_sha256: String,
    pub replacement_identity_sha256: String,
    pub nonce_hex: String,
    pub expires_unix: u64,
    pub signatures: Vec<RecoverySignature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySignature {
    pub authority_public_key_hex: String,
    pub signature_hex: String,
}
#[derive(Debug, Serialize)]
pub struct RecoveryVerdict {
    pub authorization_verified: bool,
    pub distinct_authorities: usize,
    pub device_key_replaced: bool,
    pub production_eligible: bool,
}

pub fn signed_payload(request: &RecoveryRequest) -> Result<Vec<u8>, String> {
    if request.schema != "frequency-guardian-recovery/v1" {
        return Err("wrong recovery request schema".into());
    }
    let old = decode_fixed::<32>(&request.existing_identity_sha256)?;
    let new = decode_fixed::<32>(&request.replacement_identity_sha256)?;
    let nonce = decode_fixed::<32>(&request.nonce_hex)?;
    if old == new {
        return Err("replacement identity must differ".into());
    }
    if nonce == [0; 32] {
        return Err("empty recovery nonce".into());
    }
    let mut data = b"frequency-guardian/recovery/v1\0".to_vec();
    data.extend_from_slice(&old);
    data.extend_from_slice(&new);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&request.expires_unix.to_be_bytes());
    Ok(data)
}
fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != 2 * N || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid fixed-width hex".into());
    }
    let bytes = hex::decode(value).map_err(|_| "invalid hex")?;
    bytes.try_into().map_err(|_| "invalid length".into())
}
pub fn verify(
    policy_json: &[u8],
    request_json: &[u8],
    now: u64,
) -> Result<RecoveryVerdict, String> {
    if policy_json.len() > 8192 || request_json.len() > 16384 {
        return Err("oversized recovery evidence".into());
    }
    let policy: RecoveryPolicy = serde_json::from_slice(policy_json).map_err(|e| e.to_string())?;
    let request: RecoveryRequest =
        serde_json::from_slice(request_json).map_err(|e| e.to_string())?;
    if policy.schema != "frequency-guardian-recovery-policy/v1"
        || policy.authority_public_keys_hex.len() < 2
        || policy.authority_public_keys_hex.len() > 7
        || policy.threshold < 2
        || policy.threshold > policy.authority_public_keys_hex.len()
    {
        return Err("invalid recovery policy".into());
    }
    if request.expires_unix <= now || request.expires_unix - now > 600 {
        return Err("recovery request expired or outside ten minute window".into());
    }
    let mut authorities = HashSet::new();
    for key in &policy.authority_public_keys_hex {
        let encoded = decode_fixed::<32>(key)?;
        VerifyingKey::from_bytes(&encoded).map_err(|_| "invalid authority key")?;
        if !authorities.insert(encoded) {
            return Err("duplicate policy authority".into());
        }
    }
    let payload = signed_payload(&request)?;
    let mut used = HashSet::new();
    for entry in &request.signatures {
        let key_bytes = decode_fixed::<32>(&entry.authority_public_key_hex)?;
        if !authorities.contains(&key_bytes) || !used.insert(key_bytes) {
            return Err("unapproved or duplicate signer".into());
        }
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "bad verifying key")?;
        let sig = Signature::from_bytes(&decode_fixed::<64>(&entry.signature_hex)?);
        key.verify(&payload, &sig)
            .map_err(|_| "invalid recovery signature")?;
    }
    if used.len() < policy.threshold {
        return Err("insufficient independent signatures".into());
    }
    // This is independent authorization evidence only. No recovery key or device identity changes.
    Ok(RecoveryVerdict {
        authorization_verified: true,
        distinct_authorities: used.len(),
        device_key_replaced: false,
        production_eligible: false,
    })
}
pub fn request_fingerprint(request_json: &[u8]) -> String {
    hex::encode(Sha256::digest(request_json))
}
