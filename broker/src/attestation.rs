//! Offline diagnostic evidence inspection. A root pin is an operator input, never learned
//! from the export. This module never enrolls a key or authorizes an operation.
use crate::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::{Command, Stdio},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    schema: String,
    purpose: String,
    production_eligible: bool,
    attestation_verified: bool,
    certificates_der_b64: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct DiagnosticReport {
    pub chain_signatures_verified_against_supplied_pin: bool,
    pub challenge_matches: bool,
    pub p256: bool,
    pub attestation_security_level: u8,
    pub key_security_level: u8,
    pub production_eligible: bool,
    pub enrollment_enabled: bool,
}
#[derive(Clone, Copy)]
struct Tlv<'a> {
    class: u8,
    tag: u32,
    constructed: bool,
    value: &'a [u8],
}
fn take<'a>(input: &mut &'a [u8]) -> Result<Tlv<'a>> {
    let mut i = 0;
    let first = *input.get(i).ok_or("truncated DER tag")?;
    i += 1;
    let mut tag = u32::from(first & 31);
    if tag == 31 {
        tag = 0;
        for n in 0..5 {
            let b = *input.get(i).ok_or("truncated high tag")?;
            i += 1;
            if n == 0 && b & 127 == 0 {
                return Err("nonminimal tag".into());
            }
            tag = tag
                .checked_mul(128)
                .and_then(|x| x.checked_add(u32::from(b & 127)))
                .ok_or("tag overflow")?;
            if b & 128 == 0 {
                break;
            }
            if n == 4 {
                return Err("tag too long".into());
            }
        }
        if tag < 31 {
            return Err("nonminimal high tag".into());
        }
    }
    let b = *input.get(i).ok_or("truncated length")?;
    i += 1;
    let mut len = usize::from(b);
    if b & 128 != 0 {
        let count = usize::from(b & 127);
        if count == 0 || count > 3 {
            return Err("invalid DER length".into());
        }
        len = 0;
        for n in 0..count {
            let v = *input.get(i).ok_or("truncated length")?;
            i += 1;
            if n == 0 && v == 0 {
                return Err("nonminimal length".into());
            }
            len = (len << 8) | usize::from(v);
        }
        if len < 128 {
            return Err("nonminimal length".into());
        }
    }
    let value = input
        .get(i..i.checked_add(len).ok_or("length overflow")?)
        .ok_or("truncated value")?;
    *input = &input[i + len..];
    Ok(Tlv {
        class: first >> 6,
        tag,
        constructed: first & 32 != 0,
        value,
    })
}
fn children(t: Tlv<'_>) -> Result<Vec<Tlv<'_>>> {
    if !t.constructed {
        return Err("expected constructed DER".into());
    }
    let mut bytes = t.value;
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if out.len() >= 128 {
            return Err("too many DER fields".into());
        }
        out.push(take(&mut bytes)?);
    }
    Ok(out)
}
fn exact(bytes: &[u8], tag: u32) -> Result<Tlv<'_>> {
    let mut rest = bytes;
    let t = take(&mut rest)?;
    if !rest.is_empty() || t.class != 0 || t.tag != tag {
        return Err("unexpected DER object".into());
    }
    Ok(t)
}
fn number(t: Tlv<'_>, tag: u32) -> Result<u8> {
    if t.class != 0 || t.tag != tag || t.value.len() != 1 || t.value[0] > 127 {
        return Err("unexpected attestation integer".into());
    }
    Ok(t.value[0])
}
fn inspect_leaf(der: &[u8], challenge: &[u8]) -> Result<(u8, u8)> {
    let cert = children(exact(der, 16)?)?;
    if cert.len() != 3 {
        return Err("invalid certificate".into());
    }
    let tbs = children(cert[0])?;
    if tbs.first().map(|x| (x.class, x.tag)) != Some((2, 0)) {
        return Err("requires v3 certificate".into());
    }
    let spki = children(*tbs.get(6).ok_or("missing SPKI")?)?;
    if spki.len() != 2 {
        return Err("invalid SPKI".into());
    }
    let alg = children(spki[0])?;
    if alg.len() != 2
        || alg[0].tag != 6
        || alg[0].value != [42, 134, 72, 206, 61, 2, 1]
        || alg[1].tag != 6
        || alg[1].value != [42, 134, 72, 206, 61, 3, 1, 7]
        || spki[1].tag != 3
        || spki[1].value.len() != 66
        || spki[1].value[..2] != [0, 4]
    {
        return Err("requires uncompressed P-256 EC public key".into());
    }
    let exts: Vec<_> = tbs.iter().filter(|t| t.class == 2 && t.tag == 3).collect();
    if exts.len() != 1 {
        return Err("missing/duplicate extension container".into());
    }
    let wrapper = children(*exts[0])?;
    if wrapper.len() != 1 {
        return Err("invalid extensions".into());
    }
    let mut found = None;
    for ext in children(wrapper[0])? {
        let fields = children(ext)?;
        if fields.len() < 2 || fields.len() > 3 {
            return Err("invalid extension".into());
        }
        if fields[0].tag == 6 && fields[0].value == [43, 6, 1, 4, 1, 214, 121, 2, 1, 17] {
            if found.is_some() {
                return Err("duplicate attestation".into());
            }
            let value = fields.last().ok_or("missing extension value")?;
            if value.tag != 4 || value.class != 0 {
                return Err("invalid extension value".into());
            }
            found = Some(value.value);
        }
    }
    let kd = children(exact(
        found.ok_or("missing Android attestation extension")?,
        16,
    )?)?;
    if kd.len() != 8 || kd[4].class != 0 || kd[4].tag != 4 || kd[4].value != challenge {
        return Err("attestation challenge mismatch or invalid description".into());
    }
    let a = number(kd[1], 10)?;
    let k = number(kd[3], 10)?;
    if !(1..=2).contains(&a) || !(1..=2).contains(&k) {
        return Err("software/unknown security level refused".into());
    }
    // Require hardware-enforced EC, 256-bit size, P-256 curve and generated origin.
    let hardware = children(kd[7])?;
    for (tag, expected) in [(2, vec![2]), (3, vec![1, 0]), (10, vec![1]), (702, vec![0])] {
        let fields: Vec<_> = hardware
            .iter()
            .filter(|t| t.class == 2 && t.tag == tag)
            .collect();
        if fields.len() != 1 {
            return Err("missing/duplicate hardware key property".into());
        }
        let integer = exact(fields[0].value, 2)?;
        if integer.value != expected {
            return Err("unexpected hardware key property".into());
        }
    }
    // Validate both authorization lists structurally, without treating other claims as policy.
    children(kd[6])?;
    Ok((a, k))
}

pub fn verify_export(
    json: &[u8],
    challenge: &[u8],
    root_sha256: &[u8],
) -> Result<DiagnosticReport> {
    if json.len() > 70000 || challenge.len() != 32 || root_sha256.len() != 32 {
        return Err("invalid input bounds".into());
    }
    let export: Export = serde_json::from_slice(json)?;
    if export.schema != "frequency-guardian-attestation/v2"
        || export.purpose != "diagnostic-only"
        || export.production_eligible
        || export.attestation_verified
        || !(2..=8).contains(&export.certificates_der_b64.len())
    {
        return Err("unsupported diagnostic export".into());
    }
    let mut chain = Vec::new();
    let mut total = 0;
    for encoded in export.certificates_der_b64 {
        let der = STANDARD.decode(encoded)?;
        total += der.len();
        if der.is_empty() || der.len() > 16384 || total > 49152 {
            return Err("chain exceeds bounds".into());
        }
        children(exact(&der, 16)?)?;
        chain.push(der);
    }
    let root = chain.last().ok_or("empty chain")?;
    if Sha256::digest(root).as_slice() != root_sha256 {
        return Err("root does not match independently supplied pin".into());
    }
    let (a, k) = inspect_leaf(&chain[0], challenge)?;
    let dir = tempfile::tempdir()?;
    let pem = |der: &[u8]| {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        )
    };
    fs::write(dir.path().join("root.pem"), pem(root))?;
    fs::write(dir.path().join("leaf.pem"), pem(&chain[0]))?;
    let intermediates: String = chain[1..chain.len() - 1].iter().map(|x| pem(x)).collect();
    // Always include the root in the untrusted bundle so the file is nonempty.
    fs::write(
        dir.path().join("intermediates.pem"),
        intermediates + &pem(root),
    )?;
    // Fixed executable/options/relative filenames; no shell, URI, supplied option,
    // network retrieval, environment configuration or operating-system roots.
    let status = Command::new("/usr/bin/openssl")
        .env_clear()
        .env("OPENSSL_CONF", "/dev/null")
        .current_dir(dir.path())
        .args([
            "verify",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-x509_strict",
            "-check_ss_sig",
            "-purpose",
            "any",
            "-trusted",
            "root.pem",
            "-untrusted",
            "intermediates.pem",
            "leaf.pem",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(
            "pinned certificate chain cryptographic verification failed (or OpenSSL unsupported)"
                .into(),
        );
    }
    // Require every exported link, in the exported order, to verify against its
    // immediate issuer. OpenSSL path building alone may ignore surplus certificates.
    for pair in chain.windows(2) {
        fs::write(dir.path().join("child.pem"), pem(&pair[0]))?;
        fs::write(dir.path().join("issuer.pem"), pem(&pair[1]))?;
        let link = Command::new("/usr/bin/openssl")
            .env_clear()
            .env("OPENSSL_CONF", "/dev/null")
            .current_dir(dir.path())
            .args([
                "verify",
                "-no-CAfile",
                "-no-CApath",
                "-no-CAstore",
                "-x509_strict",
                "-partial_chain",
                "-purpose",
                "any",
                "-trusted",
                "issuer.pem",
                "child.pem",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !link.success() {
            return Err("exported chain link signature/order verification failed".into());
        }
    }
    Ok(DiagnosticReport {
        chain_signatures_verified_against_supplied_pin: true,
        challenge_matches: true,
        p256: true,
        attestation_security_level: a,
        key_security_level: k,
        production_eligible: false,
        enrollment_enabled: false,
    })
}

/// Extract canonical P-256 SPKI from a certificate after independent chain verification.
pub fn candidate_spki(export_json: &[u8]) -> Result<Vec<u8>> {
    if export_json.len() > 70000 {
        return Err("oversized attestation export".into());
    }
    let export: Export = serde_json::from_slice(export_json)?;
    if export.schema != "frequency-guardian-attestation/v2"
        || export.purpose != "diagnostic-only"
        || export.production_eligible
        || export.attestation_verified
    {
        return Err("unsupported export".into());
    }
    let leaf = STANDARD.decode(export.certificates_der_b64.first().ok_or("missing leaf")?)?;
    if leaf.is_empty() || leaf.len() > 16384 {
        return Err("invalid leaf size".into());
    }
    let cert = children(exact(&leaf, 16)?)?;
    if cert.len() != 3 {
        return Err("invalid certificate".into());
    }
    let tbs = children(cert[0])?;
    if tbs.first().map(|x| (x.class, x.tag)) != Some((2, 0)) {
        return Err("not v3 certificate".into());
    }
    let spki = children(*tbs.get(6).ok_or("missing public key")?)?;
    if spki.len() != 2 {
        return Err("invalid SPKI".into());
    }
    let alg = children(spki[0])?;
    if alg.len() != 2
        || alg[0].value != [42, 134, 72, 206, 61, 2, 1]
        || alg[1].value != [42, 134, 72, 206, 61, 3, 1, 7]
        || alg[0].tag != 6
        || alg[1].tag != 6
    {
        return Err("not P-256".into());
    }
    let point = spki[1];
    if point.tag != 3 || point.class != 0 || point.value.len() != 66 || point.value[..2] != [0, 4] {
        return Err("unsupported point".into());
    }
    let mut output = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200")?;
    output.extend_from_slice(&point.value[1..]);
    Ok(output)
}

/// Verify Android attestationApplicationId (authorization tag 709) against
/// independently configured package and signing certificate digest.
pub fn verify_application_id(
    export_json: &[u8],
    package: &str,
    signer_sha256: &[u8],
) -> Result<()> {
    if package.is_empty()
        || package.len() > 200
        || !package
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_')
        || signer_sha256.len() != 32
    {
        return Err("invalid independent app policy".into());
    }
    let export: Export = serde_json::from_slice(export_json)?;
    let der = STANDARD.decode(export.certificates_der_b64.first().ok_or("missing leaf")?)?;
    let cert = children(exact(&der, 16)?)?;
    let tbs = children(*cert.first().ok_or("invalid certificate")?)?;
    let exts: Vec<_> = tbs.iter().filter(|e| e.class == 2 && e.tag == 3).collect();
    if exts.len() != 1 {
        return Err("invalid certificate extensions".into());
    }
    let wrappers = children(exts[0].to_owned())?;
    if wrappers.len() != 1 {
        return Err("invalid extensions wrapper".into());
    }
    let mut description = None;
    for extension in children(wrappers[0])? {
        let fields = children(extension)?;
        if fields.len() < 2 || fields.len() > 3 {
            return Err("invalid extension fields".into());
        }
        if fields[0].tag == 6 && fields[0].value == [43, 6, 1, 4, 1, 214, 121, 2, 1, 17] {
            if description.is_some() {
                return Err("duplicate key attestation".into());
            }
            description = Some(exact(fields.last().ok_or("missing extension")?.value, 16)?);
        }
    }
    let kd = children(description.ok_or("attestation missing")?)?;
    if kd.len() != 8 {
        return Err("invalid key description".into());
    }
    let software = children(kd[6])?;
    let app_ids: Vec<_> = software
        .iter()
        .filter(|t| t.class == 2 && t.tag == 709)
        .collect();
    if app_ids.len() != 1 {
        return Err("missing or duplicate attestation application id".into());
    }
    let inner = exact(app_ids[0].value, 4)?;
    let app_fields = children(exact(inner.value, 16)?)?;
    if app_fields.len() != 2 {
        return Err("invalid application identity".into());
    }
    let packages = children(app_fields[0])?;
    if packages.len() != 1 {
        return Err("unexpected shared UID packages".into());
    }
    let package_fields = children(packages[0])?;
    if package_fields.len() != 2
        || package_fields[0].tag != 4
        || package_fields[0].value != package.as_bytes()
        || package_fields[1].tag != 2
    {
        return Err("package identity mismatch".into());
    }
    let digests = children(app_fields[1])?;
    if digests.len() != 1 || digests[0].tag != 4 || digests[0].value != signer_sha256 {
        return Err("signing certificate digest mismatch".into());
    }
    Ok(())
}

/// Additional operational policy. Diagnostic chain verification alone is insufficient.
/// Requires a hardware-enforced no-auth signing key, locked verified boot and a patch floor.
pub fn verify_enrollment_policy(export_json: &[u8], minimum_patch: u32) -> Result<()> {
    let export: Export = serde_json::from_slice(export_json)?;
    let der = STANDARD.decode(export.certificates_der_b64.first().ok_or("missing leaf")?)?;
    let cert = children(exact(&der, 16)?)?;
    let tbs = children(*cert.first().ok_or("missing certificate")?)?;
    let container: Vec<_> = tbs.iter().filter(|e| e.class == 2 && e.tag == 3).collect();
    if container.len() != 1 {
        return Err("invalid extension container".into());
    }
    let wrapper = children(*container[0])?;
    if wrapper.len() != 1 {
        return Err("invalid extension wrapper".into());
    }
    let mut descriptions = Vec::new();
    for extension in children(wrapper[0])? {
        let fields = children(extension)?;
        if fields
            .first()
            .map(|f| f.tag == 6 && f.value == [43, 6, 1, 4, 1, 214, 121, 2, 1, 17])
            .unwrap_or(false)
        {
            descriptions.push(children(exact(
                fields.last().ok_or("missing description")?.value,
                16,
            )?)?);
        }
    }
    if descriptions.len() != 1 || descriptions[0].len() != 8 {
        return Err("invalid attestation description".into());
    }
    let hardware = children(descriptions[0][7])?;
    let field = |tag| -> Result<Tlv<'_>> {
        let values: Vec<_> = hardware
            .iter()
            .filter(|f| f.class == 2 && f.tag == tag)
            .collect();
        if values.len() != 1 {
            return Err("missing or duplicated operational key property".into());
        }
        Ok(*values[0])
    };
    if !exact(field(503)?.value, 5)?.value.is_empty() {
        return Err("noAuthRequired missing".into());
    }
    if hardware
        .iter()
        .any(|f| f.class == 2 && (f.tag == 504 || f.tag == 505))
    {
        return Err("authenticated key refused for tap workflow".into());
    }
    for (tag, value) in [(1, 2), (5, 4)] {
        let values = children(exact(field(tag)?.value, 17)?)?;
        if !values.iter().any(|f| number(*f, 2).ok() == Some(value)) {
            return Err("signing purpose or SHA-256 missing".into());
        }
    }
    let boot = children(exact(field(704)?.value, 16)?)?;
    if boot.len() != 4
        || boot[0].tag != 4
        || boot[0].value.is_empty()
        || boot[1].tag != 1
        || boot[1].value != [255]
        || number(boot[2], 10)? != 0
        || boot[3].tag != 4
        || boot[3].value.is_empty()
    {
        return Err("locked verified boot required".into());
    }
    let patch = exact(field(706)?.value, 2)?;
    if patch.value.is_empty() || patch.value.len() > 4 || patch.value[0] & 128 != 0 {
        return Err("invalid OS patch level".into());
    }
    let value = patch
        .value
        .iter()
        .fold(0u32, |v, b| (v << 8) | u32::from(*b));
    if minimum_patch < 202001 || value < minimum_patch {
        return Err("OS patch below independent policy".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_der() {
        for data in [
            &[0x30, 0x80][..],
            &[0x30, 0x81, 0],
            &[0x30, 3, 1],
            &[0x30, 0, 0],
            &[0x1f, 0x80, 1, 0],
        ] {
            assert!(exact(data, 16).is_err());
        }
    }
    #[test]
    fn refuses_self_assertions_and_bounds() {
        assert!(verify_export(&vec![0; 70001], &[0; 32], &[0; 32]).is_err());
        assert!(verify_export(br#"{"schema":"frequency-guardian-attestation/v2","purpose":"diagnostic-only","production_eligible":true,"attestation_verified":true,"certificates_der_b64":[]}"#, &[0;32], &[0;32]).is_err());
        assert!(verify_export(b"{}", &[], &[0; 32]).is_err());
    }
}
