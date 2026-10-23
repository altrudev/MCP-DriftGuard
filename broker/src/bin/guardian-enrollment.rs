//! Independent chain/application/key checks and durable challenge consumption.
//! The authority service must also check live certificate revocation before issuing a grant.
use std::{fs::File, io::Read};
fn run() -> driftguard_broker::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 8 {
        return Err("usage: guardian-enrollment ATTESTATION.json CHALLENGE_HEX ROOT_PIN_HEX PACKAGE APK_SIGNER_SHA256 MINIMUM_OS_PATCH_YYYYMM PRIVATE_CHALLENGE_DIRECTORY".into());
    }
    let mut bytes = Vec::new();
    File::open(&args[1])?.take(70001).read_to_end(&mut bytes)?;
    let report = driftguard_broker::attestation::verify_export(
        &bytes,
        &hex::decode(&args[2])?,
        &hex::decode(&args[3])?,
    )?;
    driftguard_broker::attestation::verify_application_id(
        &bytes,
        &args[4],
        &hex::decode(&args[5])?,
    )?;
    driftguard_broker::attestation::verify_enrollment_policy(&bytes, args[6].parse()?)?;
    driftguard_broker::guardian_challenge::consume(
        std::path::Path::new(&args[7]),
        &args[2],
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "chain_verified": report.chain_signatures_verified_against_supplied_pin,
            "application_verified": true,
            "operational_key_policy_verified": true,
            "candidate_spki_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, driftguard_broker::attestation::candidate_spki(&bytes)?),
            "revocation_checked": false, "challenge_consumed": true
        }))?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("enrollment checks refused: {e}");
        std::process::exit(1);
    }
}
