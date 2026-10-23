use std::{fs::File, io::Read};
fn bounded(p: &str, max: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut v = Vec::new();
    File::open(p)?.take(max + 1).read_to_end(&mut v)?;
    if v.len() as u64 > max {
        return Err("oversize JSON".into());
    }
    Ok(v)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 9 {
        return Err("usage: guardian-acceptance DIAGNOSTICS.json ATTESTATION.json CHALLENGE_HEX INDEPENDENT_ROOT_PIN_SHA256_HEX PRIVATE_CHALLENGE_DIRECTORY BINDING.json PACKAGE_NAME APK_SIGNING_CERT_SHA256_HEX".into());
    }
    let report = driftguard_broker::guardian_acceptance::verify(
        &bounded(&a[1], 70000)?,
        &bounded(&a[2], 70000)?,
        &hex::decode(&a[3])?,
        &hex::decode(&a[4])?,
        &bounded(&a[6], 4096)?,
        &a[7],
        &hex::decode(&a[8])?,
    )?;
    driftguard_broker::guardian_challenge::consume(
        std::path::Path::new(&a[5]),
        &a[3],
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("independent acceptance refused: {e}");
        std::process::exit(1)
    }
}
