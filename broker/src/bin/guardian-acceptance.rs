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
    if a.len() != 5 {
        return Err("usage: guardian-acceptance DIAGNOSTICS.json ATTESTATION.json CHALLENGE_HEX INDEPENDENT_ROOT_PIN_SHA256_HEX".into());
    }
    let report = driftguard_broker::guardian_acceptance::verify(
        &bounded(&a[1], 70000)?,
        &bounded(&a[2], 70000)?,
        &hex::decode(&a[3])?,
        &hex::decode(&a[4])?,
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
