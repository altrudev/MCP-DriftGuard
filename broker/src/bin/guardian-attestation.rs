use std::{fs::File, io::Read};
fn run() -> driftguard_broker::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: guardian-attestation EXPORT.json EXPECTED_CHALLENGE_HEX PINNED_ROOT_DER_SHA256_HEX; diagnostic only, no enrollment".into());
    }
    let challenge = hex::decode(&args[2])?;
    let pin = hex::decode(&args[3])?;
    let mut bytes = Vec::new();
    File::open(&args[1])?.take(70001).read_to_end(&mut bytes)?;
    let report = driftguard_broker::attestation::verify_export(&bytes, &challenge, &pin)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("diagnostic verification refused: {e}");
        std::process::exit(1);
    }
}
