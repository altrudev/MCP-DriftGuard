use std::{fs::File, io::Read};
fn bounded(path: &str, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err("recovery evidence exceeds size limit".into());
    }
    Ok(buf)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: guardian-recovery POLICY.json REQUEST.json PRIVATE_NONCE_LEDGER_DIRECTORY (offline verification only; no device recovery)".into());
    }
    let policy = bounded(&args[1], 8192)?;
    let request = bounded(&args[2], 16384)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let verdict = driftguard_broker::recovery::verify(&policy, &request, now)?;
    #[cfg(unix)]
    driftguard_broker::recovery::consume_nonce(std::path::Path::new(&args[3]), &request)?;
    #[cfg(not(unix))]
    return Err("durable nonce ledger is currently supported on Unix only".into());
    println!("{}", serde_json::to_string_pretty(&verdict)?);
    Ok(())
}
fn main() {
    if let Err(err) = run() {
        eprintln!("recovery authorization refused: {err}");
        std::process::exit(1)
    }
}
