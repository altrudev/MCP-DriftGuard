fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err(
            "usage: guardian-challenge EXISTING_PRIVATE_CHALLENGE_DIRECTORY (mode 0700)".into(),
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let issue = driftguard_broker::guardian_challenge::issue(std::path::Path::new(&args[1]), now)?;
    println!("{}", serde_json::to_string_pretty(&issue)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("challenge issuance refused: {e}");
        std::process::exit(1)
    }
}
