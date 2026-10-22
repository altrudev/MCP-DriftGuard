use driftguard_broker::*;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 7 && (a[1] == "check" || a[1] == "consume") || a.len() == 8 && a[1] == "consume" {
        if a[1] == "consume" && a.len() != 8 {
            return Err("consume requires ledger directory".into());
        }
        let policy: Policy = read_json(Path::new(&a[2]))?;
        let sig: Envelope = read_json(Path::new(&a[3]))?;
        let key = fixed_key(APPROVAL_KEY)?;
        require_endpoint(&policy, &a[6])?;
        let binary = std::fs::read(&a[4])?;
        let baseline = std::fs::read(&a[5])?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut evidence = check(&policy, &sig, &key, &binary, &baseline, now)?;
        if a[1] == "consume" {
            consume(
                Path::new(&a[7]),
                &policy,
                &sig,
                &key,
                &binary,
                &baseline,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
            evidence.consumed = true;
        }
        println!("{}", String::from_utf8(canonical(&evidence)?)?);
        return Ok(());
    }
    if a.len() == 6 && a[1] == "verify-evidence" {
        let policy: Policy = read_json(Path::new(&a[4]))?;
        let approval: Envelope = read_json(Path::new(&a[5]))?;
        verify_signature(&policy, &approval, &fixed_key(APPROVAL_KEY)?)?;
        verify_evidence(
            &read_json(Path::new(&a[2]))?,
            &read_json(Path::new(&a[3]))?,
            &fixed_key(EVIDENCE_KEY)?,
            &policy,
        )?;
        println!("verified");
        return Ok(());
    }
    Err("usage: driftguard-broker check POLICY SIGNATURE BINARY BASELINE ENDPOINT | consume POLICY SIGNATURE BINARY BASELINE ENDPOINT LEDGER | verify-evidence EVIDENCE SIGNATURE POLICY POLICY_SIGNATURE".into())
}
fn require_endpoint(p: &Policy, endpoint: &str) -> Result<()> {
    if p.endpoint == endpoint {
        Ok(())
    } else {
        Err("endpoint mismatch".into())
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("denied: {e}");
        std::process::exit(1);
    }
}
