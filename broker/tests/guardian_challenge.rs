#[cfg(unix)]
#[test]
fn issued_challenge_is_random_bounded_and_one_use() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let a = driftguard_broker::guardian_challenge::issue(d.path(), 1000).unwrap();
    let b = driftguard_broker::guardian_challenge::issue(d.path(), 1000).unwrap();
    assert_ne!(a.challenge_hex, b.challenge_hex);
    assert!(
        driftguard_broker::guardian_challenge::consume(d.path(), &a.challenge_hex, 1001).is_ok()
    );
    assert!(
        driftguard_broker::guardian_challenge::consume(d.path(), &a.challenge_hex, 1001).is_err()
    );
    assert!(
        driftguard_broker::guardian_challenge::consume(d.path(), &b.challenge_hex, 1300).is_err()
    );
    assert!(
        driftguard_broker::guardian_challenge::consume(d.path(), &"1".repeat(64), 1001).is_err()
    );
}
