# Guardian v0.3 recovery authorization evidence

Historical diagnostic/proposed contract. The current native tap approval workflow,
independent enrollment, revocation and safe replacement are specified in
[GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Its tap policy supersedes earlier
per-operation biometric/password requirements. Existing diagnostic bridges and
quorum evidence validators retain their diagnostic-only verdicts.

A standalone, offline independent verifier is implemented in `broker/src/recovery.rs`, with CLI `guardian-recovery POLICY.json REQUEST.json PRIVATE_NONCE_LEDGER_DIRECTORY`. This is an authorization-evidence component, **not a completed recovery ceremony**. It never replaces device keys, changes enrollment, or admits production operations.

A separately trusted recovery policy binds 2–7 Ed25519 authority public keys and a threshold of at least two. The request binds old/new device SPKI SHA-256 digests, a 32-byte nonce and an expiration within ten minutes. Each distinct policy authority must sign the exact domain-separated binary payload. An altered payload, duplicate authority, insufficient signatures, expired/overlong request, unapproved signer or invalid policy fails closed.

The independent policy must be provisioned out-of-band and integrity protected. The current CLI **does not persist nonce consumption or revocation**, cannot establish authority independence and does not implement recovery enrollment or Android identity replacement. Therefore it must not authorize actual recovery until durable one-use nonce consumption, key revocation, independent approval custody and audited on-device recovery are integrated and tested. Production eligibility stays false.

Testing: `cargo test --offline --manifest-path broker/Cargo.toml --test recovery`. Positive and negative fixture keys are generated deterministically for tests only, never used for real authority provisioning.

The verifier now persists nonce consumption in an existing operator-controlled private 0700 directory, using exclusive 0600 marker creation and synchronization. Reusing a nonce fails closed. Policy revocation and real device identity transition remain separate required controls.
