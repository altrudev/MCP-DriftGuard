# Experimental Rust offline broker slice

This is an original Rust implementation of offline authorization checks, local one-time consumption and independent signed evidence verification. It does not execute the Go verifier, change identity, create keys, sign evidence, or provide an OS sandbox. It is not production ready. The Go verifier and Python experiment are unchanged.

Build and test using cached crates:

```
cargo test --offline --manifest-path broker/Cargo.toml
cargo build --offline --manifest-path broker/Cargo.toml
```

The executable accepts positional arguments:

```
broker/target/debug/driftguard-broker check POLICY SIGNATURE BINARY BASELINE ENDPOINT
broker/target/debug/driftguard-broker consume POLICY SIGNATURE BINARY BASELINE ENDPOINT LEDGER
broker/target/debug/driftguard-broker verify-evidence EVIDENCE SIGNATURE POLICY POLICY_SIGNATURE
```

`check` emits an unsigned `mcpdrift-offline-check/v1` receipt on stdout without consuming authorization. `consume` performs the same checks and permanently burns the ID before emitting a receipt with `consumed:true`. A receipt is not a verifier verdict or proof of execution. All errors exit 1 and emit no success JSON. No network access occurs. CLI time comes from the system clock; it cannot be overridden by an argument or environment variable.

Administrators must externally provision the approval verification public key at `/etc/mcpdrift/trust/operator-approval-ed25519.pub.hex` and, for evidence verification, the separate evidence verification public key at `/etc/mcpdrift/trust/operator-evidence-ed25519.pub.hex`. Each is exactly 64 lowercase hex digits encoding raw Ed25519 public bytes, optionally followed by one newline. These fixed paths and every ancestor must be root-owned, without group/world write permissions or symlinks. There are no caller-selected CLI keys or production key generation commands. Tests inject disposable public keys through the library and never write these paths. This checkout does not provision or modify system paths.

Signature envelopes contain exactly `algorithm: "Ed25519"` and `signature` (canonical padded base64 of 64 signature bytes). Evidence signing belongs to an external trusted signer; the Rust program has no private key input. `verify-evidence` independently verifies both policy and evidence signatures, schema, historical check time, and all policy bindings. It does not require the approval still to be current when inspecting historical evidence. Consumers must also enforce their own evidence freshness and trusted-signer issuance rules. An unsigned receipt must never be treated as signed evidence.

The ledger must already exist as a directory owned by the current effective user, mode 0700 (or stricter). Its final component cannot be a symlink. It uses an opened directory descriptor, `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, mode 0600 markers, and fsync of file and directory. Existing files and symlinks deny reuse. Errors after exclusive creation burn the ID, including output errors; never remove markers to retry. The local ledger path is caller-selected for this unprivileged offline tool. A future execution service must pin one administrator-controlled ledger; separate directories do not share replay protection.

Callers must protect ledger ancestors from replacement, keep a durable local filesystem, retain markers, and trust the clock. No distributed replay protection, rollback resistance, clock rollback defense, arbitrary filesystem race defense, or full runtime/resource bounds are claimed. Key custody checks do not pin every ancestor against concurrent privileged replacement. Artifact contents are checked as read; no executable is launched, so this does not solve future execution-time artifact replacement. This Unix implementation has no Windows portability guarantee.

See [CONTRACT.md](CONTRACT.md) for migration differences and validation coverage. All dependencies resolved offline; no dependency blocker remains for this slice. Privileged execution, signed verdict production and deployment integration remain deliberately unimplemented.
