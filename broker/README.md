# Experimental Rust offline broker slice

This is an original Rust implementation of offline authorization checks, local one-time consumption and independent signed evidence verification. Its CLI remains offline; the separate experimental library runner can launch an authorized verifier inside Bubblewrap. It does not create keys or sign evidence. It is not production ready. The Go verifier and Python experiment are unchanged.

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

The ledger must already exist as a directory owned by the current effective user, mode 0700 (or stricter). Its final component cannot be a symlink. It uses an opened directory descriptor, `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, mode 0600 markers, and fsync of file and directory. Existing files and symlinks deny reuse. Errors after exclusive creation burn the ID, including output errors; never remove markers to retry. The local ledger path is caller-selected for this unprivileged offline tool. An embedding execution service must pin one administrator-controlled ledger when constructing its coordinator; separate directories do not share replay protection.

Callers must protect ledger ancestors from replacement, keep a durable local filesystem, retain markers, and trust the clock. No distributed replay protection, rollback resistance, clock rollback defense, arbitrary filesystem race defense, or full runtime/resource bounds are claimed. Key custody checks do not pin every ancestor against concurrent privileged replacement. Artifact contents are checked as read; the live library runner separately seals artifact snapshots before launch. This Unix implementation has no Windows portability guarantee.

See [CONTRACT.md](CONTRACT.md) for migration differences and validation coverage. All dependencies resolved offline; no dependency blocker remains for this slice. Privileged execution, signed verdict production and deployment integration remain deliberately unimplemented.

The separate library [runner module](src/runner.rs) now supports constrained offline replay of the Go verify JSON contract. Live Bubblewrap execution requires working unprivileged namespaces and fails closed when unavailable. It has no host network access or endpoint relay. See [Frequency AI integration](../docs/FREQUENCY-AI-MCP-DRIFTGUARD-INTEGRATION.md) for bounds, provenance, and operator acceptance requirements. Existing CLI behavior is unchanged.

Live launch also requires Linux `close_range(CLOSE_RANGE_CLOEXEC)` support. Before exec, the child marks every descriptor above stderr close-on-exec, then clears that flag only for the two sealed artifact snapshots. The broker retains CLOEXEC on its snapshots, and unrelated host descriptors cannot survive exec. Unsupported descriptor isolation fails closed. Run the mandatory live gate with `DRIFTGUARD_REQUIRE_LIVE=1 cargo test --offline --manifest-path broker/Cargo.toml`; unavailable namespaces are a failure in this mode.

Artifact delivery requires Bubblewrap `--ro-bind-data` and `--perms`: sealed memfds are rewound and copied into read-only mounts with modes 0500 (verifier) and 0400 (baseline). Unsupported options fail closed; no path-based fallback is used.


The library [coordinator](src/coordinator.rs) connects one-time authorization to live execution:

```rust,ignore
let authorization = ValidatedAuthorization::validate(&approved, &policy, &signature)?;
let coordinator = Coordinator::new(admin_selected_ledger);
let record = coordinator.execute(authorization)?;
```

Import these types from `driftguard_broker::coordinator`. Validation uses the fixed
approval public key path and system clock. The opaque handle retains an immutable
policy/signature and borrows the approved artifact snapshots. Execution rechecks
signature, artifacts and expiry, then exclusively creates and fsyncs the ledger marker
before invoking the existing `BubblewrapRunner`. Missing, unsafe or symlinked ledgers,
replay and validation failures return errors without invoking the runner. Errors after
marker creation leave the ID burned. Runner failure also permanently burns the ID;
there is no retry or rollback. The coordinator accepts no key, command, custom runner,
clock override or environment configuration. The lower-level experimental runners
remain available but do not themselves consume authorization; use the coordinator
for one-time execution.

After a runner attempt, `mcpdrift-unsigned-execution/v1` records bind the SHA-256 of
canonical policy bytes, authorization ID and consumption time. A validated report
supplies the observed verdict and its `bubblewrap-live/v1` provenance; an operational
failure supplies a typed `failure_class`, null verdict and `bubblewrap-attempt/v1`
provenance. That failure provenance records an attempt, not a successful sandbox launch
or observation. Records contain no signatures and are **unsigned execution records**.
External trusted signing, custody, freshness checks and persistence remain separate;
the existing offline `verify-evidence` schema does not verify these execution records.
A crash after consumption may produce no record. The trusted clock and protected,
permanent ledger ancestors remain deployment requirements.

Coordinator tests cover signature tampering, expiry including expiry after validation,
missing/unsafe/symlinked ledgers, exact policy binding, consume-before-run ordering,
failed execution burning the ID, replay denial, observed verdict/provenance, and live
static fixture success/failure. On 2026-10-22, offline tests pass with unavailable-live
skips. Required live tests fail on this host because Bubblewrap reports no permission
to create a namespace. This is an acceptance blocker, not a live execution pass.

## Guardian attestation diagnostic

The separate `guardian-attestation` binary and `attestation` module inspect v0.2
Android exports offline with an independent challenge and root pin. See
[protocol and limitations](../docs/FREQUENCY-GUARDIAN-V02.md). No enrollment or
broker acceptance is enabled. OpenSSL verification failure always denies.
