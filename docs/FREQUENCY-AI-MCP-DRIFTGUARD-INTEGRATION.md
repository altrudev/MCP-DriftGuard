# Frequency AI MCP DriftGuard integration

## Delivered scope

The experimental Rust broker now exposes `runner::ApprovedVerifier` and a separate
`ExecutionRunner` interface. `OfflineReplay` exercises the existing Go verify JSON
contract without executing any program or contacting any server. `BubblewrapRunner`
always returns `IsolationUnavailable`. There is no live execution CLI or direct
execution fallback. Existing offline authorization commands remain available.
The Go core is unchanged. This is an adapter experiment, not a production deployment.

A live Bubblewrap probe in this workspace, running as UID 1000, failed with
“No permissions to create a new namespace”. Merely finding `/usr/bin/bwrap` is
insufficient. No verifier was launched. No private keys were read or generated.

## Adapter contract

A Frequency AI adapter should translate a configured MCP server identity into one
administrator-approved literal loopback endpoint and select the approved verifier
and baseline digests. It must not translate model text into commands, executable
paths, stdio arguments, environment variables, or URLs. Endpoint spelling is compared
exactly against the signed policy; other transports are rejected in this slice.

Load the two artifacts with `ApprovedVerifier::load`, then call an execution runner
with the policy, detached approval signature, public key and trusted current time.
The library reads bounded regular files with final-component symlink rejection and
retains artifact bytes. `authorize` verifies the signature, expiry, endpoint and both
SHA-256 digests. The planned namespace invocation is exactly:

```
/verifier verify --baseline /baseline.json --format json APPROVED_ENDPOINT
```

There are no caller-selected flags, shell, keygen, signing, or stdio server execution.
The offline capture is a disposable local JSON file with exactly `exit` (integer),
`stdout` and `stderr` (strings), and `delay_ms` (unsigned integer). For example:

```json
{"exit":0,"stdout":"{\"match\":true,\"risk\":\"NONE\",\"score\":0,\"changes\":null}","stderr":"","delay_ms":0}
```

Replay limits each decoded stream to 64 KiB and serialized input to 1 MiB. Artifact
inputs are limited to 64 MiB each. Deadlines must be positive and at most 30 seconds;
the replay waits at most the remaining deadline, including for a malicious delay.
Replay loading is synchronous bounded regular-file I/O; this is not a hard real-time
filesystem I/O guarantee. No subprocess pipes or child cleanup are claimed here.

Go exit 0 is a match; 1 is drift below score 35; 2 is drift at or above 35.
The adapter checks report consistency, score range, risk and change presence.
Other exits, malformed JSON, inconsistent results, authorization failure, capture
limits and timeout are operational errors, never drift or a successful match.
The replay's `offline-replay/v1` provenance is mandatory: it is untrusted diagnostic
input, not fresh observation, signed evidence, or proof the Go verifier ran.
Never feed replay results to a production authorization gate as live verification.

## Security boundary and operator acceptance

Live execution remains unavailable even on another host until an implementation is
reviewed and accepted. Operators must establish and test all of the following before
replacing the fail-closed runner:

- A dedicated non-root identity, with real/effective/saved IDs and supplementary
  groups checked, no capabilities, no privilege escalation, and no inherited secrets.
  Never launch a verifier as root, even briefly before dropping privileges.
- Working unprivileged Bubblewrap user, PID, mount, IPC and network namespaces;
  isolated process lifetime, complete process-tree termination and reaping on timeout,
  resource limits, and bounded concurrent stdout/stderr draining without deadlock.
- An allowlisted minimal filesystem containing only immutable, digest-checked
  executable and baseline snapshots and required runtime files. No host root, home,
  private keys, credentials, sockets or writable executable mounts. Preserve exact
  verified bytes across launch; this offline loader is not a secure executable launcher.
- Explicit narrowly scoped connectivity to the approved endpoint. An isolated network
  namespace cannot reach the host loopback server automatically. Sharing host networking
  defeats that boundary; design and accept a restricted relay instead. Account for Go
  discovery requests and redirects so an approved URL cannot escape egress restrictions.
- Fixed protected trust roots, a trusted clock, an administrator-pinned durable replay
  ledger, consume-before-launch semantics, and freshness/binding for independently
  signed execution evidence. The replay runner neither consumes an ID nor signs receipts.
- Tests under the actual service identity proving filesystem denial, egress denial,
  child cleanup, tamper resistance, overflow handling and timeout behavior. A successful
  `bwrap true` alone is not acceptance. Missing prerequisites must remain operational denial.

Signed Go baselines currently need the Go public verification key option. This slice
supplies no verification-key mount/flag; such baselines must fail operationally until
a fixed public-key configuration and custody check are designed. Digest authorization
is not a substitute for required baseline signature verification.

## When to check and how to compose

For a future accepted live adapter, check during MCP onboarding, before enabling a
new tool/catalog revision, following server upgrades or credential/scope changes,
and periodically according to risk and acceptable evidence age. Recheck after
reconnect or suspected compromise. Bind cached verdicts to endpoint, baseline digest,
verifier digest and observation time; invalidate them on configuration changes.
A failed probe means unknown state and should block sensitive work or require explicit
operator handling. Do not silently refresh a baseline to resolve drift.

Frequency Authority Envelope/Guardian remain responsible for request authority,
identity, consent, scope, runtime enforcement and any existing signing/audit lifecycle.
DriftGuard supplies catalog/metadata drift information to that boundary; it does not
issue authority envelopes, authorize tool calls, duplicate Guardian policy evaluation,
or prove server behavior is benign. These are intended integration responsibilities,
not a claim that a Frequency API was discovered or changed in this repository.
Use one adapter and one existing enforcement decision point, with a reference to fresh
DriftGuard evidence when available, instead of building a second authority system.

## Validation

Run `cargo test --offline --manifest-path broker/Cargo.toml` and
`cargo clippy --offline --manifest-path broker/Cargo.toml --all-targets -- -D warnings`.
Disposable fixtures cover match/drift/operational exits, report corruption, artifact
substitution, endpoint mismatch, expiry, capture overflow, timeout and symlink denial.
These tests execute no verifier, use no network, and grant no production authority.
