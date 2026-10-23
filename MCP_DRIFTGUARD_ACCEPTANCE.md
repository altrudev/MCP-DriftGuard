# MCP DriftGuard operational acceptance — 2026-10-23

**Acceptance is incomplete. No 100% operational or production-ready claim is justified.**
The actual Go MCP stdio server now works with an official SDK client against an
operator-approved synthetic target. Prior direct-VPS HTTP and full-race checks
passed. Real production-target discovery, trusted baseline enrollment, persistent
monitoring, actual agent tool invocation and namespace acceptance remain unestablished.

Evidence: [suite results](evidence/mcp-audit-20261023/results.json),
[SDK transcript result](evidence/mcp-audit-20261023/sdk_e2e.log),
[live process receipt](evidence/mcp-audit-20261023/live-live-status.json),
[live JSON-RPC responses](evidence/mcp-audit-20261023/live-output.jsonl).
All evidence was generated locally; SDK interoperability is independent of the
server implementation, but this is not an independent human or external audit.

## Production continuation from b90dc23 — 2026-10-23

**Production acceptance remains incomplete.** This continuation targets MCP
DriftGuard only. The original matrix below records historical runs; the later
successful direct-VPS HTTP/full-race results supersede its environment-only
blockers for that tested VPS execution, not for this restricted Codex process.

| Gate | Current evidence and result |
| --- | --- |
| User-owned service selection | Reviewed existing user service definitions and Conduit bridge source read-only. Selected `frequency-conduit-mcp.service`, `http://127.0.0.1:8765/mcp`, for initialization/inventory only. Existing service was neither restarted nor duplicated. Current uptime is not established by source inspection. |
| Independent real-target discovery | New stdlib JSON HTTP probe and installed inspector both attempted the selected endpoint. Independent client returned `URLError`, errno 1 (`EPERM`); installed CLI exited 3. **INCONCLUSIVE**, no inventory or drift verdict obtained. [Receipt](evidence/mcp-production-20261023/real-target.json). |
| Authorized VPS terminal path | Remote Desktop Commander `start_process` was attempted; tool rejected it with `MCP tool call requires approval, but approval policy is never`. No command executed through that path. No permission bypass or root escalation attempted. [Service review](evidence/mcp-production-20261023/service-review.json). |
| Prior actual VPS networking | Retained direct-VPS conformance at `8100533a1db17349fbf699a17fda1f905204581c`: seven suites PASS, including HTTP/loopback and full Go race. These are actual earlier VPS results, not a fresh run of this continuation. |
| Installed binary protocol/tool execution | **PASS, synthetic target**: official Go SDK v1.8.0 launched `/home/ubuntu/.local/bin/mcpdrift`; both tools, resource and prompt worked; intentional drift, pinned baseline, forbidden override and unavailable-target handling passed. Binary SHA-256 `3a15556ec78b5d25a280a365f697dc333c5411ea7852f1f7ac67cce112dc0c78`. [SDK result](evidence/mcp-production-20261023/sdk-installed.log). |
| Isolated local Codex configuration | **PASS** with Codex CLI 0.163.0: exact installed executable and `serve` arguments registered, enabled, read back and removed in a temporary `CODEX_HOME`. This is real command registration, not model execution. [Receipt](evidence/mcp-production-20261023/codex-registration.log). |
| Actual Codex agent invocation | Attempted `codex exec --oss --local-provider ollama --model qwen3:1.7b` with isolated configuration, read-only sandbox, analytics disabled, no OTEL exporter, no inherited API credentials, and existing local Ollama endpoint `127.0.0.1:11485`. CLI exited 1 during OSS setup: no reachable Ollama server detected. **NOT PROVEN**; no `tools/call` event observed. This does not establish that the real VPS Ollama service is down. [Command](evidence/mcp-production-20261023/codex-agent.json), [log](evidence/mcp-production-20261023/codex-agent.log). |
| Persistent production monitoring | **GATED, not installed**. No independently approved Conduit baseline and trusted verification-key provenance established. Existing `/dev/shm/driftguard-live/approved.json` is explicitly synthetic and cannot authorize Conduit. No key issuance, baseline self-approval, timer, cron job or persistent service changes. |
| Current tests | New probe safety/protocol tests: 4 PASS. Core Go race suite PASS. Stdio security/transport acceptance PASS. Full race invocation again fails at socket creation in this sandbox; retained as failure, not a VPS limitation. [Core race](evidence/mcp-production-20261023/core-race.log), [full race](evidence/mcp-production-20261023/go-race.log). |

The independent probe covers initialization and paginated JSON HTTP inventories,
with exact response IDs, size/page/deadline bounds, no redirects/proxy/credentials,
and no tool invocation. It records only inventory counts and name hashes when
successful. It does not cover SSE, authentication, stateless discovery, resource
templates, or full MCP conformance. Tests use mocked responses for negative paths;
they do not substitute for a successful real-service connection.

Acceptance improvements include installed-binary SDK selection, visible bounded
build diagnostics, exact Codex command/argument and enabled-state checks, and an
MCP-only audit scope that excludes optional Guardian/Rust suites. README and INSTALL
now describe these operations and the actual registration/agent distinction. The
initial SDK rerun failed because the default Go cache was read-only; its failure
log is retained. Retrying with a writable cache passed; no network/dependency
fetch was required.

No production tool was invoked, no production configuration changed, no hosted
model or telemetry used, and no proprietary implementation was copied into this
repository. The previously untracked continuation bundle and patch are preserved;
[initial hashes](evidence/mcp-production-20261023/initial-hashes.json) bind their
contents. Local model setup could not complete, so no model inference is claimed.

The final MCP-only replay exited **1**, correctly retaining three failed suites
out of 14: conformance (socket restrictions), stdio sandbox security (namespace
restrictions), and historical mutations (6/8 detected; two HTTP cases blocked).
The other 11 suites passed, including all six platform builds and their integrity
verification, 200,000 bounded canonical fuzz executions, and the new probe tests.
[Aggregate results](evidence/mcp-production-20261023/audit/results.json) retain
individual commands, exits and log hashes. Build success does not prove native
execution on macOS/Windows. The working tree was explicitly recorded dirty against
base `b90dc23`; Go production code is unchanged in this continuation.

Git staging in the original worktree failed because its Git metadata is mounted
read-only (`index.lock`: read-only file system). Changes and sanitized evidence
are committed in `/dev/shm/driftguard-production-commit`, based directly on
`b90dc23`. The original branch cannot be advanced from this sandbox. An incremental
bundle and patch are exported beside that clone for import into a writable repo.

Residual production gates: obtain a successful discovery-only connection to the
selected real service through a permitted execution path; independently review
and approve its baseline and trust root; then configure and prove boot-persistent
monitoring with protected artifacts, bounded retained evidence and operator alerts.
Prove an actual Codex agent tool call once its local provider is reachable. Native
non-Linux platform execution and externally controlled release authorization remain
unestablished. Android/device enrollment is outside this MCP production acceptance
scope and is not a prerequisite for a local MCP drift monitor.

## Implemented and verified changes

Previously `mcpdrift` was a Go verifier CLI/MCP client, with no MCP server command.
`serve` now exposes two read-only tools, a policy resource and a review prompt over
newline-delimited stdio JSON-RPC. Endpoint, executable, argv, baseline and public
key are operator startup configuration. Tool arguments cannot override them.
The validated baseline and key are pinned for the session; no baseline approval,
creation, arbitrary tool execution or credential-entry tool exists. Probe failures
return `isError: true`, with raw backend errors withheld. Drift remains explicit
result data (`match`, `score`, `risk`, `changes`), not a successful-verification claim.

Tests first failed because `Serve` did not exist. They now verify initialization,
protocol framing, inventory, invalid envelopes, target override rejection,
resource/prompt handling, secret-error suppression, output errors and oversized
frames. CLI tests reject missing, tampered and signature-downgraded baseline
artifacts before reading stdin. The official Go SDK launches the real binary,
checks all interfaces, detects intentional drift, verifies baseline pinning and
rejects an unavailable target as inconclusive.

Additional concrete fixes:

- Codex smoke script no longer runs host configuration operations or exits during
  Python test discovery; standalone absence still exits 2 and reports BLOCKED.
- Historical mutation evidence rejects infrastructure panics as defect detection.
  Regression tests first failed, then passed. Archived builds disable VCS stamping
  so the stdio process-group mutation is tested rather than failing to build.
- Rust attestation tests moved after production items to pass strict Clippy;
  runtime behavior is unchanged. Clippy failed before this change and passed after.
- Install/skill docs describe server setup and boundaries. Literal escaped-newline
  formatting errors were repaired. README no longer implies a built-in continuous
  monitoring scheduler. The audit runner retains failures and returns nonzero.

## Acceptance matrix

| Area | Status | Evidence and precise scope |
| --- | --- | --- |
| Actual Go server command | PASS, local | `serve`; operator-bound configuration, stdout reserved for JSON-RPC |
| Real MCP client/server | PASS, local | Official Go SDK v1.8.0 `CommandTransport` launches compiled server; `sdk_e2e.log` |
| Initialize, ping, protocol negotiation | PASS, tested scope | Legacy stdio negotiation through 2025-11-25; no claim of full protocol conformance |
| Tools | PASS | Two tools listed and invoked; `{}` arguments only; malicious target override rejected |
| Resources and prompts | PASS | Lists plus `driftguard://policy` read and `review_drift` retrieval |
| Actual running process | PASS at audit time | Session 11958; signed synthetic baseline; FIFO client observed match, drift FAIL, resource, prompt and ping |
| Production service uptime | NOT ESTABLISHED | Session-backed process, not boot-managed or remotely reachable; no uptime guarantee |
| Policy drift | PASS, synthetic | Core baseline/diff/race tests; schema, capability, description, annotation and identity tests; intentional new tool produces FAIL |
| Baseline integrity | PASS, local | Signed baseline startup; tamper and unsigned-with-trusted-key rejection; session pinning |
| Go core race tests | PASS | CLI, baseline, canonical, diff, report, server; `go_core_race.log` |
| Go observation pure/security subset | PASS | Wire schema, URL credentials, issuer approval matching, guarded destinations; `go_observe_pure.log` |
| Entire Go unit/race suite | BLOCKED | `httptest` panics: socket creation denied; `conformance-final.json` preserves nonzero exits |
| Go vet and formatting | PASS | `go_vet.log`; `gofmt -l` empty and `git diff --check` clean |
| Stdio client/skill transport suite | PASS | Correct discovery, matching baseline, drift exit 2, wrong IDs, malformed/missing inventory, cursor loops, exact argv allowlist, credential isolation, descendant cleanup |
| Large/concurrent inventories | PASS | 10/100/1,000/10,000 tools, 100 verifications across 8 workers; `conformance-final.json` extreme suite |
| Official SDK clean dependency isolation | PASS here | Separate test module; pinned cached dependency versions; core has no new dependencies. Test client needs Go 1.26; clean-machine offline install not proven |
| Minimum Go 1.23 execution | NOT TESTED | Only Go 1.26 installed; core go.mod remains 1.23 |
| Portable skill packaging | PASS, structural | SKILL metadata/procedure and docs checks; CLI transport integration passes; actual installed agent execution untested |
| Codex registration / real AI host | BLOCKED | Codex executable unavailable (`codex_host.log`, exit 2); no host registration or agent execution claimed |
| HTTP discovery/client integration | BLOCKED | Even loopback sockets prohibited; `http_acceptance` nonzero; no remote endpoints contacted |
| Bubblewrap sandbox | BLOCKED | Kernel denies namespace creation; isolation tests failed and were not relabeled PASS |
| Historical mutations | PARTIAL | 6/8 detected, including stdio group cleanup; OAuth issuer and bearer HTTP mutations blocked by sockets, now correctly NOT DETECTED |
| Python suite with Rust verifiers | PASS | 43 tests, zero skips, `python-with-rust.log`; synthetic enrollment only |
| Guardian TLS simulation | PASS, simulated | MemoryBIO TLS plus real HTTP handler; no network socket, phone or production attestation claim |
| Rust tests / fmt / strict Clippy | PASS | Unit, integration, binary and doctest targets; logs retained; test success does not prove production kernel privileges |
| Canonical fuzzing | PASS on bounded retry | 200,000 executions; initial 5-second run failed with context deadline exceeded and remains retained |
| Release/artifact mutation tests | PASS | Release evidence gate tests and artifact tampering tests |
| Six platform builds | PASS, compile/integrity | Linux/macOS/Windows amd64/arm64 candidates and checksums; `candidate-manifest.json` |
| Native cross-platform execution | NOT TESTED | Linux amd64 exercised; other OS/architecture binaries were only built |
| Actual release authorization | BLOCKED | `release-gate.log`: aggregate conformance not PASS; hosted CI UNVERIFIED; `release_authorized: false` |
| Live remote MCP client | NOT TESTED | No remote endpoint/client provisioned or contacted; socket creation unavailable |
| Production enrollment / external integrations | NOT TESTED | No production trust roots, real device enrollment or third-party accounts used |
| Android companion | NOT REQUIRED | No APK changes; core MCP server and verifier do not depend on Android |

## Security, privacy and configuration limits

No telemetry, model service, paid service, new VPS, external endpoint or production
credential was used. All temporary builds, fixtures, keys and test output used
`/dev/shm`; durable sanitized logs are in this repository's evidence directory.
The live synthetic signing private key was deleted after startup. Existing user
files `evidence/continuation-v051/continuation.bundle` and `.patch` were untouched.

Server callers cannot supply probe URLs, paths, commands or arguments. Starting
`serve` does not grant remote callers authority over baseline approval. For stdio
targets, the existing exact executable/argv allowlists and minimal child environment
apply. Allowlisting authorizes executable code, not its trustworthiness; binary
contents are not authenticated by a path hash. Optional bubblewrap with a read-only
host root is not a host-filesystem confidentiality boundary. Only approved trusted
executables should be launched. Sandbox enforcement could not be validated here.

Untrusted endpoint descriptions remain data, not instructions. A matching observable
surface does not prove binary identity, backend integrity or baseline safety.
Requests are sequential; cancellation does not interrupt the current callback.
Discovery has a 30-second context, with the existing TLS identity capture having
its own up-to-10-second dial timeout. Stdio discovery also has its own 20-second
limit. Frames above 1 MiB terminate the session. No batch JSON-RPC, remote HTTP MCP
serving, continuous scheduler, RBAC, hosted monitoring or device enrollment is
implemented by this server. Operator credentials remain environment-only; tool
errors suppress raw probe diagnostics. No complete security certification or
current dependency vulnerability database scan was performed.


## Additional verification on the authorized VPS host

The Codex sandbox's denied socket operations **were not VPS restrictions**. In a separate authorized terminal on the same VPS, an independent conformance execution on the exact isolated Codex implementation commit completed with exit 0. All seven suites passed: Go unit, Go race, Go vet, documentation, real HTTP client/loopback socket acceptance, stdio acceptance and extreme limits. The full Go race suite also independently passed outside the sandbox. Evidence is retained under `evidence/mcp-audit-20261023/direct-vps/`. This overrides the environment-only HTTP and full-Go-suite blockers *for the tested VPS process*. It does not establish an external remote MCP client, a production approved target/baseline, installed third-party skill operation, hosted release signing or long-lived production uptime. The original sandbox failures are retained without rewriting history.

The rebuilt `mcpdrift` executable was installed at `/home/ubuntu/.local/bin/mcpdrift` on the VPS. A separate Codex CLI, configured under a disposable isolated `CODEX_HOME`, successfully registered this binary with the signed synthetic baseline and reported its MCP configuration enabled. This confirms configuration compatibility, **not** an AI model running the tools or a production operator target. Registration evidence is under `evidence/mcp-audit-20261023/direct-vps/`.

## Reproduction and usable process

Operator installation and host configuration are in [INSTALL.md](INSTALL.md).
The optional skill procedure is [SKILL.md](skills/mcp-driftguard/SKILL.md).

```sh
mkdir -p /dev/shm/driftguard-rerun
python3 scripts/audit_mcp_driftguard.py --output /dev/shm/driftguard-rerun
```

The runner records every suite exit and log hash. A restricted host should produce
a nonzero aggregate; do not bypass the restrictions or convert those gates to PASS.
Offline runs need the pinned dependencies already cached. On this host Go 1.26,
Rust/Cargo, Python with cryptography, OpenSSL, and a C compiler were available.
The configured Python supplement used `FG_RUST_BINARIES` pointing at the built
Rust binaries. Full tests require a host that permits loopback and namespaces.

At audit time the actual process used `/dev/shm/driftguard-live/mcpdrift serve
--endpoint stdio --stdio-exec /dev/shm/driftguard-live/fixture.py --baseline
/dev/shm/driftguard-live/approved.json --verify-key
/dev/shm/driftguard-live/test.public.pem`, with
`MCPDRIFT_STDIO_ALLOWED_EXEC=/dev/shm/driftguard-live/fixture.py`.
Its input FIFO is mode 0600 at `/dev/shm/driftguard-live/input`, output is
`/dev/shm/driftguard-live/output.jsonl`; use one local client at a time. Initialization
already occurred for this session. For example, send a fresh ping ID:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":100,"method":"ping"}' > /dev/shm/driftguard-live/input
tail -n 1 /dev/shm/driftguard-live/output.jsonl
```

The process is usable for this synthetic target only. Launch a fresh normal stdio
session from a real MCP host for a separately approved production target; this
report does not imply that step has happened. `/dev/shm` artifacts are ephemeral.

## Revision and commit boundary

The clean isolated code commit tested was
`6452314d26e25452e475c78bf401e15922ec7ac3`, based on
`fbd6bc3d7e524d9732903a04468b493b77acb2c3`. Final documentation and audit-runner
reporting refinements are recorded separately with this acceptance evidence.
Candidate checksums bind the tested code commit, not a published release.

The original worktree's Git metadata is read-only. `git add` failed with:
`Unable to create .../.git/worktrees/guardian-v030-repair/index.lock: Read-only file system`.
No attempt was made to bypass that protection. Verified changes were committed in
an isolated `/dev/shm` clone. An incremental Git bundle (requiring the base commit), patch and receipt accompany
this report under `evidence/mcp-audit-20261023/`; they can be imported into a writable
repository. The original worktree branch/HEAD could not be advanced in this execution.

Remaining acceptance work is concrete: run the blocked HTTP and namespace suites
on a permitted host; exercise actual agent installation and a live remote MCP
client; validate a real operator-approved production baseline/credential path;
perform production device enrollment and any selected third-party integrations;
run native platform jobs and obtain hosted release evidence. No 100% claim should
be made before those applicable gates are satisfied.

## Final replay

The final audit runner was replayed on clean commit
`8100533a1db17349fbf699a17fda1f905204581c` (same server implementation, final docs
and runner refinements). [Final results](evidence/mcp-audit-20261023/final-replay/results.json)
record the same infrastructure blocks and successful SDK, core race, configured
43-test Python, Rust/Clippy/fmt, cross-build and integrity suites. The bounded fuzz
run passed again (200,000 requested executions). The runner exited **1**, correctly
reflecting incomplete acceptance. Earlier failures remain preserved. Final replay
candidate hashes are in the adjacent candidate manifest; no release was authorized.

## Authorized VPS real-target verification (subsequent independent run)

Outside Codex's sandbox, direct authorized VPS execution successfully inspected the existing Frequency Conduit `http://127.0.0.1:8765/mcp` endpoint. The independent HTTP discovery and the installed DriftGuard inspector agreed on **six tool names, zero resources and zero prompts**. Both returned success, and the byte-bound result is retained in `evidence/mcp-production-20261023/direct-vps-real-target.json`. This is a real local HTTP connection, not mock testing. It **does not** establish baseline approval, any tool's behavior, trusted provenance, persistent monitoring, or remotely delivered service; approval and monitoring remain disabled.
