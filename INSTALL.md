# Installation and verification

**Release state:** pre-release source checkout. Cross-compiled platform binaries have been built in an internal temporary test environment, but are **not published as signed downloadable releases**. Do not download binaries from unverified mirrors.

## Requirements

- Git and Go **1.23 or newer** for building from source
- Network access to explicitly authorized MCP endpoints
- On Unix-like systems: an ordinary terminal and a secure location for reference baselines
- For agent-skill integration: an agent supporting portable Agent Skills and its documented skill discovery mechanism

## Build the CLI from source

```sh
git clone https://github.com/altrudev/MCP-DriftGuard.git
cd MCP-DriftGuard
go test ./...
go vet ./...
go build -o mcpdrift ./cmd/mcpdrift
./mcpdrift version
```

On Windows, use `go build -o mcpdrift.exe ./cmd/mcpdrift` and `.\\mcpdrift.exe version` in PowerShell.

**Important:** Until version stamping is added to the release workflow, `version` may report `dev`; record the checked-out Git commit for exact provenance.

## Safe isolated smoke test (no service subscription)

From the repository root:

```sh
python3 skills/mcp-driftguard/test_agent_skill.py
```

Requires Python 3.10+. The script builds temporary binaries, starts a disposable loopback MCP server, runs PASS, intentional FAIL and error-path checks, and returns `deterministic_pass: true` when its acceptance conditions hold. The script is **not a certification** or substitute for testing real external implementations.

## Verify an authorized endpoint

```sh
./mcpdrift inspect --format json https://example.org/mcp
./mcpdrift baseline --output candidate.baseline.json https://example.org/mcp
```

The candidate must be independently reviewed and approved before being used as the trust reference. Do **not** treat generation as approval.

```sh
./mcpdrift verify --baseline approved.baseline.json --format json https://example.org/mcp
```

For signed baselines, supply `--verify-key /trusted/key.pub.pem`, with the public key sourced through an independently trusted channel. Keep all private signing keys and authorization tokens outside the repository. If the endpoint requires a bearer token, supply it via `MCPDRIFT_BEARER_TOKEN` in a protected environment.

Exit codes: 0 PASS; 1 REVIEW; 2 FAIL; 3 incomplete/error; 4 baseline/key artifact error; 5 hash/signature verification failure. **Codes 3–5 are never PASS.**

## Install the portable agent skill

The CLI and the skill are separate components. Installing `SKILL.md` does not install or run the Go verifier.

Copy the `skills/mcp-driftguard` folder into the project or user skill directory supported by your *specific agent*, following that agent's current official documentation. Make the built `mcpdrift` binary available on `PATH`, or invoke it using an absolute trusted path. Confirm `mcpdrift version` works in the agent execution environment.

Do not claim Claude, Cursor or Codex acceptance until an authenticated, real-agent discovery and execution test is recorded. See [external testing guide](skills/mcp-driftguard/EXTERNAL-TESTER.md).

## Docker and GitHub Action

The repository includes a Dockerfile and `action.yml`. Both are source integrations requiring separate container/action acceptance before production use. They are not evidence of a published container image or official GitHub Marketplace listing.

## Licensing

The CLI, source and skill in this repository are Apache-2.0 licensed, subject to the repository [LICENSE](LICENSE) and [NOTICE](NOTICE). Do not bundle credentials or private keys. Optional future commercial services must state their **own** terms and must not retroactively revoke rights granted to published Apache-2.0 code.

See the [canonical glossary](GLOSSARY.md), [threat model](THREAT_MODEL.md) and [security policy](SECURITY.md).

## Experimental local MCP stdio transport

DriftGuard can inspect a local MCP server over stdin/stdout with the same snapshot and baseline verifier as HTTP. This transport is **pre-release**. It does not execute discovered MCP tools, but starting a local executable itself is a privileged action.

**Only launch an executable you have inspected and approved.** The verifier requires an exact, absolute executable allowlist via `MCPDRIFT_STDIO_ALLOWED_EXEC`, plus an independently authorized argument vector via `MCPDRIFT_STDIO_ALLOWED_ARGS_JSON` if nonempty; it never passes commands to a shell. Process arguments must come from a trusted operator, never from an LLM or MCP server metadata. The subprocess receives a minimal environment (no inherited bearer token), and its discovery session has a deadline.

For the disposable Python fixture (Linux/macOS example):

```sh
chmod u+x examples/stdio-fixture/server.py
FIXTURE="$(pwd)/examples/stdio-fixture/server.py"
export MCPDRIFT_STDIO_ALLOWED_EXEC="$FIXTURE"

./mcpdrift inspect --stdio-exec "$FIXTURE" --format json stdio
./mcpdrift baseline --stdio-exec "$FIXTURE" --output stdio.candidate.json stdio
./mcpdrift verify --stdio-exec "$FIXTURE" --baseline stdio.candidate.json stdio
```

For trusted executable arguments, independently approve the exact ordered arguments before invoking the CLI:

```sh
export MCPDRIFT_STDIO_ALLOWED_ARGS_JSON='["--safe-option"]'
./mcpdrift inspect --stdio-exec "$FIXTURE" --stdio-args-json '["--safe-option"]' stdio
```

**Both the executable path and every argument must match the trusted allowlist.** If no argument authorization is configured, only the empty argument vector is accepted. Never approve a generic interpreter with attacker-controlled script paths or flags. The endpoint argument must be exactly `stdio`; the full executable path and argument vector are committed into the snapshot's endpoint identity. This does not authenticate executable contents; pin a binary digest and review changes in the operator's deployment process.

Reproducible local test, without external services:

```sh
python3 skills/mcp-driftguard/test_stdio_transport.py
```

**Remaining limitations:** no production-grade OS sandbox or child-process-tree isolation, resource controls are incomplete, Windows stdio execution has not been independently exercised, and the model cannot grant executable permissions. Do not use stdio mode on untrusted executables.

## Cross-origin OAuth issuer metadata

MCP DriftGuard fetches protected-resource metadata from the MCP endpoint origin. **Discovered authorization-server issuer metadata hosted on a different origin is not fetched unless the operator explicitly approves its origin.** This avoids silently contacting arbitrary third-party URLs supplied by an MCP endpoint.

For example, when you have separately verified and approved an OAuth provider:

```sh
export MCPDRIFT_ALLOWED_AUTH_ISSUERS="https://auth.example.com"
./mcpdrift inspect https://mcp.example.com/mcp
```

The variable accepts comma-separated exact URL origins with no path, credentials, query, or fragment. It does not delegate trust to an arbitrary URL path and does not perform OAuth login or token refresh. Same-origin issuer metadata and explicitly approved origins retain normal TLS verification. An unapproved cross-origin issuer causes a failed probe rather than silent acceptance.


## DriftGuard as an MCP stdio server

Build the Go binary from this checkout (Go 1.23+):

```sh
mkdir -p "$HOME/.local/bin"
go build -trimpath -o "$HOME/.local/bin/mcpdrift" ./cmd/mcpdrift
```

Use an absolute binary path
in your MCP host configuration. The host launches one process per stdio session:

```json
{
  "mcpServers": {
    "driftguard": {
      "command": "/absolute/path/to/mcpdrift",
      "args": ["serve", "--endpoint", "https://approved.example/mcp", "--baseline", "/trusted/approved.json", "--verify-key", "/trusted/approved.pub.pem"]
    }
  }
}
```

Replace the example paths and endpoint with operator-authorized values. This is a
generic MCP host configuration example. Isolated Codex CLI registration has been
verified; actual Codex model tool invocation remains unproven (see the acceptance report).
The server validates and pins the baseline and verification key at startup. Restart
the session to adopt a separately approved replacement baseline. `serve` requires an
explicit trusted `--verify-key` and a signed baseline that verifies against it.
Unsigned baselines and missing keys fail closed before reading stdin or probing.
Obtain the trusted public key through an independent operator-controlled channel;
a key delivered alongside an untrusted baseline does not establish approval.
Startup exits 3 for configuration errors, 4 for artifact errors, 5 for integrity
errors. Stdout carries only newline-delimited JSON-RPC; diagnostics use stderr.

The server provides `driftguard_inspect` and `driftguard_verify` with empty argument
objects, `driftguard://policy`, and the `review_drift` prompt. It never accepts a
client-selected endpoint, executable, baseline path, or key. Verification returns
`match`, `score`, `risk`, and `changes`; a mismatch is a successful tool execution
whose data reports drift. A probe failure returns `isError: true` with no raw backend
error or token. Tool errors are inconclusive. The server cannot create or approve
baselines. Descriptions returned by inspected endpoints remain untrusted data.

For an approved local stdio target use `--endpoint stdio --stdio-exec /approved/server`
and the exact executable/argument environment allowlists documented above. HTTP
credentials, if required, come only from the protected process environment. Server
tools perform outbound read-only discovery, so client-side cancellation cannot undo
a request already sent. Requests are processed sequentially and discovery uses the
30-second discovery context (plus up to 10 seconds for TLS identity capture). Input frames are limited to 1 MiB; oversized frames
terminate the session. Batch JSON-RPC and remote HTTP serving are not implemented.
No listener, telemetry, cloud registration, Android app, or new VPS is required.

Reproduce official SDK interoperability with Go 1.26+ (test client only):

```sh
mkdir -p /dev/shm/driftguard-test
TMPDIR=/dev/shm/driftguard-test python3 scripts/test_mcp_server.py
```

The SDK client is a separate Go module with pinned dependencies; it is not a core
runtime dependency. Dependency acquisition may require network on a clean machine.
The test uses a synthetic local fixture; it does not prove remote client, production
enrollment, third-party integration or native macOS/Windows acceptance.


## Local operational acceptance without baseline approval

To compare the installed inspector with an independent JSON HTTP discovery client
against an already authorized local service:

```sh
python3 scripts/probe_local_mcp.py \
  --endpoint http://127.0.0.1:8765/mcp \
  --binary "$HOME/.local/bin/mcpdrift" --output local-discovery.json
```

Use an existing operator-selected endpoint. This probe accepts only explicit
loopback HTTP IP addresses, disables proxies and redirects, does not use credentials,
and sends only initialization and inventory requests. It saves counts and hashes,
not proprietary tool descriptions. An inaccessible service exits nonzero and is
inconclusive. Inventory agreement is not drift verification or baseline approval.

To exercise the installed binary against disposable synthetic fixtures with the
independent official Go SDK client:

```sh
MCPDRIFT_TEST_BINARY="$HOME/.local/bin/mcpdrift" python3 scripts/test_mcp_server.py
```

The synthetic baseline created by this test is not a production approval.
For a Codex configuration-only check, set `MCPDRIFT_CODEX_BIN` to the installed
Codex CLI and optionally `MCPDRIFT_CODEX_COMMAND_JSON` to an exact JSON array of
the absolute server executable and its startup arguments, then run
`python3 scripts/test_codex_clean_config.py`. It uses a temporary `CODEX_HOME`,
checks the command and arguments, and removes the registration. It does not invoke
a model or modify the normal Codex configuration. See the
[official Codex MCP configuration instructions](https://developers.openai.com/learn/docs-mcp).

For MCP-only audit suites, excluding the optional Android Guardian/Rust checks:

```sh
python3 scripts/audit_mcp_driftguard.py --scope mcp --output /tmp/driftguard-audit
```

No persistent monitor should be enabled until the operator supplies a separately
approved baseline and a verification key obtained through an independent trusted
channel. Do not generate a key or approve today's observed surface to clear this
gate. A persistent deployment also needs protected artifact storage, an explicit
service account/environment, restart/boot scheduling, bounded evidence retention,
and an alert route for drift and inconclusive probes. No such deployment is implied
by successful CLI registration or a one-shot test. Network-denied sandbox results
do not establish restrictions on the underlying VPS.
