# MCP DriftGuard

**Continuous integrity verification for Model Context Protocol (MCP) servers.**

MCP DriftGuard answers a narrow security question:

> Does the security-relevant MCP surface running now still match the surface that was approved?

An MCP server can change after review: tools can appear, schemas can widen, descriptions can acquire new authority language, server identity can change, and authorization metadata can move. DriftGuard records a deterministic baseline and compares the live server against it later.

It is intentionally standalone: **no LLM, no DDC dependency, no hosted account, and no telemetry are required.**

## Status

v0.1 release candidate. DriftGuard speaks the current MCP 2026-07-28 stateless protocol and falls back to legacy initialize/session-based servers through 2025-11-25. Treat the project as pre-release until interoperability testing across multiple independent production MCP implementations is complete.

## What it detects

- Added or removed tools
- Tool input-schema changes
- Tool annotation changes
- Security-sensitive description changes
- Added or removed resources and prompts
- MCP protocol-version and advertised-version changes\n- TLS certificate and public-key identity changes
- Authentication challenge changes
- Protected-resource / authorization metadata changes when captured
- Endpoint and TLS identity changes
- Baseline tampering through SHA-256 integrity checks
- Optional baseline authenticity through Ed25519 signatures

## Core model

```text
MCP endpoint
    |
    v
discovery
    |
    v
canonical snapshot
    |
    +--> SHA-256 fingerprint
    |
    +--> optional Ed25519 signature
    |
    v
approved baseline
    |
    | time passes
    v
live discovery
    |
    v
structural + authority diff
    |
    v
PASS / REVIEW / FAIL
```

## Install from source

Requires Go 1.23+.

```bash
git clone https://github.com/altrudev/MCP-DriftGuard.git
cd MCP-DriftGuard
go build -o mcpdrift ./cmd/mcpdrift
```

## Quick start

```bash
./mcpdrift inspect https://server.example/mcp

./mcpdrift baseline https://server.example/mcp \
  --output production.baseline.json

./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json
```

JSON or SARIF output:

```bash
./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json \
  --format json

./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json \
  --format sarif > mcpdrift.sarif
```

For an authenticated MCP endpoint, provide a bearer token only through the process environment:

```bash
MCPDRIFT_BEARER_TOKEN="$TOKEN" \
  ./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json
```

The bearer token is used for HTTP requests and is not written into snapshots or baseline artifacts.

## 90-second PASS → FAIL demo

Start the included current-protocol MCP fixture:

```bash
go run ./examples/demo-server
```

In another terminal:

```bash
go build -o mcpdrift ./cmd/mcpdrift

./mcpdrift baseline http://127.0.0.1:8787/mcp \
  --output demo.baseline.json

./mcpdrift verify http://127.0.0.1:8787/mcp \
  --baseline demo.baseline.json
```

The result is `PASS`.

Restart the fixture with drift enabled:

```bash
MCPDRIFT_DEMO_DRIFT=1 go run ./examples/demo-server
```

Run the same verification again. The server now exposes `export_customer_database`, so DriftGuard produces a HIGH-risk capability change and a `FAIL` exit.

## Signed baselines

```bash
./mcpdrift keygen \
  --private mcpdrift.ed25519.pem \
  --public mcpdrift.ed25519.pub.pem

./mcpdrift baseline https://server.example/mcp \
  --output production.baseline.json \
  --sign-key mcpdrift.ed25519.pem

./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json \
  --verify-key mcpdrift.ed25519.pub.pem
```

Keep private signing keys outside the repository.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | PASS / no drift |
| 1 | REVIEW-level drift |
| 2 | FAIL-level drift |
| 3 | Probe, discovery, usage, or output failure |
| 4 | Baseline or key artifact error |
| 5 | Baseline signature/integrity verification failure |

## Post-certification drift

Certification establishes an approved MCP package and reviewed runtime surface at a point in time. DriftGuard addresses the later operational question:

> Does the MCP surface running now still match what was approved?

This is directly useful in environments where publishers or administrators are expected to keep a live MCP implementation aligned with an approved or certified definition and resubmit material changes such as new tools or significant metadata changes.

DriftGuard does not certify MCP servers and is not affiliated with or endorsed by Microsoft or the Model Context Protocol project. It provides independent integrity evidence that can complement certification, governance, change-management, and procurement workflows.

A practical pattern is:

```text
approved / certified MCP package
        ↓
DriftGuard baseline
        ↓
live MCP endpoint
        ↓
continuous or CI verification
        ↓
PASS / REVIEW / FAIL
```

## Trust boundary

DriftGuard observes the externally visible MCP surface. It does **not** claim that an unchanged external surface proves an unchanged binary, source tree, dependency graph, container image, or backend implementation.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SPEC.md](SPEC.md).

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/mcpdrift
```

## Protocol coverage

- MCP 2026-07-28 stateless discovery using `server/discover`
- Per-request protocol metadata and `Mcp-Method` routing headers
- Header-aware observation compatible with current 2026-07-28 stateless requests
- Legacy initialize/session fallback through 2025-11-25
- Bounded pagination for tools, resources, and prompts
- Fail-closed discovery when an advertised inventory cannot be enumerated
- OAuth Protected Resource Metadata discovery
- RFC 8414 / OpenID Connect authorization-server metadata discovery
- TLS certificate and SPKI SHA-256 fingerprints

## Roadmap

- Broader independent MCP interoperability fixtures
- Cache-hint (`ttlMs` / `cacheScope`) drift observation
- Named-operation (`Mcp-Name`) evidence where applicable
- Change-notification/subscription observation
- OpenTelemetry events
- Published container release
- Baseline approval metadata and rotation policy
- Optional adapters for external governance systems

## Project independence

MCP DriftGuard is designed as a standalone product. Optional integrations may be added later under adapters, but the core CLI and baseline format will not require DDC, DSR, or any Altru.dev infrastructure.

## Author

**Valentyn Rukhaylo**  
Altru.dev  
LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

Copyright © 2026 Valentyn Rukhaylo / Altru.dev.

## Open-source and commercial model

MCP DriftGuard Core remains a useful open-source verifier: local inspection, baselines, signatures, drift analysis, CI output, and interoperable evidence formats belong in the public core.

A future hosted or enterprise product may add fleet monitoring, history, approval workflows, RBAC/SSO, integrations, managed evidence, private deployment, and support without being required for local verification.

See [COMMERCIAL.md](COMMERCIAL.md).

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

Apache-2.0 permits commercial use and redistribution, includes an explicit patent grant, preserves attribution and NOTICE obligations, and does not grant project branding rights beyond customary attribution.
