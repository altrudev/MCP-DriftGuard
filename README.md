# MCP DriftGuard

**Continuous integrity verification for Model Context Protocol (MCP) servers.**

MCP DriftGuard answers a narrow security question:

> Does the security-relevant MCP surface running now still match the surface that was approved?

An MCP server can change after review: tools can appear, schemas can widen, descriptions can acquire new authority language, server identity can change, and authorization metadata can move. DriftGuard records a deterministic baseline and compares the live server against it later.

It is intentionally standalone: **no LLM, no DDC dependency, no hosted account, and no telemetry are required.**

## Status

Early v0.1 implementation. The CLI is functional, but the project should be treated as pre-release until interoperability testing across multiple production MCP implementations is complete.

## What it detects

- Added or removed tools
- Tool input-schema changes
- Tool annotation changes
- Security-sensitive description changes
- Added or removed resources and prompts
- MCP server identity and protocol-version changes
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

JSON output:

```bash
./mcpdrift verify https://server.example/mcp \
  --baseline production.baseline.json \
  --format json
```

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

## Trust boundary

DriftGuard observes the externally visible MCP surface. It does **not** claim that an unchanged external surface proves an unchanged binary, source tree, dependency graph, container image, or backend implementation.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SPEC.md](SPEC.md).

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/mcpdrift
```

## Roadmap

- Broader MCP transport/interoperability fixtures
- OAuth protected-resource discovery and authorization-server metadata capture
- Pagination and change-notification handling
- SARIF output
- GitHub Action packaging
- OpenTelemetry events
- Container release
- Baseline approval metadata and rotation policy
- Optional adapters for external governance systems

## Project independence

MCP DriftGuard is designed as a standalone product. Optional integrations may be added later under adapters, but the core CLI and baseline format will not require DDC, DSR, or any Altru.dev infrastructure.

## Author

**Valentyn Rukhaylo**  
Altru.dev  
LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6/

Copyright © 2026 Valentyn Rukhaylo / Altru.dev.

## License

MIT. See [LICENSE](LICENSE).
