# Changelog

## v0.1 public preview — 2026-09-14

Initial public preview of MCP DriftGuard.

### Core
- deterministic MCP endpoint inspection
- canonical snapshots and SHA-256 fingerprints
- Ed25519-signed baselines
- PASS / REVIEW / FAIL drift verdicts
- JSON, text, and SARIF output

### Protocol coverage
- current stateless MCP discovery path
- legacy initialize/session fallback
- bounded pagination for tools, resources, and prompts
- fail-closed behavior for incomplete advertised inventories

### Security evidence
- OAuth protected-resource metadata observation
- authorization-server metadata observation
- TLS certificate and SPKI SHA-256 fingerprints
- bearer-token support without persisting credentials into evidence artifacts

### Drift analysis
- new and removed capability detection
- deterministic schema-widening and narrowing classification
- authorization and protocol drift
- TLS public-key identity drift
- security-sensitive description changes

### Integration
- CLI
- Docker
- GitHub Action
- SARIF
- CI release gate

### Demonstration
The included demo server proves the central behavior:

1. create an approved baseline
2. verify unchanged server → PASS
3. expose a new tool, `export_customer_database`
4. verify again → FAIL with exit code 2

MCP DriftGuard Core is licensed under Apache-2.0.

Created by Valentyn Rukhaylo / Altru.dev.

## Frequency Guardian 0.2.0 diagnostic foundations

- Separate attested P-256 candidate with external challenge and explicit bounded public certificate export.
- Offline independent Rust DER inspection and pinned-root OpenSSL signature verification; no production enrollment.
- Lost-device recovery specification with pre-provisioned offline recovery key and atomic revocation epoch.
