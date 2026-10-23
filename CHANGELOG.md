# v0.5.1 — private deployment preparation

- Fix foreground review/pairing state, validation retry and visible enrollment status; preserve existing Android identity and debug signer.
- Validate private authority/TLS-key state before listening; return generic HTTP refusals and add explicit real-network acceptance mode.
- Prepare a restricted dedicated systemd unit. Deployment, device acceptance and Git commit are blocked by execution-environment restrictions; see DEPLOYMENT_STATUS.md.

# v0.5.0 — online Android approval prototype

- Explicit HTTPS server pairing and foreground polling, readable signed action review, signed Approve/Deny delivery and durable acceptance lookup.
- Reuses independently attested candidate identity, authority/signer binding, revocation and replay enforcement; no automatic execution.
- Device-scoped random transport tokens, bounded API, rate limits, atomic receipts, negative tests and setup/threat-model documentation.
- APK retains the prior debug signer; physical-phone and deployment acceptance remain outstanding.

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
