# Threat Model

## Protected claim

MCP DriftGuard protects the claim:

> The observable security-relevant MCP surface currently exposed by an endpoint matches the approved baseline.

## Threats considered

- Capability drift: tools, resources, prompts, annotations, or protocol capabilities appear/change after approval.
- Authority drift: an approved tool accepts a wider schema or externally declares broader authority.
- Identity drift: endpoint, MCP server identity, protocol declaration, or TLS identity changes.
- Authorization drift: externally observable authentication/authorization state changes.
- Description drift: descriptions change in ways that may imply broader write/delete/export/execute/admin behavior.
- Baseline tampering: stored approval evidence is modified to normalize an unauthorized live state.

Baseline tampering is mitigated with SHA-256 integrity verification and optional Ed25519 signatures.

## Out of scope

A backend can change while preserving the same externally observable MCP surface. DriftGuard cannot detect that from protocol observation alone.

A party controlling both the endpoint and the observer's network path may be able to present a selective view. Independent observers and supply-chain attestations are future hardening options.

## Security posture

DriftGuard does not invoke discovered MCP tools during inspection.
