# MCP DriftGuard v0.1 Specification

## Objective

MCP DriftGuard compares an approved observation of an MCP endpoint with a later observation and reports security-relevant drift.

The unit of comparison is the **externally observable MCP surface**, not the server implementation.

## Protocol coverage

v0.1 prefers MCP `2026-07-28`, using stateless `server/discover` negotiation and per-request protocol metadata. For older servers it can fall back to the initialize/session model through `2025-11-25`.

A modern-protocol error MUST NOT automatically trigger legacy fallback. Fallback is allowed only when the response provides evidence that the modern discovery method is unsupported.

## Observation completeness

If a server advertises tools, resources, or prompts, DriftGuard MUST enumerate that advertised inventory successfully before accepting the observation.

Paginated inventories MUST be followed until `nextCursor` is empty, subject to a bounded page limit. A transport failure, malformed page, RPC error, or exceeded pagination limit makes the observation incomplete and MUST fail the probe.

Partial observations MUST NOT be accepted as baselines.

## Snapshot

A snapshot contains:

- endpoint
- negotiated and advertised MCP protocol versions
- self-reported server metadata
- advertised capabilities
- tools and input schemas
- resources
- prompts
- authentication challenge metadata
- OAuth Protected Resource Metadata when discoverable
- authorization-server metadata when discoverable
- HTTP transport metadata
- TLS certificate and SubjectPublicKeyInfo SHA-256 fingerprints

Self-reported server name/version fields are metadata only. They MUST NOT be treated as cryptographic server identity.

Observation time is evidence metadata and is excluded from the canonical identity hash.

Credentials used to observe an authenticated endpoint MUST NOT be persisted into snapshots or baseline artifacts.

## Canonicalization

Canonicalization MUST:

- sort tools by name
- sort resources by URI/name
- sort prompts by name
- normalize embedded JSON
- exclude volatile observation time
- preserve values that can alter authority, capability, authorization, protocol, or transport identity

The canonical representation is compact JSON fingerprinted with SHA-256.

## Baseline artifact

Format identifier:

```text
mcpdrift-baseline/v1
```

A baseline contains the source snapshot, canonical hash, creation time, endpoint, and an optional Ed25519 signature.

A signed baseline MUST fail verification when its canonical snapshot is altered.

## Drift classes

v0.1 reports changes including:

- identity
- metadata
- protocol
- authorization
- capability
- authority
- description

Examples:

- a newly exposed tool: HIGH
- TLS public-key fingerprint change: HIGH
- OAuth resource/authorization metadata change: HIGH
- input schema widening: HIGH
- input schema narrowing that can be proven: MEDIUM
- schema mutation whose direction cannot be safely proven: HIGH
- self-reported server-name change: MEDIUM metadata drift
- certificate rotation with stable public key: LOW

Schema widening includes deterministic cases such as making `additionalProperties` more permissive, removing required fields, or expanding an enum.

## Verdict

- PASS: no observed drift
- REVIEW: drift exists below the FAIL threshold
- FAIL: aggregate score reaches the FAIL threshold

The default v0.1 FAIL threshold is score >= 35.

## Outputs

v0.1 supports:

- human-readable text
- JSON
- SARIF 2.1.0 for diff/verify results

Exit status is part of the CLI contract and allows CI systems to distinguish PASS, REVIEW, FAIL, probe failure, baseline failure, and signature/integrity failure.

## Authorization discovery safety

Protected-resource metadata supplied by the MCP endpoint MUST remain same-origin with the observed endpoint.

Authorization-server metadata MAY be cross-origin because the authorization server is a distinct security principal, but non-loopback HTTP issuers MUST be rejected.

Metadata fetches MUST be size-bounded.

## Non-goals

v0.1 does not claim to:

- prove source-code, binary, container-image, or dependency identity
- establish that an approved baseline is safe
- invoke MCP tools as part of verification
- infer semantic equivalence using an LLM
- bypass MCP authentication
- act as an authorization proxy or firewall
- prove that an unchanged externally visible MCP surface implies an unchanged backend
