# MCP DriftGuard v0.1 Specification

## Objective

MCP DriftGuard compares an approved observation of an MCP endpoint with a later observation and reports security-relevant drift.

The unit of comparison is the **observable MCP surface**, not the server implementation.

## Snapshot

A snapshot contains the endpoint, server identity, protocol version, advertised capabilities, tools, resources, prompts, captured authorization metadata, and transport/TLS observations.

Observation time is evidence metadata and is excluded from the identity hash.

## Canonicalization

Canonicalization MUST sort tools by name, resources by URI/name, prompts by name, normalize embedded JSON, exclude volatile observation time, and preserve values that can alter authority or capability.

The canonical representation is compact JSON fingerprinted with SHA-256.

## Baseline artifact

Format identifier:

```text
mcpdrift-baseline/v1
```

A baseline contains the source snapshot, canonical hash, creation time, endpoint, and an optional Ed25519 signature.

## Drift classes

v0.1 reports changes in these categories:

- identity
- protocol
- authorization
- capability
- authority
- description

Adding a tool or changing a tool input schema is HIGH severity by default.

## Verdict

- PASS: no observed drift
- REVIEW: drift exists below the FAIL threshold
- FAIL: aggregate score reaches the FAIL threshold

The default v0.1 FAIL threshold is score >= 35.

## Non-goals

v0.1 does not claim to prove source-code or binary identity, establish that an approved baseline is safe, execute tools as part of verification, infer semantic equivalence using an LLM, bypass MCP authentication, or act as an authorization proxy/firewall.
