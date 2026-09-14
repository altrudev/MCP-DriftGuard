# Open Core and Commercial Product Boundary

MCP DriftGuard Core is intended to remain a complete and useful implementation of local MCP drift verification.

## Public core

The public core should include:

- MCP endpoint inspection
- deterministic canonicalization and fingerprints
- baseline creation and verification
- signed baselines
- structural and authority drift analysis
- JSON and SARIF-compatible output
- GitHub Action and container execution
- local policy and CI use
- documented evidence formats and interoperability fixtures

## Commercial product

A separately operated DriftGuard service may add organization-level capabilities such as:

- continuous scheduled monitoring
- fleet-wide MCP inventory
- historical evidence retention
- baseline approval workflows
- role-based access control
- SSO/SAML
- organization policy management
- alerts and incident routing
- SIEM and enterprise integrations
- managed keys and attestations
- private deployment options
- service-level agreements and support

The commercial service must not be required for local baseline creation or verification.

## Compatibility principle

Commercial services should consume the same public baseline and result formats wherever practical. Users should be able to generate and verify evidence locally without sending MCP metadata to a hosted service.

## Independence

The core has no required dependency on DDC, DSR, DDCal, Altru.dev infrastructure, an LLM provider, or a hosted DriftGuard account. Optional adapters must remain separable from the core verification path.
