# Threat Model

## Protected claim

MCP DriftGuard protects this claim:

> The externally observable security-relevant MCP surface currently exposed by an endpoint matches the approved baseline under the observation checks implemented by this DriftGuard version.

A PASS is an integrity comparison result, not a statement that the endpoint is intrinsically safe.

## Threats considered

- **Capability drift:** tools, resources, prompts, annotations, or protocol capabilities appear or change after approval.
- **Authority drift:** an approved tool accepts a wider class of inputs or otherwise exposes greater authority.
- **Transport identity drift:** endpoint or TLS public-key identity changes.
- **Protocol drift:** supported/negotiated MCP protocol behavior changes.
- **Authorization drift:** authentication challenges, protected-resource metadata, authorization servers, scopes, issuer/resource declarations, or related observable authorization state changes.
- **Description drift:** text changes introduce security-sensitive verbs or materially different declared behavior.
- **Partial-observation normalization:** a failed list request or missing pagination page makes a dangerous live server appear smaller than it really is.
- **Baseline tampering:** stored approval evidence is modified to normalize an unauthorized live state.
- **Metadata redirection / SSRF:** untrusted discovery metadata attempts to make the observer fetch arbitrary internal URLs.
- **Credential disclosure:** credentials used to inspect a protected endpoint are accidentally embedded into evidence artifacts.

## Mitigations

- advertised inventories fail closed when enumeration cannot complete
- pagination is bounded and exhaustive within the configured limit
- SHA-256 protects baseline integrity
- optional Ed25519 signatures protect baseline authenticity
- TLS certificate and SPKI SHA-256 fingerprints provide transport identity evidence
- protected-resource metadata is constrained to the observed endpoint origin
- authorization-server discovery requires HTTPS except for loopback development endpoints
- metadata responses are size-bounded
- bearer credentials are read at execution time and are not included in snapshots/baselines
- DriftGuard never invokes discovered tools during inspection

## Self-reported MCP identity

MCP server name/version metadata is self-reported. DriftGuard records changes to it as metadata drift, but does not use it as cryptographic proof of endpoint identity.

## Out of scope

A backend can change while preserving exactly the same externally observable MCP surface. DriftGuard cannot detect that condition from protocol observation alone.

A party controlling both the endpoint and the observer's trusted network/PKI view may be able to present a selective surface.

An approved baseline may itself describe a malicious or over-privileged server. DriftGuard proves consistency with that baseline; it does not certify the baseline as safe.

Supply-chain attestations, independent multi-observer verification, and active behavioral execution are separate assurance layers.
