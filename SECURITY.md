# Security Policy

MCP DriftGuard is pre-release security software. Do not treat PASS as proof that an MCP server is safe; PASS means the observed surface matched the supplied baseline under the checks implemented by the running version.

## Reporting vulnerabilities

Please avoid publishing exploitable vulnerabilities in a public issue before coordinated disclosure.

Contact the project owner through the Altru.dev contact channel or GitHub profile associated with this repository and include the affected version/commit, reproduction steps, impact, and suggested mitigation if known.

## Baseline signing keys

Never commit private baseline signing keys. Operators remain responsible for key custody and rotation.

## MCP credentials

For authenticated endpoints, DriftGuard can read a bearer credential from `MCPDRIFT_BEARER_TOKEN`.

The token is added to outbound HTTP requests at execution time and is not intentionally serialized into snapshots or baseline artifacts. Operators should still protect process environments, CI secrets, shell history, and diagnostic logs.

Do not pass production credentials as command-line arguments.

## Evidence handling

Snapshots can contain tool schemas, endpoint names, authorization metadata, resource identifiers, and other infrastructure details. Treat baseline artifacts as security evidence and apply access controls appropriate to that metadata.

## Observation limitations

DriftGuard does not execute discovered tools. It observes the declared MCP surface and transport/authorization metadata. See [THREAT_MODEL.md](THREAT_MODEL.md) for explicit assumptions and non-goals.
