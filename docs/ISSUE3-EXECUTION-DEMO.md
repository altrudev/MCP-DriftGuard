# Opt-in local execution evidence demonstration (issue #3)

Run from the repository root on a machine permitting loopback listeners:

```sh
go run ./cmd/execution-demo --confirm execute-local-mock-only > /tmp/execution-evidence.json
GOCACHE=/tmp/ddc-issue3-cache go test ./...
```

Without the exact confirmation the command fails before listeners or execution.
It creates only its own short-lived loopback HTTP mock, governed proxy/observer,
and separate read-only state endpoint. It never selects production endpoints,
loads credentials, invokes a process tool, or accepts arbitrary arguments or URLs.
The only tool is `mock.put_record`, with three fixed synthetic operation keys.
The proxy requires confirmation on every POST, exact JSON-RPC tools/call shape,
and bounded strict JSON. Redirects and environment proxies are disabled. This is
an execution fixture, not a complete MCP session/initialization implementation.
Do not expose these listeners as a service: the fixed confirmation string is an
explicit consent guard, not authentication against other local processes.

The scenarios are a normal write, retry with a new request ID and the same
operation key, server false-success without a write, and a write whose response
times out. The mock stores each operation only once, preserving the first request
hash. Exact request-ID replay is rejected before forwarding. Retry observations
retain the original observer branch digest as retry ancestry. State verification
uses GET on a different endpoint and never invokes tools/call.

The existing signed actor ledger stores JSON metadata in observation Value:

* `request_observed`: the observer accepted a governed request; forwarding or
  execution is not thereby proven.
* `response_acknowledged`: a matching JSON-RPC success response was received;
  durable state and tool success are not thereby proven.
* `outcome_unknown`: timeout leaves execution unknown even when state is later
  found. The earlier observation remains unknown.
* `independent_state_observed`: the verifier read presence/absence and the
  stored first-request hash. An absent false-success record contradicts the
  acknowledgement in this controlled fixture. Presence without a matching
  request hash establishes no correlation. Even a matching hash alone does not
  prove causation, authenticity of the server, or absence of other writers.

Observer and verifier have separate ephemeral signing keys and declared claims.
The verifier does not promote or use cross-actor ledger support. No sensitive
bodies, credentials, private keys, or raw HTTP responses are exported. Hashes
are bindings for fixed synthetic inputs, not anonymization for real secrets.

The output includes the signed manifest, ledger, public keys, and final head.
Reconstruction uses DecodeLedger then VerifyLedger with independently trusted
manifest/actor keys and an independently retained expected head. Public keys in
this demo output are convenience material, not an external trust root. Without
an external checkpoint, a valid truncated prefix cannot be detected. Signatures
protect recorded assertions, not the truth of their underlying sources.

Tests cover missing confirmation, unauthorized methods/tools/URL fields, body
bounds, request replay, idempotent retry, timeout after write, false success,
actor substitution/isolation, tampering, prefix truncation, and JSON replay.
They explicitly opt in and use an in-memory HTTP RoundTripper with no network
fallback, exercising the same handlers. They run through the conformance runner's
existing go_unit/go_race suites; no live CLI execution is added to conformance.
Timing values, keys, signatures and hashes vary; assertions concern invariant
behavior. A one-second client deadline drives the timeout scenario.

## Gaps and validation limits

This advances issue #3; it does not close production end-to-end execution.
There is no production adapter, durable mock storage, multi-writer ledger,
external checkpoint distribution, independently administered verifier, real
service integration, credential management, or full MCP transport lifecycle.
All actors and state are controlled by one test process. State reads rely on the
mock's honesty; a malicious server controlling both surfaces can deceive both.
Idempotency is specific to the fixed mock operation keys, not a generic MCP
exactly-once guarantee. The HTTP CLI requires loopback socket permission.

In the restricted implementation workspace, the requested full go test command
was run; existing internal/observe HTTP tests fail because the sandbox denies
socket creation. Demo handler tests use the socket-free transport so their
behavior can still be checked here. A native loopback CLI rerun remains needed.
