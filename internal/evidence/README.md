# Evidence contracts and discovery ledger (experimental)

This package implements the offline evidence portion of [issue #3](https://github.com/altrudev/MCP-DriftGuard/issues/3). It compares declared semantic contracts and verifies signed actor assertions with append-only replay. The opt-in HTTP discovery path captures locally observed RPC outcomes. It does not validate the truth of a source, prove tool execution from discovery or an acknowledgement, or establish real-world clock accuracy. Issue #3 remains unresolved: runtime behavior semantics and independent reconstruction acceptance are absent.

Claim IDs are stable and unique. Changes to actor, receipt meaning, timestamp meaning, authority, errors, acknowledgements, provenance or reconstruction meaning produce HIGH-severity drift candidates. Equality means matching declarations only.

## Signed declarations

```sh
mcpdrift evidence-sign --sign-key private.pem --output original.manifest.json claims.json
mcpdrift evidence-diff --verify-key public.pem original.manifest.json proposed.manifest.json
```

Inputs to `evidence-sign` are arrays of `Claim` objects. Both manifests in `evidence-diff` must verify under the explicitly selected public key. Exit 0 means matching declarations; 2 means drift; 5 means failed verification. Signing errors and file errors return 4, and usage errors return 3.

## Offline ledger verification

```sh
mcpdrift evidence-verify \
  --manifest original.manifest.json --verify-key public.pem \
  --actor-keys actor-keys.json \
  --expected-head "$TRUSTED_HEAD" observations.json
```

`actor-keys.json` is an operator-controlled JSON object mapping actor names to Ed25519 public key PEM paths, for example `{"agent-a":"keys/agent-a.pub.pem"}`. Relative paths resolve from the working directory. Declaration and actor keys may differ. Never accept a trust configuration supplied by the party whose ledger you are verifying.

The ledger envelope is `{"format":"mcpdrift-evidence-ledger/v1","observations":[...]}`. Use the Go `SignObservation` API to create observations, `NewLedger` and `Append` to validate each addition, and `File` to serialize the retained history. Each observation includes:

- `format` (`mcpdrift-evidence-observation/v1`), global `sequence` starting at 1, and `previous` (empty for the first record, otherwise the previous record digest).
- `contract` (the signed manifest digest), `actor`, `claim` (owned by that actor), and nonempty `branch`.
- Optional `retry_of`, referencing an earlier observation on a different branch of the same actor and claim. Every record on an existing branch preserves its initial retry ancestry.
- `observed_at` (RFC3339Nano acquisition time), optional `event_at` (no later than acquisition), and nonempty provenance `source`.
- `state`: `unknown`, `inferred`, or `observed`; `kind`: `receipt`, `acknowledgement`, `error`, or `assertion`; and a string `value`.
- Optional `supports`, containing unique digests of earlier same-actor observations, plus `digest` and `signature`.

`SignObservation` sets the format, empties digest and signature, JSON-encodes the Go observation struct in field order, hashes it with SHA-256, and signs the digest with Ed25519. Digest is lowercase hex; signature is standard base64. Empty optional fields are omitted; the empty digest and signature fields are included in the signed payload. Exported fields and field order in `ledger.go` define this version's encoding. Signatures bind provenance labels and epistemic labels as assertions, not as independently established facts.

For example, an offline producer in this repository can construct a first record with:

```go
o, err := evidence.SignObservation(evidence.Observation{
    Sequence: 1, Contract: manifest.Digest,
    Actor: "agent-a", Claim: "receipt/1", Branch: "initial",
    ObservedAt: "2026-10-24T12:00:00Z", State: "unknown",
    Kind: "acknowledgement", Source: "synthetic-offline-fixture", Value: "received",
}, actorPrivateKey)
// Check err, then ledger.Append(o); check its error before serializing ledger.File().
```

Verification returns JSON with the verified record count, head digest, checkpoint status and explicit offline scope. Exit 0 means the submitted assertions pass the signature and replay rules; 5 means a rejected ledger, signature, chronology, or checkpoint; 4 means a file/key/configuration error; 3 means usage error. Empty ledgers are representable and prove no observations.

## Invariants and limits

`History(actor, throughSequence)` returns copies of only that actor's historical prefix, preserving unknown states, failures, receipts, acknowledgements and all retry branches. It never collapses history into a latest-success view. Acquisition times cannot move backwards within an actor; delayed evidence may describe an older event but only enters history at its append sequence. No clock ordering is imposed between independent actors. Supports and retry parents cannot cross actors or refer to future/missing evidence. An observed assertion cannot use unknown or inferred support to promote certainty. Inferred assertions remain explicitly inferred; acknowledgements do not become proof of execution.

The global hash chain establishes record order, not shared knowledge. The offline verifier sees the entire submitted file; `History` provides actor-filtered replay, not a multi-user authorization service. Source strings and wall clock timestamps remain signer assertions. A signer can lie, omit facts or sign alternate histories; signatures alone cannot prevent that.

Bounds are 4,096 observations, 16 KiB of compact JSON per observation and 8 MiB cumulative compact observation bytes. Decoder input is also capped at 8 MiB, including envelope and whitespace. Producers must keep serialized files within that input bound. Capacity failures reject appends without evicting history. The API owns copies of keys, observations and nested support slices; failed appends leave the prefix unchanged. It is a serial in-memory ledger, with no concurrent writer or durable storage guarantees. Store exported histories durably through an application-specific mechanism.

The decoder rejects unknown fields, malformed/trailing JSON and oversized input. Verification rejects edits, interior deletions, duplicates and reordering. A valid prefix remains a valid ledger: retain the latest trusted head independently and pass `--expected-head` to detect suffix truncation or substitution. Without a checkpoint, verification makes no completeness or freshness claim. Preserve the corresponding manifest and trust configuration with each archived ledger; changing a declaration starts a separately reviewed ledger.

Tests inject signed invariant violations and corrupted records at append, replay and CLI boundaries. These are synthetic offline tests, not live MCP observations.

Broader DDC architecture/products: Valentyn Rukhaylo / Altru.dev. Evidence/replay refinements were materially sharpened through Valentyn Rukhaylo's public technical engagement with Jason McGill, as attributed in issue #3.

## Opt-in HTTP discovery acquisition

An application can attach the existing HTTP discovery client to a separately trusted
observer ledger (declaration and observer keys remain separately configured):

```go
client := observe.New()
client.DiscoverySink = func(d evidence.Discovery) error {
    return ledger.RecordDiscovery(d, "observer", "discovery", "attempt-1", "", observerKey)
}
snapshot, err := client.Inspect(ctx, endpoint)
// Check err even if a partial snapshot exists. Archive ledger.File() and retain
// ledger.Head() independently, including failed attempts.
```

This is an internal Go API, not a new CLI flag. The sink is synchronous, opt-in and
fail-closed: rejected appends fail acquisition; modern fallback cannot hide an append
failure. Existing safe transport and endpoint policy still apply. No telemetry or
external storage is added. Configure endpoint paths without secrets; evidence mode
rejects endpoint queries, userinfo and fragments before sending. Headers, bearer
credentials, session identifiers, response bodies and error messages are not retained.
Request hashes bind the exact generated JSON, including ID, cursor and protocol
metadata. Request ID is recorded separately. Response hashes cover the existing
bounded RPC body reader's output (first SSE data payload for SSE; at most 4 MiB for
JSON, 8 KiB prefix for HTTP errors), not a full wire transcript or completeness proof.
HTTP status 0 means no HTTP response acquired. Transport, HTTP, decoding and RPC
errors remain distinct; a valid matching JSON-RPC envelope is only a discovery
response. Tool input/output behavior, effects and authority remain unknown.

Each typed `discovery` field is included in the observation signature and chain.
`RecordDiscovery` uses acquisition completion as `observed_at`, preserves the
start time, endpoint, method, request ID/hash, response hash and status, and signs
with the observer's key. It cannot write another actor's claim. Separate retry
branches can reference the earlier observation digest using the existing retry
rules; no failure is replaced. Legacy initialization and list RPCs are covered;
initialized notifications, authorization metadata, TLS probes and stdio are outside
this recorder's scope. No tool invocation method is allowed by evidence validation.

`CompareDiscovery` operates on observations from verified ledgers; it does not
verify signatures itself. It requires the same actor, claim, contract, endpoint,
method and exact request hash. Status, HTTP status and RPC error-code changes are
demonstrable changes in what the observer received. Changed response hashes are
`UNKNOWN` semantic-impact candidates, never proof of behavior drift. Equal hashes
prove only equal captured bytes. Different requests are incomparable rather than
silently equated. Arbitrary result semantics, server claims, authority changes,
event time truth and end-to-end reconstruction remain unproven. Signed assertions
can still be fabricated by a compromised observer; independent acceptance and
trusted checkpoints are required. The new transport tests are synthetic, socket-free
fixtures, not live deployment proof.

## Conformance and release dispositions

The conformance runner always tests negative and positive closure-gate dispositions
and always invokes the actual release gate. Provide local reviewed inputs:

```sh
GOCACHE=/tmp/mcpdrift-gocache python3 scripts/conformance_suite.py \
  --issues /path/to/github-issues.json --dispositions /path/to/reviewed-dispositions.json
```

Without those files, the mandatory release gate fails closed; no GitHub API access
is attempted. Passing synthetic gate tests cannot establish release closure. An open
issue may be `blocked` or `deferred` with explicit evidence, but cannot be `verified`.
A passing disposition inventory is not certification or proof that all issues are
complete. The operator must independently establish inventory completeness,
freshness and runtime evidence quality. Keep actual #3 blocked/deferred pending
independent runtime behavior proof; discovery tests do not satisfy its acceptance.
