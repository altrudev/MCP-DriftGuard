# Python to Rust contract comparison

Reference: `scripts/approved_verification_evidence.py` and `scripts/evidence_signatures.py`. Python remains available and unchanged. This slice replaces authorization primitives, not the whole privileged operator service.

| Contract | Python experiment | Rust slice |
| --- | --- | --- |
| Policy | Exactly seven v2 fields | Same field names/version; unknown, missing and duplicate fields rejected |
| JSON signatures | Sorted compact UTF-8 JSON, Ed25519 | Same bytes for this typed schema; strict Ed25519 verification; canonical padded base64 |
| Numbers | Python integers, no booleans | Unsigned 64-bit integer seconds; rejects floats, exponents, negative values and booleans |
| Approval key | Fixed root-protected PEM file | Fixed root-protected raw-hex public key file; explicit provisioning format change |
| Endpoint | Exact signed URL, HTTP, parsed hostname 127.0.0.1, no credentials/fragment | Exact signed URL and explicit CLI match; ASCII literal host, port 1–65535, no whitespace/backslash/fragment; intentionally narrower |
| Digests | Compare artifact SHA-256 strings | Additionally require exactly 64 lowercase hex digits for both digests |
| ID | 32 lowercase hex digits | Same |
| Time | issued <= now < expires; lifetime <= 300 seconds | Same; checked again before ledger consumption |
| Replay | Fixed root-owned ledger, exclusive relative creation and fsync | Current-user private local ledger, exclusive descriptor-relative creation and fsync; CLI selects directory because no privileged service exists |
| Evidence | Signed execution verdict v1 with verifier result | Distinct offline-check/v1 receipt; no verdict or execution claim; external signatures independently verified |
| Execution | Linux privileged launcher and bounded verifier capture | Separate bounded offline replay and experimental Bubblewrap library runner; CLI remains offline; isolated networking without a relay |

The canonicalizer serializes typed structures into a sorted JSON value before encoding. Only fixed ASCII property names, strings, unsigned integers and booleans are present. No claim is made to implement general RFC 8785 canonical JSON for arbitrary documents or Python arbitrary-precision numbers. Policy input whitespace and property order do not affect signing. Duplicate properties fail parsing rather than silently selecting a value.

`tests/fixtures/python-policy.json` was produced with the existing Python `evidence_signatures.canonical` and `cryptography` Ed25519 signer using the public disposable seed `[42;32]`. It includes exact canonical bytes, public key and detached signature. The Rust test compares bytes and verifies that signature. It uses fixed historical timestamps and grants no live authorization. Other tests sign with disposable deterministic test keys and cover independent evidence key verification, tampering, wrong keys, artifact substitution, invalid schemas/types, endpoint confusion, expiry edges, invalid IDs/digests, ledger races, existing marker/symlink denial, unsafe directory mode, and invalid CLI invocations. These are local tests, not privileged host deployment or sandbox validation.

Migration requires external public key format conversion and provisioning, one fixed protected ledger for any future execution service, external execution-record signing and service deployment acceptance. The library coordinator and sealed runner implement consumption ordering and artifact pinning, while the CLI remains an offline checker.

Coordinator update (2026-10-22): the Rust library now connects validated signed policy,
durable exclusive one-time consumption, and the existing Bubblewrap runner. It emits
an unsigned execution record binding canonical policy digest, ID, observed verdict and
provenance or operational failure class. External signing remains separate. The CLI
and Go engine are unchanged. Production construction uses fixed approval key custody
and the system clock; runner/clock/key injection for coordinator tests is private.

The earlier `/proc/self/fd/3` artifact-delivery failure was addressed by the existing
sealed data-mount runner. Required live acceptance remains BLOCKED on this host:
`DRIFTGUARD_REQUIRE_LIVE=1 cargo test --offline --manifest-path broker/Cargo.toml`
fails because Bubblewrap cannot create the required namespaces (permission denied).
The separately forced `live_namespace_contract` gate fails for the same reason.
Ordinary offline tests skip unavailable live execution. Neither that skip nor an
unsigned failure record demonstrates successful live execution. The isolated network
still cannot reach a real MCP target. Do not merge or deploy until required-live
acceptance is independently demonstrated.
