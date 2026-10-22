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
| Execution | Linux privileged launcher and bounded verifier capture | Absent; no subprocess or network operation in library/CLI |

The canonicalizer serializes typed structures into a sorted JSON value before encoding. Only fixed ASCII property names, strings, unsigned integers and booleans are present. No claim is made to implement general RFC 8785 canonical JSON for arbitrary documents or Python arbitrary-precision numbers. Policy input whitespace and property order do not affect signing. Duplicate properties fail parsing rather than silently selecting a value.

`tests/fixtures/python-policy.json` was produced with the existing Python `evidence_signatures.canonical` and `cryptography` Ed25519 signer using the public disposable seed `[42;32]`. It includes exact canonical bytes, public key and detached signature. The Rust test compares bytes and verifies that signature. It uses fixed historical timestamps and grants no live authorization. Other tests sign with disposable deterministic test keys and cover independent evidence key verification, tampering, wrong keys, artifact substitution, invalid schemas/types, endpoint confusion, expiry edges, invalid IDs/digests, ledger races, existing marker/symlink denial, unsafe directory mode, and invalid CLI invocations. These are local tests, not privileged host deployment or sandbox validation.

Migration requires external public key format conversion and provisioning, one fixed protected ledger for any future execution service, a distinct execution evidence design, execution confinement and artifact pinning. None of those missing service features is represented as implemented by this offline checker.
