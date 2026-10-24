# Evidence contract comparison (experimental)

This package compares **declared** per-actor evidence semantic contracts, not proof that runtime messages follow them. Claim IDs must be stable and unique. Changes or disappearance of contract meaning are HIGH-severity candidates for independent review. It does not infer success from acknowledgements, backdate knowledge, merge actor knowledge, or discard historic states. Callers must preserve old evidence records and validate receipt signatures and timestamps independently.

Not yet integrated into MCP discovery, baseline signing, the CLI, or observed-flow replay. Consequently, issue #3 is **not resolved** by this addition; further work requires versioned evidence manifests, signed/provenanced observations, historical append-only replay, and failure injection at the verifier boundary.

### Signed declaration CLI

`mcpdrift evidence-sign --sign-key private.pem --output original.manifest.json claims.json`

`mcpdrift evidence-diff --verify-key public.pem original.manifest.json proposed.manifest.json`

Inputs are arrays of declared `Claim` objects. Both manifests MUST verify under the explicitly chosen public key. Exit 0 means matching declarations only; 2 means drift, 5 means a failed signature or rejected manifest. This CLI does not observe MCP runtime receipts and does not replace an append-only evidence ledger.
