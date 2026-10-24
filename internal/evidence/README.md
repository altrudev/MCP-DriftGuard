# Evidence contract comparison (experimental)

This package compares **declared** per-actor evidence semantic contracts, not proof that runtime messages follow them. Claim IDs must be stable and unique. Changes or disappearance of contract meaning are HIGH-severity candidates for independent review. It does not infer success from acknowledgements, backdate knowledge, merge actor knowledge, or discard historic states. Callers must preserve old evidence records and validate receipt signatures and timestamps independently.

Not yet integrated into MCP discovery, baseline signing, the CLI, or observed-flow replay. Consequently, issue #3 is **not resolved** by this addition; further work requires versioned evidence manifests, signed/provenanced observations, historical append-only replay, and failure injection at the verifier boundary.
