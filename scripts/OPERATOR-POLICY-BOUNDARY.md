# Experimental operator verification policy

This Python operator wrapper is experimental and loopback-only. The original Go CLI is unchanged. Codex reads the resulting evidence; independent administrators provision approvals and keys. The wrapper requires `cryptography` and never installs dependencies.

## Fixed administrator custody

Approval verification uses only `/etc/mcpdrift/trust/operator-approval-ed25519.pub.pem`. Evidence signing uses only `/etc/mcpdrift/trust/operator-evidence-ed25519.pem`; there is no caller-selected private-key argument or environment override. Both must be regular, root-owned files with no group/world write permission. The private key must additionally have no group/world permissions (typically mode 0600). Every ancestor must be a root-owned directory without group/world write permissions. Symlinks anywhere in these paths are rejected. Missing or unsafe paths fail closed before verifier execution.

Administrators must independently distribute the evidence public key. A report and its detached `<output>.sig.json` alone do not establish trust. These checks require administrator provisioning; they do not establish hardware-backed custody or prevent privileged key theft. Never put real signing keys in the repository or agent-accessible workspaces. Tests generate disposable keys and substitute fixture paths in-process; they never read production keys or modify `/etc`.

## Signed one-time authorization

`--policy` and `--policy-signature` supply a canonical-JSON Ed25519 signed policy with exactly these fields:

- `schema`: `mcpdrift-operator-policy/v2` (legacy v1 policies are rejected).
- `endpoint`: the exact approved `http://127.0.0.1` URL, without credentials or fragments.
- `binary_sha256` and `baseline_sha256`: approved artifact digests.
- `authorization_id`: a fresh administrator-generated random 128-bit identifier encoded as 32 lowercase hexadecimal characters.
- `issued_at` and `expires_at`: integer Unix seconds, with `issued_at <= now < expires_at` and a positive lifetime of at most 300 seconds. Booleans are rejected.

All fields are signed together. The evidence records the authorization ID, expiry, and SHA-256 of the canonical verified policy snapshot. Changing the ID, endpoint, timestamps, or artifact digests invalidates the signature. The administrator must issue a new ID for each authorized attempt.

The fixed ledger directory `/var/lib/mcpdrift/consumed-authorizations` must already exist, be root-owned with no group/world permissions (typically 0700), and have the same protected, symlink-free ancestry. The wrapper does not create it. After signature, key, endpoint, artifact, and output checks, the wrapper rechecks expiry and atomically creates a marker named by authorization ID using exclusive creation relative to an opened directory descriptor. It records the policy digest, flushes the marker and directory with `fsync`, and only then starts the verifier. Any ledger error denies execution. Concurrent processes sharing this local ledger admit at most one attempt per ID; re-signing or changing a policy with the same ID does not reset consumption. Existing markers, including symlinks, deny execution.

Consumption is permanent for that ledger: verifier failures, timeouts, signing/output errors, and crashes after marker creation burn the approval. Administrators must not delete markers or reuse IDs. Fresh approvals are needed for retries. Expiry limits when execution can start, not when it must finish. Expiry is checked immediately before consumption, not throughout execution.

## Limits

This is **local replay resistance**, not distributed replay protection. Separate hosts or ledger directories can each accept the same approval. Ledger deletion, rollback, restoration from an older backup, filesystem durability failures, or privileged tampering can restore replay opportunities. Do not prune markers without an independently justified retention and clock policy. Clock rollback can make an unused expired approval appear current; there is no trusted clock or external monotonic service. Ledger growth and burned approvals can cause denial of service.

Root and the administrator-controlled filesystem are trusted. Path ownership/mode checks are not safe descriptor pinning of keys, artifacts, or every ancestor against concurrent privileged replacement. The verifier binary and baseline can still be swapped between digest checks and use; the verifier is not sandboxed and output is not bounded. Output and detached signature publication is not a single atomic transaction, so incomplete pairs must be rejected by consumers. Local users must not receive generic privileged access to this wrapper: signed artifact selection is not process confinement. These controls do not establish production authorization lifecycle, separated key custody, or a production security broker. No production or third-party endpoint use is authorized by this experiment.
