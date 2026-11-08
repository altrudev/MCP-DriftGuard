# Frequency Guardian v0.3 diagnostics

Historical diagnostic/proposed contract. The current native tap approval workflow,
independent enrollment, revocation and safe replacement are specified in
[GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Its tap policy supersedes earlier
per-operation biometric/password requirements. Existing diagnostic bridges and
quorum evidence validators retain their diagnostic-only verdicts.

The home screen has **Run All Diagnostics**, ten visible results, and **Export
diagnostics JSON**. One system authentication signs a fresh local fixture.
Export uses an allowlisted read-only JSON Sharesheet attachment. Schema
`frequency-guardian-diagnostics/v3` includes app version, run timestamp,
`production_eligible: false`, `private_keys_exported: false`,
`external_attestation_challenge_required: true`, and ten named checks with
`pass`, `fail`, or `pending` plus evidence/limitations. No private keys,
certificates, credentials, or settings enter this report. The separate public
certificate export still requires its metadata warning.

| Check | Meaning |
| --- | --- |
| hardware | Local Keystore KeyInfo reports secure hardware; software/unknown fails |
| ecdsa | Authenticated device signature verifies locally; cancellation is pending, signing errors fail |
| tampering | Modified digest fails verification against the same signature |
| nonce | Two fresh 32-byte nonces differ; consumed fixture refuses replay |
| expiry | Local fixture refuses pre-issuance and expiry timestamps |
| identity_continuity | First observation pending; later runs compare persisted SPKI baseline; matching baseline remains pending independent continuity evidence; mismatch fails without replacing baseline |
| strongbox | API 31+ StrongBox passes; TEE/software fails this specific check; API 30 pending |
| attestation_certificate_status | Missing chain pending; bad bounds, dates or missing Android extension fail; locally valid chain remains pending independent trust verification |
| recovery_readiness | Pending: offline identity, quorum, revocation and recovery ceremony are unimplemented |
| update | Pending: same-package/same-certificate installation and physical-device identity continuity need upgrade acceptance |

Attestation generation **requires a fresh external independent verifier challenge**
(32 random bytes / 64 hex characters). Run All never invents a challenge or
replaces the attestation candidate. Presence of certificates does not verify
challenge freshness, chain trust, pinned roots, revocation, application identity
or hardware claims. Use the v0.2 offline verifier protocol. Local KeyInfo and
passing diagnostics confer no production approval, enrollment or recovery.

The original device-key alias, app package, launcher icon resources and existing
local APK debug signing keystore are preserved. Baselines are local observations,
not remote enrollment evidence. Uninstall/clear storage loses both identity and
baseline; do not use either for recovery. Report state is in memory; recreation
requires a new run and cannot promote incomplete authentication to a pass.

Host tests cover schema membership, pending defaults, JSON escaping, real host
ECDSA verification and corruption rejection, nonce replay and time boundaries.
They do not establish device hardware custody. On a physical device, run on
StrongBox and TEE devices, cancel/background authentication, export JSON through
a document receiver, check API 30 pending behavior, compare repeated identity
runs, and install v0.3 over v0.2 with the same APK certificate before comparing
SPKI. Actual update and recovery readiness remain pending, even if local tests pass.

JSON export correction: diagnostics, public pairing, attestation and nonsecret settings now use Android ACTION_CREATE_DOCUMENT (`application/json`) to save a named JSON file to the user-selected destination. No Sharesheet or clipboard is needed for JSON. Destination cancellation does not save; failed writes are reported rather than assumed successful.
