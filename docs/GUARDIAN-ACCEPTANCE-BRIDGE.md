# Guardian Android export to independent verifier bridge

Historical diagnostic/proposed contract. The current native tap approval workflow,
independent enrollment, revocation and safe replacement are specified in
[GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Its tap policy supersedes earlier
per-operation biometric/password requirements. Existing diagnostic bridges and
quorum evidence validators retain their diagnostic-only verdicts.

Run `guardian-acceptance DIAGNOSTICS.json ATTESTATION.json CHALLENGE_HEX INDEPENDENT_ROOT_PIN_SHA256_HEX` on the offline verifier machine. The JSON exports come from the Android `Save diagnostics JSON` and `Save attestation JSON` actions. The challenge must be generated externally and matched to the exported candidate; the pinned root fingerprint must be provisioned separately and must not be trusted from the Android export.

The bridge checks the ten-slot Android diagnostic contract and independently calls the pinned-chain cryptographic attestation verifier. On verified chain and challenge it emits `PENDING_INDEPENDENT_TRUST`, not a production enrollment approval. Application identity validation, revocation status, durable challenge consumption, device binding, and actual recovery remain unimplemented and are explicitly false in the report. Any invalid input fails closed and produces no acceptance report.

Do not equate `attestation_chain_verified_against_supplied_pin` with authorization. Android remains without network permissions and no remote execution is added.

## Fresh challenge issuance and replay control

Create an operator-owned directory with `chmod 700`, then run `guardian-challenge PRIVATE_CHALLENGE_DIRECTORY` to produce a 32-byte cryptographically random challenge with a five-minute lifetime. On the phone, enter its `challenge_hex` when generating the attestation candidate. Supply the resulting saved attestation and diagnostics JSON exports to `guardian-acceptance DIAGNOSTICS.json ATTESTATION.json CHALLENGE_HEX INDEPENDENT_ROOT_PIN_SHA256_HEX PRIVATE_CHALLENGE_DIRECTORY`. After independent certificate verification, acceptance durably marks the issued challenge consumed; duplicates and expired challenges refuse. The owner must separately supply trusted root pins. A passing certificate challenge remains diagnostic-only and cannot authorize production, particularly until the device's signing key is cryptographically bound to attestation and the app identity is verified.

## Candidate binding required

The acceptance command now requires a sixth argument `BINDING.json` after the challenge-ledger directory. The verifier compares the candidate key in that binding to the public key extracted from the cryptographically verified attestation leaf and verifies the authenticated signature made by the prior key. Mismatch rejects the entire acceptance operation before marking the issued challenge consumed. This proves a signed association, NOT that the prior key was hardware-attested. The bridge still returns `PENDING_INDEPENDENT_TRUST` until application identity, revocation and recovery are implemented.

## Application identity policy

Independent acceptance also requires `PACKAGE_NAME APK_SIGNING_CERT_SHA256_HEX` as final command arguments. The verifier now examines the Android attestation Application ID (authorization tag 709) and rejects missing/duplicate IDs, shared-UID package ambiguity, incorrect package names and signer fingerprints. Both policy values must be obtained independently of the phone's JSON exports. This check does not replace certificate revocation, recovery activation or deployment approval; diagnostic status remains pending.
