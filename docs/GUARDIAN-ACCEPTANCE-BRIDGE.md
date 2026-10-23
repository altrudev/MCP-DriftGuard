# Guardian Android export to independent verifier bridge

Run `guardian-acceptance DIAGNOSTICS.json ATTESTATION.json CHALLENGE_HEX INDEPENDENT_ROOT_PIN_SHA256_HEX` on the offline verifier machine. The JSON exports come from the Android `Save diagnostics JSON` and `Save attestation JSON` actions. The challenge must be generated externally and matched to the exported candidate; the pinned root fingerprint must be provisioned separately and must not be trusted from the Android export.

The bridge checks the ten-slot Android diagnostic contract and independently calls the pinned-chain cryptographic attestation verifier. On verified chain and challenge it emits `PENDING_INDEPENDENT_TRUST`, not a production enrollment approval. Application identity validation, revocation status, durable challenge consumption, device binding, and actual recovery remain unimplemented and are explicitly false in the report. Any invalid input fails closed and produces no acceptance report.

Do not equate `attestation_chain_verified_against_supplied_pin` with authorization. Android remains without network permissions and no remote execution is added.
