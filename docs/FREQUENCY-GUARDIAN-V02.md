# Frequency Guardian v0.2: diagnostic evidence and lost-device protocol

Historical diagnostic/proposed contract. The current native tap approval workflow,
independent enrollment, revocation and safe replacement are specified in
[GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Its tap policy supersedes earlier
per-operation biometric/password requirements. Existing diagnostic bridges and
quorum evidence validators retain their diagnostic-only verdicts.

Status: offline diagnostic foundations only. No enrollment, broker trust update,
production approval, recovery execution or private-key export is enabled.

## Diagnostic ceremony and export

An independent reviewer generates 32 random bytes using an OS CSPRNG (for example
`openssl rand -hex 32`) and records the challenge, candidate identity, intended
application, expiry and one-use transaction identifier outside the phone. Paste
exactly 64 hex characters into the app. The phone cannot establish that pasted
bytes are random, fresh or from an authorized reviewer. It never generates a
replacement challenge automatically and never upgrades trust on generation.

The v2 candidate uses its own Android Keystore alias, P-256, SHA-256 and
per-operation authentication. StrongBox is requested; only
StrongBoxUnavailableException permits standard Keystore fallback. Generation
replaces only the disposable candidate. The v1 device signing key, its fingerprint
and diagnostic signing flow are preserved. A failed replacement can lose the old
candidate; generate a fresh external challenge and retry. No candidate signing or
production enrollment path is exposed.

Export is a separate explicit action with a metadata disclosure warning and share
confirmation. `frequency-guardian-attestation/v2` contains only diagnostic flags
and leaf-first base64 DER public certificates. It never reads private key bytes,
settings, credentials, device identifiers or recovery material. Certificates can
nonetheless disclose application/device/hardware metadata and should be treated
as sensitive public evidence. No unique device ID attestation is requested.
Bounds: 2–8 certificates, 16 KiB per certificate, 48 KiB aggregate DER and 70,000
UTF-8 bytes for JSON. No truncation: exceeding any limit refuses export. No chain
is automatically shared, copied, logged, uploaded or trusted. The app has no
Internet permission, telemetry or network client.

## Independent Rust diagnostic verifier

```
cargo run --offline --manifest-path broker/Cargo.toml --bin guardian-attestation -- EXPORT.json EXPECTED_CHALLENGE_HEX PINNED_ROOT_DER_SHA256_HEX
```

Obtain and authenticate the root DER SHA-256 pin out of band from an independently
maintained attestation trust policy. Never derive the accepted pin from this
export, accept a phone-supplied pin, or assume a self-signed root is trusted. This
repository supplies no production root allowlist. A caller-supplied pin is a
trust-policy input, not proof that the root belongs to Google or an OEM.

The Rust module bounds input, rejects unknown/duplicate JSON fields, parses DER
certificate/SPKI/Android KeyDescription fields, checks the externally expected
32-byte challenge, requires P-256 SPKI and hardware-enforced EC algorithm,
256-bit size, P-256 curve and generated origin, and refuses software/unknown
attestation or key security levels. It uses only cached Rust crates and a fixed
`/usr/bin/openssl verify` invocation with an empty environment except
`OPENSSL_CONF=/dev/null`, fixed generated filenames, no shell, no default trust
stores and no URL retrieval. The last exported certificate must exactly match
the independent DER root pin. OpenSSL checks signatures, certificate validity and
strict certificate path constraints against that root, including its self
signature. A second fixed invocation checks each adjacent exported issuer link,
so surplus or reordered certificates cannot be silently ignored. Missing OpenSSL, unsupported options, parse errors and cryptographic
errors all refuse verification; there is no parser-only success fallback.

Success describes diagnostic cryptographic checks only. It always reports
`production_eligible=false` and `enrollment_enabled=false`. It does not establish
challenge freshness/consumption, current root/revocation policy, application
package/signing-certificate allowlists, verified boot/locked-device policy,
patch requirements, authentication authorization policy, proof of possession,
certificate revocation status or resistance to a compromised trusted issuer.
Those checks and physical-device validation remain prerequisites for any future
enrollment. Exported flags and local KeyInfo claims confer no authority.

## Explicit future lost-device migration protocol

This is a protocol specification, not an implemented recovery feature.

1. **Before loss:** independently generate an offline recovery signing key in a
   nonexportable offline hardware token. Register its public key and fingerprint
   through the existing trusted quorum; store a second independently controlled
   recovery factor according to the organization's quorum policy. Keep the
   recovery token physically separate from the phone. Do not place its private
   material, seed, backup or credentials in Guardian, exports or broker storage.
   Record the account identifier, active device public-key fingerprints, recovery
   policy hash and monotonically increasing revocation epoch in the authoritative
   broker ledger. Test a dry-run recovery ceremony before relying on it.
2. **Declare loss:** freeze pending approvals for the account. A recovery request
   commits to domain `frequency-guardian-recovery/v1`, account, old device
   fingerprint, replacement SPKI fingerprint, independent attestation challenge
   and evidence digest, policy hash, current epoch, proposed epoch=current+1,
   fresh transaction nonce, issuance and expiry. Obtain offline recovery-key
   signature plus required independent quorum signatures over canonical bytes.
   An exported candidate or a newly generated phone key alone cannot recover.
3. **Verify replacement:** independent verifiers validate pinned issuer chains,
   challenge freshness, hardware and app/boot/authentication policy, revocation
   status and replacement proof of possession with user authentication. Bind all
   results to the same recovery transaction; prevent substitution of a different
   candidate or account. Diagnostic v0.2 output is insufficient for this step.
4. **Atomic revoke and activate:** compare-and-swap the authoritative epoch from
   the committed old value to old+1, permanently revoke the lost fingerprint,
   invalidate outstanding challenges/approvals/sessions and activate only the
   committed replacement key in one durable transaction. Reject concurrent,
   replayed, expired, stale-epoch or partially signed requests. All subsequent
   authorization must bind the current epoch; replicas must fail closed until
   they have the authoritative new epoch. Never accept old-device signatures
   after revocation even if their certificates remain valid.
5. **Audit and resume:** issue a signed recovery receipt binding transaction,
   old/new fingerprints, policy and epoch. Independently check durable revocation
   propagation before unfreezing approvals. Recovery-key rotation needs the
   existing recovery policy/quorum and a further epoch transition. If the
   pre-provisioned recovery key or required quorum is unavailable, fail closed;
   reinstalling, exporting settings or presenting the lost key's certificates
   cannot bypass recovery. No phone private key is ever migrated or exported.
