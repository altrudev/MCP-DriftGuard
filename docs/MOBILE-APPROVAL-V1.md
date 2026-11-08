# Frequency Guardian mobile approval contract v1 (design, acceptance DISABLED)

Historical diagnostic/proposed contract. The current native tap approval workflow,
independent enrollment, revocation and safe replacement are specified in
[GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Its tap policy supersedes earlier
per-operation biometric/password requirements. Existing diagnostic bridges and
quorum evidence validators retain their diagnostic-only verdicts.

Status: experimental v0.1.0. This specification is an interoperability boundary for a
future Rust broker adapter, **not** authorization to accept mobile signatures.
The existing broker uses pinned Ed25519 keys and remains unchanged. Never feed a
mobile ES256 signature into its current approval path or translate one into an
Ed25519 approval. There is no live enrollment, attestation verifier, recovery
implementation, paired broker state, or production approval importer in this app.

## Implemented diagnostic protocol

The only request source is `LocalFixture.create()` inside the application. No
intent, URI, clipboard, QR, imported file, deep link, network, or caller-provided
request can enter signing. Launcher is exported solely for launching the UI;
unrecognized actions are refused. Pairing payloads are public **diagnostic
candidates**, explicitly `attestation_verified:false`, `production_eligible:false`.
No trust is acquired by copying/sharing one.

Signing bytes, in exact concatenation order:

| Field | Encoding |
| --- | --- |
| Domain | ASCII `frequency-guardian/diagnostic-approval/v1` followed by one NUL byte |
| Version | one byte `01` |
| Nonce | 32 CSPRNG bytes |
| Issued | unsigned nonnegative Unix seconds, 8-byte big-endian |
| Expiry | same, exactly issued + 120 |
| Action digest | 32 SHA-256 bytes over exact UTF-8 action below |

The exact action has no newline:
`Diagnostic only: verify local signing; authorize no operation.`

All fields are created in process; there is no JSON-to-sign conversion. User sees
action, nonce, timestamps, digest, source, and diagnostic limitation before the
system authentication prompt. The app checks time before authentication and again
at the successful callback, requires the same pending fixture and CryptoObject,
and clears pending state on cancellation/error/backgrounding. A monotonic 120-second
lifetime additionally bounds local fixtures; a fixture is consumed before signing
and cannot be retried after a signing failure. ECDSA P-256 with
SHA-256 signs the entire byte sequence. Android returns ASN.1 DER `(r,s)`; the
receipt explicitly calls this `ES256-DER`, **not** JOSE's 64-byte ES256 signature.
Receipt includes exact signed bytes in padded RFC 4648 standard base64, DER
signature and SHA-256 fingerprint of X.509 SubjectPublicKeyInfo DER. The app
verifies its signature locally before presenting a receipt. A diagnostic signature
has no authority, even if replayed or copied. Device wall clock is not a trusted
production clock or rollback defense.

## Reserved production wire contract (unimplemented)

A future reviewed adapter MUST use a different domain:
ASCII `frequency-guardian/approval/v1` + NUL, then fixed-width fields below in this
order. This is a new authorization type, never equivalent to current broker policy.

| Field | Bytes / interpretation |
| --- | --- |
| Version | 1, `01` |
| Broker identity | 32, SHA-256 of pinned broker SPKI DER |
| Pairing ID | 32, broker-generated random ID bound to verified enrollment |
| Device identity | 32, SHA-256 of device SPKI DER |
| Trust epoch | 8, big-endian u64, current enrollment/revocation epoch |
| Request nonce | 32, broker CSPRNG, unique within pairing and epoch |
| Issued seconds | 8, big-endian u64, <= signed 64-bit maximum |
| Expiry seconds | 8, same, issued < expiry <= issued + 120 |
| Action digest | 32, SHA-256 of exact action document bytes |
| Policy digest | 32, SHA-256 of exact pinned policy bytes |

No variable strings, implicit defaults, Unicode normalization, field reordering,
trailing bytes, floats or JSON canonicalization occur in the signed body. The
transport envelope must have exactly `schema`, `algorithm`, `body_b64`,
`signature_der_b64`, `action_b64` with schema `frequency-guardian-approval/v1`
and algorithm `ES256-DER`. A strict parser rejects duplicate/unknown keys,
noncanonical base64, wrong sizes, trailing content, oversized values (envelope
max 32 KiB, action max 16 KiB), invalid UTF-8 action documents and unsupported
schemas. Envelope JSON itself is not signed; signed body commits to exact action
and policy bytes. Parser/transport/action grammar need test vectors and an
independent review before implementation is eligible for acceptance.

The broker must authenticate its challenge over a distinct domain,
`frequency-guardian/broker-challenge/v1` + NUL + the exact production body, with
its pinned enrolled challenge-signing public key. Unsigned requests must never
reach approval UI. Before signing, a paired app must verify that signature,
identities, epoch, clock bounds, action hash, policy hash, allowlisted action
schema, requested authority and a trustworthy complete human-readable rendering.
No opaque digest-only operational consent. Unknown actions and unpaired issuers
must fail closed. Request details must bind every authority-bearing field,
including target/environment, scope, amounts/limits where relevant and effects.

The future Rust adapter must independently verify authenticated enrollment,
attestation, device/pairing/broker bindings, algorithm, strict DER and scalar
range, signature, action and policy digests, current revocation/epoch, trusted
time and durable global one-use nonce consumption **before execution**. Signature
malleability must not create a second authorization: replay keys are pairing +
epoch + nonce, never signature bytes. Serialize consumption and revocation to
avoid acceptance races. A receipt is not an execution result. Keep adapter behind
a default-off gate until attestation, recovery and all negative acceptance tests
are reviewed and pass; this change adds no broker code or gate enabling it.

## Device key custody and attestation gate

Android Keystore creates nonexportable `secp256r1` signing keys. Every signature
requires a `BiometricPrompt` CryptoObject with strong biometric or device
credential, auth timeout zero. Secure lock screen is required. StrongBox is tried
first; specifically `StrongBoxUnavailableException` allows a standard Keystore
retry. Other generation failures remain failures. Local `KeyInfo` reports the
actual security level; software/unknown levels cannot sign. API 30 reports only
secure-hardware membership, not a definitive TEE/StrongBox level. Failure and
fallback history are visible. The app never exports a private key, certificate
backup, or key material in settings; no private key migration is supported.

Local `KeyInfo` is not remote attestation. Production provisioning must generate a
fresh key with a broker-supplied unique attestation challenge and independently
validate the full chain against explicitly maintained acceptable roots, current
revocation data, challenge, app signing certificate/package identity, verified
boot/locked state, OS/security patch policy, key purpose/curve/digest,
authentication enforcement, origin and TEE/StrongBox security levels. Pin and
review root transitions, deny revoked/unverifiable/stale chains. Offline
verification requires pre-provisioned current trust material and a freshness
policy; lack of Internet must never mean skipping revocation checks. v0.1 does
not request or assert this evidence and its diagnostic key must not be promoted
to production. Enrollment requires independent operator verification and quorum.

## Lost-phone recovery (design required before production)

Before enrolling any operational phone, provision an **independent offline
recovery identity**, e.g. an offline Ed25519 public key whose private key remains
on independently secured offline media/token. Record its public fingerprint,
algorithm, organization, recovery policy digest and quorum memberships through an
out-of-band verified ceremony. Recovery authority cannot be created by the lost
phone, imported settings, a replacement phone, possession of a pairing payload,
or a single broker operator. Suggested initial policy: 2 of 3 independent
custodians, including the pre-provisioned offline recovery identity; require at
least one other independently provisioned custodian. Distinct people/keys and
recovery availability must be verified in a rehearsal before activation.

A recovery statement under a separate `frequency-guardian/recovery/v1` + NUL
domain must bind organization, broker, old pairing/device fingerprint, new device
fingerprint and verified enrollment/attestation digest, prior/new monotonic trust
epoch, recovery policy digest, nonce, issued and expiry times. Exact encoding and
quorum envelope are reserved for a separately reviewed recovery specification;
there is deliberately no recover button that pretends to implement this design.

Quorum validates new attestation and signs the **same** recovery statement.
Broker durably and atomically revokes old device/pairing, invalidates all old
outstanding challenges, advances the trust epoch and activates new enrollment.
Deny the old device even if it later reappears. Persist tamper-evident recovery
evidence; replicas must acknowledge revocation before accepting new approvals.
Offline or partitioned consumers that cannot establish current epoch must deny
requests. Recovery cannot be rolled back by restoring a backup. If quorum or
pre-provisioned identity is unavailable, fail closed and use an independently
audited organization re-bootstrap process; never silently trust a new phone.
**No private key is copied to a replacement device.** Deleting the app, clearing
storage, lock-screen changes or biometric enrollment changes may invalidate keys;
handle them as identity loss, never automatic production re-enrollment.

## Data, permission and commercial boundary

Only `USE_BIOMETRIC` is requested. No network, contacts, camera, location, storage
permission, telemetry or service. Backup is disabled. App switcher/screenshots
are protected with FLAG_SECURE. Public pairing data can be intentionally shared
or copied; the OS/selected receiving apps control that public data afterward.
Settings are versioned appearance only, read with a 4096-byte bound and a strict
export grammar, validated and confirmed before applying. Import cannot modify
identity, trust, pairing, recovery or approval state. A nonexported read-only
provider grants one shared cache file to the chosen recipient; no directory or
key access. Diagnostic signatures may be intentionally shared as text.

This source is original repository code under the root LICENSE/NOTICE. Public
protocols, diagnostic signing and interoperability documentation stay separable
from commercial organization workflows. No proprietary Frequency, DDC, DSR or
DDCal implementation, secrets, hosted-service rights, trademarks or third-party
IP are included or licensed by the app name. Managed fleet enrollment, quorum
operations and attestation services remain separate product/integration work;
see ../COMMERCIAL.md. No dependency on those services for local diagnostics.

## Glossary

- **SPKI**: X.509 SubjectPublicKeyInfo DER, the public-key fingerprint input.
- **Pairing**: authenticated binding of a device to a specific broker and policy;
  sharing public data alone is not pairing.
- **Nonce**: unpredictable one-use request identifier, durably consumed by broker.
- **Action digest**: hash binding the signature to exact reviewed action bytes.
- **StrongBox / TEE**: isolated Android key execution environments; neither is
  established to a remote verifier by local status text.
- **Attestation**: independently verified hardware/boot/app/key evidence.
- **Trust epoch**: monotonically increasing enrollment/revocation generation.
- **Quorum**: policy-required set of distinct independently trusted signers.
- **Recovery identity**: independent offline authority provisioned before loss.
