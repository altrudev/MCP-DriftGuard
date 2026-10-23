# Native offline approval workflow

The repaired Android client supports **Approve / Deny**, without a password or
biometric dialog. Its operational key is the **attested candidate itself**, not
the separate legacy diagnostic key. A locked phone cannot use newly generated
keys (`setUnlockedDeviceRequired(true)`); no per-use authentication is requested.
Anyone controlling an unlocked, enrolled phone can tap a decision.

This is an offline file workflow, not push delivery or production broker execution.
The Python reference authority verifies enrollment independently and checks signed
receipts. It never executes an approved action. The previous diagnostic acceptance
bridge remains diagnostic-only; its pending verdict cannot issue an enrollment.
A physical-device acceptance run and a production signing/deployment ceremony are
still required. Host fixtures are not hardware evidence.

## Independent verifier setup

Use an operator-controlled verifier machine, separate from the enrolled phone.
Python `cryptography` 46.x, OpenSSL 3, and Rust broker binaries are required. Build
with `CARGO_TARGET_DIR=/dev/shm/guardian-build cargo build --offline --manifest-path
broker/Cargo.toml --bins`. Use `/dev/shm` for temporary build files; **persistent
production authority state must survive restarts** on the verifier's private disk.

Obtain the trusted Android attestation root DER SHA-256, the intended APK signing
certificate SHA-256 and the minimum allowed OS patch independently. Never learn
these policy values from the phone's export. Create a policy JSON with exactly:

```json
{"root_pin_sha256":"<64 lowercase hex>","apk_signer_sha256":"<64 lowercase hex>","minimum_os_patch":202610}
```

Initialize a NEW private authority directory; init refuses to overwrite:

```sh
python3 scripts/guardian_offline.py /secure/guardian-authority init --policy policy.json
python3 scripts/guardian_offline.py /secure/guardian-authority public-key
```

The second command prints P-256 public SPKI base64 and SHA-256. On the phone tap
**Pin independent verifier**, enter the key and its fingerprint, and authenticate
the fingerprint via a separate trusted channel. Trust is delegated to that pinned
verifier; pinning a key obtained from an attacker defeats this ceremony. There is
no in-app authority replacement or trust import through settings.

Keep the authority private key, policy, clock watermark, challenge records and
request/revocation ledger under independent custody. Protect them from rollback
and loss. The tool locks the ledger, uses private files and durable replacement,
and blocks uncertain commits. There is no automatic ledger repair or reset.

## Enrollment

1. Run `guardian-challenge /secure/guardian-authority/challenges` from the built
   broker binaries. It issues a cryptographically random, single-use challenge
   with a five-minute lifetime.
2. On the phone, **Generate attestation candidate**, paste that challenge, then
   **Save attestation JSON** and **Save candidate enrollment identity**. The
   latter is an untrusted locator, not evidence. The old diagnostic-key binding
   export is unnecessary for this workflow because receipts use the attested key.
3. Transfer the attestation through an authenticated file channel. On the verifier:

```sh
python3 scripts/guardian_offline.py /secure/guardian-authority enroll \
  --attestation phone-attestation.json --challenge CHALLENGE_HEX \
  --binaries /dev/shm/guardian-build/debug > enrollment.fg
```

Enrollment requires pinned-chain signature/date/order verification, hardware P-256,
fresh issued challenge, exact package `dev.frequency.guardian`, independently
configured APK signer, hardware noAuthRequired, signing/SHA-256 authorizations,
locked verified boot, and the patch floor. It fetches certificate status from the
fixed authenticated HTTPS Google attestation status endpoint. Missing network,
malformed/stale status (HTTP Date/Age bounded to five minutes), any listed chain certificate, unsafe key or failed check refuses.
The challenge is durably consumed before grant signing. Enrollment expires in 24h.
The authority ledger stores the **verified leaf key**, not a self-asserted app key.
4. Transfer `enrollment.fg` to the phone and **Import signed enrollment / request /
   revocation**. Its pinned authority signature, candidate key and installed APK
   signer must match. Exporting a candidate or passing local diagnostics cannot
   enroll a phone. An existing enrollment cannot be replaced silently.

## Request and decision

Use the verified candidate SHA-256 from the verifier's device ledger as `DEVICE`:

```sh
python3 scripts/guardian_offline.py /secure/guardian-authority request \
  --device DEVICE --action 'Exact reviewed operation and scope' > request.fg
```

The reference issuer accepts printable ASCII action text; the Android decoder also
accepts bounded visible Unicode. Authority requests expire in at most 120 seconds,
are bound to one enrollment/device/APK signer, and have random 32-byte nonces.
Certificate revocation is checked again before request issuance.

Import the request on the phone, review its complete action, nonce, expiry and
SHA-256, and tap **Approve** or **Deny**. No additional system authentication is
invoked. Save the resulting decision JSON through Android's document picker.
Backgrounding dismisses an unresolved review; import again to review. Dismissal
creates no decision. Deny creates a signed, final denial. The app consumes the
nonce durably **before** signing, so a signing/export/storage failure may burn it.
Request a fresh nonce instead of retrying an uncertain operation.

```sh
python3 scripts/guardian_offline.py /secure/guardian-authority verify \
  --receipt frequency-guardian-decision.json
```

Verification matches the exact issued bytes, enrolled key, decision domain and
signature, rejects expired/replayed/revoked requests, rechecks certificate status,
and durably consumes the receipt before reporting its decision. Output always
includes `executed: false`. An execution system must honor only verified **approve**
for exactly the recorded action and establish its own transaction boundary. Merely
possessing the app's JSON or seeing an approve label cannot authorize execution.

## Revocation and safe replacement

Revoke at the **authority first**; outstanding receipts then fail verification:

```sh
python3 scripts/guardian_offline.py /secure/guardian-authority revoke \
  --device DEVICE > revoke.fg
```

Import `revoke.fg` on the phone, or tap **Revoke this enrollment locally**. Local
revocation permanently tombstones that candidate key and removes its grant. It
cannot notify an offline authority; both sides must be revoked. Old grants cannot
reactivate a locally tombstoned key. Revocation on the verifier blocks new requests
and previously issued receipts even when the phone is lost or unreachable.

For a replacement, revoke the old key, generate a **new** candidate with a fresh
verifier challenge, then repeat all independent enrollment checks. No identity,
authority pin or approval rights are copied automatically. A fresh or reinstalled
phone must independently authenticate the verifier pin again. Existing revoked
keys cannot enroll again at the authority.

Loss of the authority key/ledger, quorum recovery, cross-verifier synchronization,
and automatic authority rotation are **not implemented**. Existing Rust quorum
recovery validates evidence only; it does not activate app enrollment. These cases
remain blocked and require a separately designed, independently authorized ceremony.

## Protocol and limits

Transport is base64(signed payload) + `.` + base64(ECDSA P-256 SHA-256 DER signature).
Payload uses Java DataOutputStream encoding: writeUTF
`frequency-guardian/offline-trust/v1`, one-byte kind (1 enrollment, 2 request,
3 revoke), four writeUTF lowercase 64-hex strings (device SHA-256, APK signer
SHA-256, enrollment ID, nonce), two signed big-endian 64-bit Unix seconds
(issued, expires), then writeUTF action. The parser re-encodes and requires exact
canonical bytes. Limits: 16,000 transport characters, 4,096 action characters,
24h grants, 120s requests/revocations. No control/format characters in displayed
actions. The authority uses the printable ASCII subset of writeUTF.

Decision bytes are ASCII `frequency-guardian/offline-decision/v1` + NUL + one-byte
boolean (1 approve, 0 deny) + the exact request payload. ECDSA is made by the
attested candidate. Receipt JSON is strictly validated by the independent verifier.
Cross-language tests compare real Python/Kotlin payloads and signatures.

The Android app retains up to 8,192 consumed nonces and 256 revoked candidate
fingerprints; the reference verifier retains up to 8,192 requests. Full ledgers
block operations, rather than evicting replay protection. No pruning is provided.
Wall-clock rollback below a persisted watermark blocks signing. Pending reviews
also have a monotonic two-minute bound. Protect authority time and disk state;
local storage/clock rollback by a privileged attacker is not solved by app code.
Offline revocation propagation is bounded by request/grant lifetime on the phone;
final verifier acceptance always consults its current local revocation ledger and
live certificate status. Lack of access to the status service fails closed.

## Validation boundaries

Run `android/FrequencyGuardian/test-host.sh` and, after building Rust binaries,
`FG_RUST_BINARIES=/dev/shm/guardian-build/debug python3 -m unittest discover -s scripts
-p test_guardian_offline.py -v`. Set `TMPDIR=/dev/shm` and
`PYTHONDONTWRITEBYTECODE=1`. Android tests use the cached Kotlin compiler, not an
emulator. Integration certificates are explicitly disposable software fixtures;
tests mock the revocation endpoint and do not establish real Google/OEM custody,
physical taps, OEM lock behavior or release upgrade continuity.
