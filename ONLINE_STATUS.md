# Frequency Guardian v0.5.0 — online prototype status

Implemented locally; **not published, not deployed, not production ready**.
No physical phone was available for acceptance. There are no production
credentials, endpoint domains or real-phone attestation claims in this delivery.

## Delivered behavior

- Explicit HTTPS-origin and private-token pairing; authority pinning remains a
  separate, independently authenticated ceremony. Explicit transport re-pairing
  cannot replace the authority or enrollment, and blocks while delivery is pending.
- Foreground polling every 15 seconds, readable signed Who / What / Target / UTC
  expiry, explicit Approve / Deny without per-action biometrics or passwords.
- Original attested P-256 candidate signs decisions, with existing device,
  enrollment and installed APK-signer binding. No diagnostic key substitution.
- Saved decision outbox, signed submission, durable server receipt, matched
  confirmation and status lookup after lost replies. Last confirmation persists.
- TLS-only four-endpoint API, random device-scoped transport tokens issued only
  after independent enrollment, bounded JSON and strict schema, coarse rate limits,
  replay rejection, revocation, clock/ledger failure handling and no execution.
- No FCM, background push, telemetry, model calls, automatic endpoint trust,
  authority replacement, automatic recovery or automatic execution.

## Validation

| Check | Result |
| --- | --- |
| Python offline + online unittest suite | 10 tests passed; no skips with verifier binaries configured |
| Independent enrollment | Fresh challenge, actual Rust certificate/policy verifier, synthetic signed attestation fixtures |
| Simulated client end to end | Enrollment → token pairing → signed grant → pending request → candidate-signed approve/deny → receipt → durable status |
| HTTPS cryptography and HTTP dispatch | Passed with real OpenSSL TLS records via MemoryBIO and the actual HTTP handler |
| Network listening | Sandbox prohibits socket creation (`PermissionError`); TCP listener and real network path untested |
| Negative tests | Bad token, tampering, replay, expiry, revoked device, status outage, unknown/unaccepted nonce, extra/duplicate JSON fields, oversize body, unsupported route, rate limit, untrusted TLS issuer and hostname mismatch |
| Kotlin host tests | Passed existing fixture/diagnostic/trust tests, 19 trust negative cases, and 13 online endpoint/token cases |
| Python ↔ Kotlin interoperability | Exact authority request encoding and both decision signatures passed |
| APK build | Direct installed-SDK build passed; existing Android deprecation warnings remain |
| APK signature | Verified v3 signature; prior debug keystore certificate matches |
| Manifest | dev.frequency.guardian; versionCode 5; versionName 0.5.0; min API 30; target API 35; INTERNET; cleartext disabled |
| Whitespace | `git diff --check` passed |

Test certificate-status responses are mocked, and certificate chains/devices are
synthetic. No live Google certificate-status response or real Android hardware
acceptance is implied. The complete TLS test uses network sockets on permissive
hosts; here it automatically used the MemoryBIO fallback. This validates TLS and
HTTP application behavior but does not establish network reachability or server
socket lifecycle behavior. No broader unrelated Go/Rust regression suite was
rerun; the changed authority and Android code were tested directly.

Reproduction from repository root:

```sh
TMPDIR=/dev/shm FG_RUST_BINARIES=/dev/shm/guardian-repair/rust-target/debug \
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_guardian_o*.py' -v
android/FrequencyGuardian/test-host.sh
ANDROID_SDK_ROOT=/opt/android-sdk \
  FG_SIGNING_KEYSTORE="$PWD/android/FrequencyGuardian/app/build/sdk-offline/debug.keystore" \
  android/FrequencyGuardian/build-sdk-offline.sh
git diff --check
```

The binary directory above was already built in this workspace. For a fresh
machine, build with `CARGO_TARGET_DIR=/dev/shm/guardian-build cargo build --offline
--manifest-path broker/Cargo.toml --bins`, then set `FG_RUST_BINARIES` to
`/dev/shm/guardian-build/debug`. Missing binaries skip independent enrollment tests;
that is not equivalent to the full passing run reported here.

Saved human-readable evidence: [Python results](evidence/online-v050/python-tests.log),
[Kotlin results](evidence/online-v050/kotlin-tests.log),
[APK build results](evidence/online-v050/apk-build.log).
Build/compiler scratch data and logs used `/dev/shm`; no `/tmp` build data was used.
Persistent authority deployment state must instead live on private durable storage.

## Exact APK and signer

APK: [FrequencyGuardian-0.5.0-debug.apk](android/FrequencyGuardian/app/build/outputs/apk/debug/FrequencyGuardian-0.5.0-debug.apk)

Absolute path:
`/home/ubuntu/guardian-v030-repair/android/FrequencyGuardian/app/build/outputs/apk/debug/FrequencyGuardian-0.5.0-debug.apk`

APK SHA-256: `f17f3bb217fc0c5faea449ea651e365a0eabbd6c405d14272ee6dcb8dde58f2b`

APK signer certificate SHA-256:
`22a93e33cfd83c40797240407203c603e54d7cecf1482ea08c55fc33871bd572`

Signed with the requested prior keystore:
`/home/ubuntu/guardian-v030-repair/android/FrequencyGuardian/app/build/sdk-offline/debug.keystore`.
Its certificate fingerprint was independently compared with `keytool -list` and
matches the resulting APK's `apksigner verify --print-certs` output. The build now
refuses a missing prior keystore instead of generating a replacement update key.
This is the existing debug identity, not a production release signing ceremony.
The device approval key remains a separate, nonexportable Android Keystore key.
APK build outputs are ignored build artifacts; preserve/copy the linked APK if
moving this source checkout elsewhere.

## Incomplete acceptance gates

1. Install/update on an actual supported phone with the existing signer; prove
   candidate SPKI, authority pin, replay ledger and enrollment survive the update.
   Do not uninstall or clear storage to make an upgrade work.
2. Verify real OEM/Google attestation roots, live certificate status, APK signer,
   locked verified boot, patch policy and hardware custody against operator policy.
3. Exercise real foreground polling, TLS connectivity and trust rejection,
   request readability, obscured taps, screen lock/background cancellation,
   no-extra-prompt Approve/Deny, process death, dropped responses, persisted outbox,
   local/server revocation and resumed status checks on physical Android devices.
4. Run actual TCP/TLS integration outside this socket-restricted sandbox, including
   slow handshakes/body reads, denied cleartext connections and deployment firewall.
5. Independently review public-service hardening before any Internet exposure:
   connection/IP limits, TLS resource exhaustion, privacy-preserving monitoring,
   durable backups/rollback protection, ledger capacity and recovery procedures.
   Rate limits are process-local and reset on restart; the server is intentionally
   single-request and can be denied availability. It is for controlled prototyping.
6. Complete a production signing/custody and deployment ceremony. No release key,
   valid deployment certificate, production domain, execution adapter, renewal
   ceremony or automatic recovery is supplied. Enrollment currently expires in
   24h and replacement requires fresh independent verification after revocation.

## Deployment steps

Follow [the complete setup and threat model](docs/GUARDIAN-ONLINE.md): independently
source policy → initialize durable private authority → authenticate/pin authority
on phone → issue challenge and verify attested candidate → provision device token
→ configure operator-owned Android-trusted TLS certificate/hostname → start private
TLS listener with restricted ingress → explicitly pair origin/token → fetch signed
enrollment if not already imported → issue scoped Who/What/Target test request →
tap Approve/Deny → verify durable confirmation and ledger → test lost-response and
revocation cases. Use separate authenticated channels for authority fingerprint,
endpoint confirmation and private token transfer. No real endpoint is assumed.

A confirmed approval is evidence only. Any future executor must implement its own
reviewed one-use transaction boundary for the exact verified action. This prototype
never automatically executes either approvals or denials.
