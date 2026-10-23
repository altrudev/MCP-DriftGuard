# Frequency Guardian v0.5.0 — online approval prototype

See [online setup and threat model](../../docs/GUARDIAN-ONLINE.md) and
[validated artifact and outstanding gates](../../ONLINE_STATUS.md).
The app now has Internet permission for explicit HTTPS pairing and foreground
polling. Offline import/export remains available. No FCM or telemetry is added.

Native Kotlin Android app, API 30 minimum / target 35, Kotlin 2.0.21, Java 17.
Approve and Deny use explicit taps, with **no additional biometric/password dialog**.
The app has no biometric permission and disables backups and screenshots.
Keys are nonexportable Android Keystore P-256, prefer StrongBox, permit TEE fallback,
and refuse software signing. Newly generated keys require an unlocked device.

The operational workflow is now separate from local diagnostics. It uses the
**independently attested candidate key itself** for decisions. A separately pinned
verifier must issue signed, expiring enrollment and fresh signed action requests.
The installed APK signer, candidate key and enrollment must match. The independent
reference verifier checks attestation, application signing, locked verified boot,
patch policy, live certificate status, issued challenges, receipt signatures,
revocation and replay. Full workflow and exact protocol:
[GUARDIAN-OFFLINE.md](../../docs/GUARDIAN-OFFLINE.md).

Import signed enrollment/request/revocation files through Android's document picker.
Review the full action, nonce, expiry and digest; Approve or Deny creates a signed
receipt that can be saved through the picker. The request nonce is persisted as
consumed before signing. Backgrounding cancels unresolved review. Diagnostics,
attestation exports and settings imports cannot establish trust.

Local revocation permanently blocks that candidate; verifier revocation blocks even
outstanding receipts. Safe replacement requires a fresh candidate and complete
independent enrollment. There is no automatic authority replacement, private-key
migration, trust reset or quorum activation. The existing quorum verifier validates
authorization evidence only. Lost authority/ledger recovery remains blocked.

## Build and tests

The installed SDK is `/opt/android-sdk`; cached Kotlin/SDK tools are used without
downloads. Temporary compiler data, generated classes, test keys, logs and build
intermediates default to `/dev/shm`. No `/tmp` usage is required.

```sh
ANDROID_SDK_ROOT=/opt/android-sdk ./build-sdk-offline.sh
./test-host.sh
```

APK: `app/build/outputs/apk/debug/FrequencyGuardian-0.5.0-debug.apk`.
This is a **debug APK**, signed with the prior debug keystore to preserve this test app's update identity. It is not a production release identity. Keep a stable separately
managed signing key for release/update continuity. Do not confuse the APK signer
with either on-phone key. Host tests include independent Python ↔ Kotlin encoding
and ECDSA verification. `cryptography` 46.x is needed for the Python tests/verifier.

For standard Gradle builds use Gradle 8.9, JDK 17, SDK 35, AGP 8.7.3 and Kotlin
2.0.21. In this sandbox the direct SDK build avoids restricted Gradle IPC; set
`GRADLE_USER_HOME`, `java.io.tmpdir` and project build directories to `/dev/shm` if
using Gradle here. Only the direct SDK build was validated for this repair.

## Install and acceptance

Transfer the APK through an authenticated private channel; compare SHA-256 through
a separate trusted channel. Open it on a supported physical phone and allow the
chosen installer temporarily if device policy permits. No hosting or publication
was performed. A different installed APK signer requires a separate test device or
explicit uninstall; uninstall destroys app identity/trust, so do not treat it as
recovery. Do not uninstall an enrolled app as an upgrade procedure.

Actual hardware custody, no-extra-prompt taps, document providers, lock/background
behavior, app update continuity and real OEM/Google attestation require physical
acceptance. In this sandbox ADB cannot start its listening socket; no device test
was possible. The root [FINAL_STATUS.md](../../FINAL_STATUS.md) records current
commands, results, artifact hashes and genuine outstanding acceptance gates.
Historical build results in BUILD-VALIDATION.md describe earlier artifacts only.

The app does not execute actions or connect to a production broker. HTTPS approval transport is available only after explicit pairing. A downstream
executor must verify a one-use **approve** receipt for exactly the issued action
and establish its own transaction boundary. A denial or unsigned JSON cannot
execute anything. Offline phone revocation cannot synchronize itself; revoke on
the authority first. Lack of live certificate status blocks verifier acceptance.

Root [LICENSE](../../LICENSE), [NOTICE](../../NOTICE) and
[COMMERCIAL.md](../../COMMERCIAL.md) apply. No proprietary service source or
branding rights are conveyed. No keys or authority credentials are included in
this repository's source.
