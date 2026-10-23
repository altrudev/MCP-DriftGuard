# Current repair evidence

The repaired offline tap-approval artifact and current checks are recorded in
[FINAL_STATUS.md](../../FINAL_STATUS.md). Everything below is historical and
refers to earlier APKs, signing identities and diagnostic-only behavior.

# v0.3 validation — 2026-10-23

`./test-host.sh` passed: fixture encoding, nonce/replay/expiry boundaries,
ECDSA and tamper checks, ten report entries, pending defaults, invalid check
refusal, JSON escaping and independent Python JSON parser roundtrip.

`ANDROID_SDK_ROOT=/opt/android-sdk ./build-sdk-offline.sh` passed using cached
SDK/Kotlin tools. Existing platform deprecation warnings remain. APK v3 signature
verification passed with one signer. Artifact:
`app/build/sdk-offline/FrequencyGuardian-0.3.0-debug.apk`.
SHA-256: `7e1827decb5238d59d26a48d035a8ea926808933db8c22243c8f72a781968c3c`.

APK signer certificate SHA-256:
`22a93e33cfd83c40797240407203c603e54d7cecf1482ea08c55fc33871bd572`,
identical to the existing v0.2 artifact. Existing debug keystore was reused.
Packaged launcher icon resources compared byte-for-byte with v0.2; source
resources and manifest are unchanged. Badging confirms package
`dev.frequency.guardian`, version code 3/name 0.3.0, minSdk 30/targetSdk 35,
original launcher icon, and only USE_BIOMETRIC permission.

`CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test --offline --manifest-path broker/Cargo.toml`
passed all 23 tests. `git diff --check` passed.

No physical-device/emulator testing occurred. Hardware custody, system prompts,
Sharesheet export, actual in-place upgrade and identity continuity require device
acceptance in FREQUENCY-GUARDIAN-V03.md. Recovery remains unimplemented and
attestation requires an external challenge plus independent trust verification.
No private keys were exported, no production approval was enabled, and nothing
was pushed or merged. The direct SDK build was used; Gradle was not rerun because
of the previously documented IPC limitation below.

---

# v0.2 validation — 2026-10-23

`ANDROID_SDK_ROOT=/opt/android-sdk ./build-sdk-offline.sh` passed with cached
Kotlin/SDK tools. APK v3 signature verification passed (one debug signer).
Artifact: `app/build/sdk-offline/FrequencyGuardian-0.2.0-debug.apk`.
SHA-256: `0a70239fc3de0ba6627e9b4d965dfd6b9da85141762edafab78b9dac1cb0c101`.
Version code 2, name 0.2.0, minSdk 30, targetSdk 35. No new permissions.
`./test-host.sh` passed. Existing deprecation warnings remain.

`CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test --offline --manifest-path broker/Cargo.toml`
passed all 23 tests, including pinned-chain cryptography, wrong root pin,
challenge mismatch, signature corruption and software security-level rejection.
Disposable test issuer keys are host-only fixtures and confer no device trust.
An initial debug-symbol Rust build exceeded disk quota; `cargo clean` and the
bounded build configuration above resolved it without changing source behavior.

No device/emulator runtime validation was performed. Actual Android attestation,
OEM hardware levels, candidate replacement, unchanged v1 identity after an upgrade,
metadata warning and Sharesheet flows require physical-device checks. No real
enrollment, push, merge or network/telemetry was enabled. The historical Gradle
limitation below still applies; v0.2 was built using the direct SDK fallback.

---

# Build validation — 2026-10-23

## Produced artifact

`app/build/sdk-offline/FrequencyGuardian-0.1.0-debug.apk` (ignored build output)

SHA-256:
`a3dd2a4938346d03375761e89ebefc9e54a616dcf27f2cd0ee79b68928d4513b`

Built from the checked-in Android source using installed SDK platform/build-tools
35, cached Kotlin compiler + stdlib 2.0.21, Java 17 target, aapt2/javac/d8/zipalign
and apksigner. `build-sdk-offline.sh` exited zero. APK Signature Scheme v3
verification succeeded, one signer. Debug certificate is generated locally in
ignored build output, not checked in; future clean builds will have a different
APK hash/certificate. This is an installable development artifact, not a release
or a production enrollment client.

`aapt dump badging` confirmed:

- package `dev.frequency.guardian`, versionCode 1, versionName 0.1.0
- minSdk 30, targetSdk/compileSdk 35
- launcher `dev.frequency.guardian.MainActivity`, adaptive vector app icon with round/themed variants
- debuggable development build

`aapt dump permissions` confirmed only `android.permission.USE_BIOMETRIC`.
No Internet or storage permissions. Manifest source disables backup and exposes
only the launcher; settings provider is nonexported with per-URI read grants.

## Gradle attempt and exact limitation

Requested `gradle --offline --no-daemon -p android/FrequencyGuardian assembleDebug`.
Installed Gradle is 9.8.0; AGP is pinned at cached 8.7.3 and Kotlin at cached 2.0.21.
There is no cached Gradle 8.x distribution. First attempt failed creating a
native-library lock in the read-only home Gradle directory. Copied cached
artifacts to `/tmp/fg-gradle-home` and retried with `GRADLE_USER_HOME` there.
The retry failed before project configuration because this sandbox prohibits
socket creation: `Could not determine a usable wildcard IP for this machine`,
caused by `java.net.SocketException: Operation not permitted (Socket creation
failed)` in Gradle's file-lock contention service. IPv4 preference did not fix it.
**Gradle assembleDebug did not pass.** No network downloads or permission changes
were used. Use Gradle 8.9 and JDK 17 in an environment allowing normal local Gradle
IPC to validate the AGP build; the direct SDK build is the verified fallback here.

## Automated checks

`./test-host.sh` passed using cached Kotlin 2.0.21:

- exact diagnostic v1 domain, version, nonce, big-endian timestamps and action hash
- fresh independent nonces and defensive copies of mutable fields
- refusal before issuance, at expiry and beyond expiry
- one-use fixture consumption, including refusal of a second attempt
- P-256/SHA-256 DER sign/verify with a disposable host test key
- rejection after version/action-digest tampering and substitution of production domain

The disposable host test key is unrelated to device Keystore and establishes no
hardware-security claim. `git diff --check` and staged equivalent passed.

## Unverified runtime behavior / release blockers

No physical device or emulator was connected or launched. No on-device key was
generated here. StrongBox availability, TEE fallback, actual KeyInfo level,
BiometricPrompt/device-credential CryptoObject behavior, OEM lifecycle behavior,
Sharesheet/document-provider flows and visual appearance require the physical
device acceptance checks in README.md. Local KeyInfo is not remotely verified
attestation. No production trust enrollment, attestation verifier, recovery
quorum implementation or broker adapter exists. They remain prerequisites for
production acceptance; the app signs diagnostics only.

No broker behavior was changed, no pushes/merges/deployments were performed, and
no VPS system services were accessed or modified.
