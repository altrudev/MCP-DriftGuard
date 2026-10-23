# Frequency Guardian 0.2.0

Actual native Kotlin Android app. Android 11/API 30 minimum, target/compile API 35,
AGP 8.7.3, Kotlin Gradle plugin 2.0.21, Java 17 bytecode. Native platform widgets
and BiometricPrompt; no third-party runtime UI dependencies. System/light/dark
appearance, original shield/wave vector icon, about/security and glossary included.

**Diagnostic only.** No production approvals, broker acceptance, live pairing,
production attestation acceptance or implemented recovery. Read the
[mobile v1 contract](../../docs/MOBILE-APPROVAL-V1.md) before any future integration.
The UI creates a short-lived local fixture, displays it, obtains per-operation
system authentication, signs with Android Keystore and verifies locally. It does
not accept arbitrary requests. Hardware generation/security behavior requires a
real supported Android device; an emulator is not evidence of hardware custody.

## Build

Use Gradle 8.9 (AGP 8.7's corresponding supported generation), JDK 17, SDK 35 and
build-tools 35.0.0. No wrapper JAR/distribution is bundled. With those dependencies
already cached:

```sh
cd android/FrequencyGuardian
# local.properties is ignored; use your installed SDK path
printf 'sdk.dir=/opt/android-sdk\n' > local.properties
gradle --offline --no-daemon assembleDebug
```

Standard result: `app/build/outputs/apk/debug/app-debug.apk`. Gradle's debug APK
certificate is for installation only; it is unrelated to the nonexportable
on-device approval key. Do not distribute debug builds as production enrollment
clients. A release requires a separately managed APK signing identity, release
review and tested upgrade continuity; no production APK key is checked in.

For this socket-restricted workspace there is also a direct SDK fallback:

```sh
ANDROID_SDK_ROOT=/opt/android-sdk ./build-sdk-offline.sh
```

Override `FG_BUILD_TOOLS` and `FG_MAVEN_CACHE` for other installed paths. It uses aapt2,
javac, cached Kotlin 2.0.21 compiler, d8, zipalign and apksigner, and creates a disposable debug
APK signing keystore under ignored build output. It never creates/exports a phone
approval private key. Result: `app/build/sdk-offline/FrequencyGuardian-0.2.0-debug.apk`.
This fallback uses the same cached Kotlin 2.0.21 compiler/runtime as the Gradle project. See BUILD-VALIDATION.md for actual build outcomes and limitations.

Host-side security checks (same cached Kotlin compiler, no device required):

```sh
./test-host.sh
```

These check exact fixture bytes, independent nonces, immutable inputs, clock
bounds, one-use consumption, signature verification, tampering and domain
separation. They do not establish Android hardware or prompt behavior.

## Install without USB

1. Deliver the debug APK over an authenticated HTTPS download location you control
   or a trusted file-transfer channel. Hosting/publication is not performed here.
   Compare SHA-256 against a separately authenticated value before installation.
2. On the phone open that download in its browser, tap the APK, and temporarily
   permit **Install unknown apps** for that browser if Android asks. Install, then
   disable that browser's install permission again. Device/enterprise policy may
   prohibit sideloading. Open Frequency Guardian and set a secure screen lock if
   requested. Use a supported physical phone for the hardware-key diagnostic.
3. Updates require the same package and APK signing certificate; keep the debug
   certificate locally for development updates. Uninstall/clear storage loses the
   app identity and settings. Never use uninstall as production recovery.

Wireless debugging on Android 11+ (trusted local Wi-Fi, no USB assumed): enable
Developer options, then Wireless debugging → Pair device with pairing code.
Use the actual pairing host/port and code shown on the phone:

```sh
adb pair PHONE_IP:PAIRING_PORT
adb connect PHONE_IP:DEBUGGING_PORT
adb devices
adb -s PHONE_IP:DEBUGGING_PORT install -r app/build/sdk-offline/FrequencyGuardian-0.2.0-debug.apk
```

Pairing and debugging ports differ and may change. Confirm the listed device is
yours. Turn wireless debugging off and forget the workstation when finished.
No ADB, emulator or device operation was attempted by the project build.

## Device acceptance checklist

- On a StrongBox phone: confirm reported StrongBox level and no fallback. On a
  TEE-only device: confirm fallback message and TEE level. Software-only/unknown
  keys must fail signing. API 30 can only report secure-hardware membership.
- Without device PIN/password, key setup must refuse. With enrolled strong
  biometrics or device credential, confirm each signature requires a system
  prompt. Cancellation, failed authentication, backgrounding and expiry must
  produce no receipt. Verify device-credential behavior on actual OEM builds.
- Review nonce, digest, exact action and expiry; local diagnostic receipt must
  verify with the shared public key. Never regard that receipt as approval.
- Expired/replayed external requests, URI/deep-link and send intents have no
  approval importer or signing path. Sharing pairing data must not mark paired.
- Export via Sharesheet, import via document picker and confirm theme; reject
  extra/duplicate fields, bad schema, invalid theme, trailing bytes and >4096-byte
  files. Key fingerprint must remain unchanged. Test a document provider and a
  Sharesheet receiver on device.
- Check light/dark/system, rotation, small display/large font, lock/unlock,
  biometric changes, key invalidation and reinstall. No network permission or
  telemetry should appear. Recovery ceremony remains a release blocker.

## IP and custody

Root [LICENSE](../../LICENSE), [NOTICE](../../NOTICE) and
[COMMERCIAL.md](../../COMMERCIAL.md) apply. No proprietary service source or
branding rights are conveyed. Nonsecret exports contain only schema and theme;
no private-key migration, key backup, trust import or recovery shortcuts exist.

## v0.2 diagnostic attestation

See [v0.2 evidence and recovery protocol](../../docs/FREQUENCY-GUARDIAN-V02.md)
for externally supplied challenge generation, explicit certificate export bounds,
independent pinned-root Rust verification and the future recovery ceremony.
The candidate is separate from the existing signing key and never enrolls itself.
