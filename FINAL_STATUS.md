> Historical offline repair report. For the v0.5.0 online prototype, current APK and acceptance gates, see [ONLINE_STATUS.md](ONLINE_STATUS.md).

# Frequency Guardian 0.4.0 — Codex functional build, independently revalidated

Codex implemented offline Approve/Deny, independent enrollment verification, revocation checks and signed receipts. Separate post-Codex checks rebuilt 0.4.0 with the **previous debug signer**, ran the full test suites, installed the APK over the pre-existing emulator installation, and launched the app. This is **not** a production-certified release; genuine physical-device security acceptance and downstream execution integration remain open.

**Native offline approval implementation and debug APK delivered. Host checks pass.
Physical-device acceptance and production release acceptance remain open. Nothing
was published, uploaded, deployed, pushed or merged.**

## Delivered

- Native Kotlin **Approve / Deny** review and signed decision export. Removed the
  BiometricPrompt path and USE_BIOMETRIC permission. Both decisions use a tap;
  there is no additional password/biometric dialog. Newly generated keys require
  an unlocked device. Local diagnostics now actually reach explicit signing and
  update their ECDSA/tampering results.
- Offline document import/export workflow. A separately pinned P-256 verifier
  signs enrollment, action requests and revocations. Import verifies the
  signature, canonical encoding, exact candidate-key hash, installed APK signer,
  enrollment, lifetime and nonce. Diagnostics/settings cannot enroll a device.
- Operational receipts use the **attested candidate key itself**. No inferred
  hardware trust from the old diagnostic key or its candidate-binding signature.
  Independent root/app policy must come from outside the phone's exports.
- Independent `guardian-enrollment` Rust verifier and
  `scripts/guardian_offline.py` authority. Enrollment checks cryptographic chain,
  supplied root pin, hardware P-256, verifier-issued one-use challenge, package,
  independent APK signer, hardware noAuthRequired/signing/SHA-256 policy, locked
  verified boot, OS patch floor, and live certificate status. HTTP redirect,
  missing/stale Date/Age, malformed status or network failure refuses issuance.
- Phone and verifier consume requests durably before producing success. Replays,
  expired requests, clock rollback, full ledgers, signing/storage uncertainty and
  mismatched identity fail closed. Phone reviews cancel on backgrounding and
  have a monotonic bound. Approve/Deny have different signed decision bytes.
- Authority revocation blocks outstanding receipts immediately at verification;
  local revocation permanently tombstones the candidate. Safe replacement uses
  a fresh key, fresh challenge and complete independent enrollment. No automatic
  authority replacement, key migration, ledger reset or trust inheritance.
- Updated build/test scripts place generated classes, dex, test keys, logs and
  temporary files in `/dev/shm`. The finished APK and copied evidence are durable
  deliverables in the workspace. `/tmp` was not used for this repair's build data.

Current usage, exact wire format, independent provisioning, safe replacement and
limits: [docs/GUARDIAN-OFFLINE.md](docs/GUARDIAN-OFFLINE.md).
The previous diagnostic acceptance bridge still returns its pending verdict;
that verdict cannot enroll the new workflow. Historical protocol documents are
marked with the current workflow reference.

## APK evidence

[Installable debug APK](android/FrequencyGuardian/app/build/outputs/apk/debug/FrequencyGuardian-0.4.0-debug.apk)

- Size: **742,219 bytes** (verified build).
- SHA-256: `d49f58ed15fb722ad98f83d44c9d378a524fd6eb32b7c511807b189a5adcbec3`.
- Package `dev.frequency.guardian`, version code **4**, version **0.4.0**,
  minimum SDK **30**, target SDK **35**.
- `apksigner verify --verbose --print-certs`: **PASS**, APK v3, one signer.
- APK signing certificate SHA-256:
  `22a93e33cfd83c40797240407203c603e54d7cecf1482ea08c55fc33871bd572`.
- No requested Android permissions; no Internet or biometric permission.
  Packaged dex inspection finds no BiometricPrompt/biometrics API reference.
- This is a **debug** signing identity, not a production key. The original v0.3 APK's debug keystore was explicitly reused from the owner's VPS so Android in-place upgrade signature continuity is preserved. No production key was created.

The direct installed-SDK fallback built all native sources/resources using
`/opt/android-sdk`, cached Kotlin 2.0.21, javac, aapt2, d8, zipalign and apksigner.
The environment's initial SDK variable pointed at a missing directory; the final
successful build explicitly selected `/opt/android-sdk`. Platform deprecation
warnings remain. Gradle and an Android runtime were not used for this build.

## Executed validation

| Check | Result | Evidence |
|---|---|---|
| Cached Kotlin host diagnostics and protocol tests | PASS; 19 negative trust cases, fixture replay/expiry/tamper checks | [host log](evidence/guardian-repair/host-tests.log) |
| Python authority → Kotlin request verification → Python verification of both Kotlin decisions | PASS; exact bytes and real ECDSA signatures | [host log](evidence/guardian-repair/host-tests.log) |
| Python independent authority integration suite | **7 passed, 0 skipped** | [authority log](evidence/guardian-repair/offline-tests.log) |
| Rust broker suite including existing attestation/app-binding/challenge/recovery tests | **28 passed, 0 failed** | [Rust log](evidence/guardian-repair/rust-tests.log) |
| All Rust binaries including guardian-enrollment | PASS | [build log](evidence/guardian-repair/rust-build.log) |
| Native APK build | PASS | [APK build](evidence/guardian-repair/apk-build.log) |
| APK signature and packaging | PASS | [signature](evidence/guardian-repair/apk-signature.log), [badging](evidence/guardian-repair/apk-badging.log) |
| `git diff --check`, `cargo fmt -- --check` | PASS | Executed after final changes |

Integration coverage includes genuine cryptographic verification of disposable
signed certificate fixtures through the Rust executable; positive enrollment;
wrong APK signer, missing no-auth property, unlocked boot and old patch rejection;
challenge replay; signed approve/deny; receipt replay after ledger reload; changed
decision/key/signature; expiry including expiration during status verification;
revocation of outstanding requests; duplicate JSON; malformed/unavailable/stale
certificate status; private authority initialization; clock/permission checks;
and uncertain durable commits. Revocation HTTP responses are mocked in tests.
These tests do **not** establish real Android hardware custody or live status
service interoperability. No actual device was enrolled or marked trusted here.

Reproduction from repository root:

```sh
TMPDIR=/dev/shm android/FrequencyGuardian/test-host.sh
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/guardian-repair/rust-target \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --offline --manifest-path broker/Cargo.toml --bins
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/guardian-repair/rust-target \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --offline --manifest-path broker/Cargo.toml
TMPDIR=/dev/shm PYTHONDONTWRITEBYTECODE=1 \
  FG_RUST_BINARIES=/dev/shm/guardian-repair/rust-target/debug \
  python3 -m unittest discover -s scripts -p test_guardian_offline.py -v
ANDROID_SDK_ROOT=/opt/android-sdk TMPDIR=/dev/shm \
  android/FrequencyGuardian/build-sdk-offline.sh
```

Machine-readable result: [result.json](evidence/guardian-repair/result.json).
The packaged update was signed with the preserved original debug keystore. Future builds must use `FG_SIGNING_KEYSTORE` and never silently generate a new signer for an in-place upgrade.
The pre-existing working-tree edits in `broker/tests/guardian_binding.rs` were
preserved and included in the successful Rust run.

## Genuine remaining acceptance gates

1. **Physical Android acceptance — unverified.** Install on supported TEE and
   StrongBox phones. Exercise Approve and Deny with no extra system prompt,
   hardware-only signing, lock/unlock, Android 11 OEM behavior,
   background/rotation/process death, obscured-touch rejection, expired review,
   document providers, export cancellation/failure and replay after restart.
   The Codex sandbox ADB startup failed; subsequently the Android emulator on the VPS accepted `adb install -r` and launched `dev.frequency.guardian/.MainActivity` successfully with v0.4.0. This checks installation and launch, not the real on-device approval or StrongBox flow.
2. **Real independent enrollment/status acceptance — unverified.** Authenticate
   actual manufacturer/Google root pins, intended APK signer and verifier pin
   out of band. Exercise the full real-device certificate chain, genuine
   challenge, app identity, boot/patch policy and live Google status endpoint,
   including service failures and certificate/root changes. Test fixtures and
   local KeyInfo are not substitutes. No real root, production policy or
   production authority was provisioned in this workspace.
3. **Production signing and upgrade continuity — blocked pending ceremony.**
   Supply a separately managed release signer, build/review the release APK,
   bind that signer in independent verifier policy, then prove in-place upgrade
   preserves candidate/trust state on a physical phone. This Android APK reuses the historical debug certificate, but a separately managed production signer and physical upgrade acceptance are still required. Do not
   uninstall an enrolled app to force an upgrade; there is no identity recovery
   through uninstall/settings import. Old build hashes in that document are
   historical; this file records the current artifact.
4. **Authority custody, rollback protection and recovery — deployment gates.**
   Independently provision and protect the verifier key, policy, reliable clock,
   challenge ledger, replay ledger and revocations on persistent private storage.
   Test lost-phone revocation and fresh-device re-enrollment end to end.
   Phone-local revocation cannot notify an offline verifier; revoke at the
   verifier first. Phone-side propagation can lag until request/grant expiry;
   verifier receipt acceptance consults current revocation state. Loss of the
   authority/ledger, automatic authority rotation, ledger compaction and quorum
   activation remain **unimplemented and blocked**, not reported as recovered.
   Full ledgers refuse operations instead of removing replay protection.
5. **Execution integration — absent.** The app and reference authority produce
   and verify decisions; they do not execute broker actions or deliver push
   requests. Production use needs a reviewed executor that accepts only one-use
   verified approve receipts for the exact issued action, with a durable
   execution transaction boundary. Deny, pending diagnostic reports and raw JSON
   must never authorize execution. No such integration was enabled or claimed.

No publication or deployment was attempted. These remaining gates are explicitly
open; this result does not claim production readiness or completed device testing.
