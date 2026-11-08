# Frequency Guardian deployment status — 2026-10-23 UTC

Continuation from c320c37: see [current gate evidence and rebuilt APK](evidence/continuation-v051/STATUS.md).
That report supersedes the artifact hash and commit status below.

**Deployment incomplete. No verified Guardian HTTPS URL. Not production ready.**
This report supersedes earlier deployment claims; ONLINE_STATUS.md records the
previous v0.5.0 prototype. No service, route, DNS record, authority enrollment or
trust anchor was created remotely in this session. No code was pushed or published.

## Verified VPS inspection

Connected Desktop Commander device: `vps-377a113a`.
Read-only filesystem/process inspection succeeded. Remote command execution was
rejected with `MCP tool call requires approval, but approval policy is never`.
Consequently systemctl, certificate validation, installation and emulator commands
could not be run. This is an execution-policy restriction, not missing user consent.

- Caddy is running with `/etc/caddy/Caddyfile`. Its inspected config contains
  lab.ddcal.ca, staging.happyhr.ca, happyhr.ca, agentpay.altru.dev and graph.altru.dev.
  None has a Guardian API route. These existing sites are not Guardian endpoints.
  Existing access logs and unrelated applications were left untouched.
- `/etc/cloudflared` is empty; `/home/ubuntu/.cloudflared` does not exist. No
  cloudflared process appeared in the inspected process list. This does not prove
  Cloudflare DNS/account configuration or exclude configuration elsewhere.
- Caddy's certificate storage at
  `/var/lib/caddy/.local/share/caddy/certificates` was permission denied.
  No usable Guardian domain, private TLS key, valid certificate chain or Android
  hostname trust was verified. No unrelated certificate/key was copied or reused.
- `/etc/systemd/system` contains no dedicated Guardian unit. The existing
  `frequency-runtime.service` is a oneshot `/opt/frequency/bin/frequency status`,
  not the Python approval gateway. No Guardian gateway process appeared in the
  inspected process list; the IPv4 listener table had no port 8443 listener.
  Systemd active/enabled status and IPv6 listeners remain unverified.
- `/var/lib/frequency` is inaccessible. No independent Guardian authority or active
  real-phone enrollment was verified. A `guardian-challenge-state` directory is
  visible in the home listing; a challenge directory alone grants no trust.
  No keys, tokens or synthetic trust records were provisioned as deployment state.

## Actual emulator and uncompleted device acceptance

The VPS process list shows an actual running headless Android emulator using AVD
`safetyprotocol-atd`, plus ADB. Its inspected AVD configuration is API 35
`aosp_atd/x86_64`, Pixel 2 profile, Play Store disabled. Loopback IPv4 listeners
include ADB 5037 and emulator ports 5554/5555. A running process/listener does not
prove boot completion, installed application state or successful UI interactions.

Local `adb devices -l` cannot connect: the sandbox forbids creating ADB's socket
(`Operation not permitted`). Remote shell execution is denied by approval policy.
The new APK was **not installed**; app launch, runtime pairing/UI, original device
key continuity, emulator-to-VPS TLS, and signed device Approve/Deny were **not
verified**. Emulator attestation was never promoted into trusted phone enrollment.
Physical-device hardware attestation and update verification remain mandatory.

## Changes prepared locally

Android v0.5.1 (versionCode 6) retains the existing debug signing identity and
introduces no additional password or biometric prompts:

- Poll only with valid local enrollment; consult actual review state rather than
  a stale parallel flag that could stop polling after dismissal/import errors.
- Block transport replacement during an active review. Preserve pairing inputs
  when validation fails, prefill the existing origin, use URI input, disable token
  autofill, and clear the token widget after saving. Refresh visible enrollment
  status after online results. Existing persisted authority/enrollment/outbox and
  candidate identity are retained.
- The build signs directly with the original keystore instead of copying signing
  credentials into build output. Known existing keystore copies were restricted
  to mode 0600; no credential contents are included in evidence or Git changes.

Gateway startup now checks private authority state and TLS-key ownership/mode
before binding. Missing/corrupt/uncertain state refuses startup; startup never
initializes trust. Unsupported HTTP methods return generic no-store JSON without
Python version disclosure. All supported operations still require the device token,
independent enrollment and existing signature/replay/revocation enforcement.

`deploy/frequency-guardian.service` is a **local, uninstalled unit template** for a
separate unprivileged account, durable private state, loopback HTTPS on 8443,
read-only application files, restricted filesystem/capabilities, resource limits,
and restart on failure. It requires a provisioned system account, Python with
cryptography, root-owned reviewed code under `/opt/frequency-guardian`, independently
created authority under `/var/lib/frequency-guardian/authority`, and an owner-private
TLS key/certificate under `/etc/frequency-guardian/tls`. It deliberately does not
create keys, install policy, enroll devices, add public ingress, or restart Caddy.
`systemd-analyze verify` exited 1 because sandbox sockets are prohibited; unit
activation, compatibility and boot persistence have not been verified.

The single-request Python server and process-local rate limits remain availability
limitations. Edge connection controls, durable backup/rollback policy and independent
public-service review remain required before Internet exposure. No listener was
exposed by this work.

## Validation and artifact

- Python offline/online suite: **12 passed, zero skipped**, using real Rust verifier
  binaries at `/dev/shm/guardian-repair/rust-target/debug` with synthetic signed
  attestation fixtures and mocked certificate-status fetches. Both decisions,
  receipt persistence, replay/revocation, TLS issuer/hostname rejection, HTTP
  refusal, private startup state and uncertain ledger refusal passed.
- TLS used real OpenSSL records and the HTTP handler through MemoryBIO. This is
  not a socket test, emulator test or proof of Internet reachability.
- Explicit `FG_REQUIRE_NETWORK_TESTS=1` acceptance: **FAILED**, because socket
  creation raises `PermissionError: Operation not permitted`. The new switch
  prevents the MemoryBIO fallback from counting as network acceptance.
- Kotlin host suite passed: trust protocol and negative cases, 13 endpoint/token
  cases, and Python/Kotlin request/signature interoperability for both decisions.
  Host protocol checks do not exercise Android dialog lifecycle.
- Final SDK build and APK signature verification passed. Manifest: package
  `dev.frequency.guardian`, version 0.5.1 / code 6, min SDK 30, target 35.
  Original debug certificate SHA-256:
  `22a93e33cfd83c40797240407203c603e54d7cecf1482ea08c55fc33871bd572`.
  This is a debug build, not production release signing.

APK: `android/FrequencyGuardian/app/build/outputs/apk/debug/FrequencyGuardian-0.5.1-debug.apk`
under `/home/ubuntu/guardian-v030-repair`. APK SHA-256:
`2bd10188a5e2a01dac692a94cb85fda2d5ac8d44678da58549ac827ab12c1b37`.
APK and keystore are ignored build artifacts, not committed files.
Build/test scratch data used `/dev/shm`; deployment state must use durable private disk.

Evidence: `evidence/deployment-v051/python-tests.log`, `kotlin-tests.log`,
`apk-build.log`, `required-network-tests.log`, `systemd-verify.log`.

## Remaining real gates

1. Permit remote command execution and writable Git metadata in the execution
   environment. `git add` was attempted and failed creating the worktree's
   `index.lock`: **Read-only file system**. No commit was created. The existing
   Git worktree and pre-existing modified `FINAL_STATUS.md` were preserved.
2. Independently establish authority custody, real attestation root/signer/patch
   policy, fresh challenge, live certificate status and active device enrollment.
   Do not relax those checks to make an emulator pass or copy test state into service.
3. Verify an operator-controlled Guardian hostname and Android-trusted TLS chain,
   deploy the private unit and protected persistent authority, verify restart/boot
   behavior and permissions, then configure authenticated restricted ingress.
4. Pass real socket/TLS acceptance including invalid auth, cleartext, malformed
   input, slow connections, restart/durable receipts and trust rejection. Run
   emulator foreground request/review/delivery with signed Approve and Deny,
   status recovery, expiry and revocation, without claiming hardware trust.
5. Perform supported physical-phone installation/update without uninstall/data
   reset; prove original signer/candidate identity continuity, real hardware
   attestation, no-extra-prompt decisions, obscured taps, background cancellation,
   process death, lost responses, persisted outbox and local/server revocation.
6. Inspect changes, create the requested local commit when metadata is writable,
   and retain the explicit hold on push/publication pending inspection.
