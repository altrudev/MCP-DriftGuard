# Continuation from c320c37 — 2026-10-23 UTC

Deployment is incomplete. No verified Guardian HTTPS endpoint; no emulator UI or
physical phone acceptance. This record supersedes the artifact hash and Git status
in DEPLOYMENT_STATUS.md. No unrelated service or public route was changed.

| Gate | Actual result |
| --- | --- |
| Authorized VPS | Desktop Commander lists vps-377a113a online, ID b5f97e3f-b6d4-4a37-9614-85905ab97c68 |
| Remote execution | start_process rejected: `MCP tool call requires approval, but approval policy is never` |
| Direct terminal network | IPv4 and IPv6 socket creation denied with EPERM |
| Actual HTTPS attempt | curl to existing graph.altru.dev fails DNS, exit 6; this is not a Guardian endpoint |
| Mandatory socket/TLS test | FAIL, explicitly requires sockets and does not count MemoryBIO as network acceptance |
| Caddy | Remote process inspection confirms PID 1356 running /etc/caddy/Caddyfile; inspected config has no Guardian route |
| TLS prerequisites | Dedicated /etc/frequency-guardian/tls certificate/key absent; Caddy certificate store inaccessible; no Guardian hostname or Android-trusted chain verified |
| Service startup | Actual serve command refuses missing /var/lib/frequency-guardian/authority before binding |
| Service install / enable | Dedicated /opt application, authority and system unit absent; systemctl bus operations denied; not installed or enabled |
| Identity trust | No independent production authority or real-phone enrollment verified; no synthetic state provisioned |
| Emulator | Remote process inspection confirms AVD safetyprotocol-atd and ADB running; local ADB install -r attempt fails opening its socket; installation, boot and UI unverified |
| Python checks | 12 passed, zero skips; synthetic signed fixtures and mocked revocation fetches, real Rust verifier; TLS records exercised in memory |
| Kotlin checks | Host suite passes, including 13 origin/token cases and both decision signatures across Python/Kotlin |
| Android build | v0.5.1 / code 6, min SDK 30, target 35; successful installed-SDK rebuild using /opt/android-sdk |
| Original signer | APK signature verifies, SHA-256 22a93e33cfd83c40797240407203c603e54d7cecf1482ea08c55fc33871bd572 |
| Physical device | Unavailable/unverified; no hardware attestation claim |

Changes: gateway startup rejects expired and not-yet-valid leaf certificates before
binding (regression checks cover both). This does not establish issuer/hostname
trust; client trust and independent deployment prerequisites remain required.
Android protects the saved delivery outbox when a delivery starts while the discard
dialog is open. The Android change compiles; runtime dialog behavior remains
unverified because the actual emulator installation is blocked.

APK staged at:
`/home/ubuntu/guardian-v030-repair/android/FrequencyGuardian/app/build/outputs/apk/debug/FrequencyGuardian-0.5.1-debug.apk`

APK SHA-256:
`18805d11a16c2647523d911e3f9ed69be403b6fb827679b73fcc27fdca70324f`

The existing debug signing keystore was used directly; no new signing identity was
generated. Initial build attempt inherited an invalid SDK path; explicit
ANDROID_SDK_ROOT=/opt/android-sdk resolved it. Build scratch uses /dev/shm.

The source worktree's Git metadata is mounted read-only. `git add` fails creating
index.lock. An independent writable clone in /dev/shm/guardian-continuation-commit
preserves a commit based on c320c37, with a transferable bundle and patch staged in
this evidence directory. The original worktree HEAD remains c320c37; no push.

Evidence: python-tests.log, kotlin-tests.log, apk-build.log,
required-network-tests.log, environment-gates.log and install-startup.log.
Remote process observations were read-only: Caddy PID 1356, ADB PID 1910388,
headless emulator PID 1913016; no guardian_online.py service appeared.

Remaining deployment needs an execution context permitted to reach the host
network/systemd and write deployment paths, independently established durable
authority and real enrollment, and a verified dedicated hostname/TLS chain.
Existing access controls were not bypassed. Mock test credentials were not installed.
