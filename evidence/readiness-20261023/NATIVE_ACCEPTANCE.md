# Independent native VPS acceptance

The repaired source was independently tested outside the Codex sandbox through the DDC-admitted user systemd gateway. All seven conformance suites PASS, `go test -race ./...` PASS, `go vet ./...` PASS, and real Conduit discovery PASS using the freshly rebuilt candidate binary. Refer to `native-vps/summary.json`, `native-vps/conformance.json`, and `native-vps/conduit.json`.

Candidate binary SHA-256: `94b25bef027a21385e32f9215edd32aec95624e7b4da18b47db20a5ee6572e56`. Disk-backed candidate location: `/home/ubuntu/.local/share/mcpdrift/candidates/94b25bef027a21385e32f9215edd32aec95624e7b4da18b47db20a5ee6572e56/mcpdrift`. The staged candidate is **not** an approved production monitor. No independently approved Conduit baseline or trust key provenance exists; real tool behavior and ongoing monitoring remain unverified.

Codex sandbox conformance failures were due to denied network listener creation; the native rerun is the release-relevant check.
