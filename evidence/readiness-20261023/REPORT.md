# Production readiness repair — 2026-10-23

Source working tree only; no commit, push, deployment, baseline approval, or persistent process was created. Existing continuation-v051 bundle and patch hashes match `preserved.sha256`.

## Changes

- `cmd/mcpdrift/main.go` and tests: serve now requires an explicit trusted --verify-key. Missing configuration exits 3, unreadable/malformed key or baseline exits 4, integrity/signature failure exits 5. Startup validates before reading stdin or probing. Tests cover unsigned/signed artifacts without keys, unsigned with trusted key, missing/malformed/wrong key, hash tamper, tamper with recomputed hash, corrupt signature, and signed trusted positive startup.
- `internal/baseline/baseline.go` and tests: same-directory temporary file, file sync, close, atomic rename, directory sync. Saves replace symlinks rather than truncating their targets; temporary files are cleaned on failures. Newly saved artifacts use private 0600 permissions. Rename is the publication point; a subsequent directory-sync failure returns an error even though the new artifact may already be visible. Malformed nonempty Ed25519 key lengths return errors instead of panics. CLI unsigned baseline/verify mode remains supported outside serve.
- `internal/mcpserver/server.go` and tests: validate parameter objects for ping and initialize as well as inventory/tool methods. Invalid ping arrays no longer receive success. Null initialize remains rejected.
- `scripts/test_mcp_server.py`, `scripts/mcp-sdk-client/main.go`: official SDK acceptance now generates ephemeral synthetic signing keys and supplies the public key to serve.
- `README.md`, `INSTALL.md`: mandatory signed serve trust policy and independently established key provenance.

## Verification

`test-first.log` retains failures observed before implementation: unsigned startup accepted, symlink target truncated, malformed private key panic, invalid ping params accepted.

`core-race.log`: PASS for cmd/mcpdrift, baseline, canonical, diff, mcpserver, report.
`go-vet.log`: go vet ./... PASS.
`go-race.log`: go test -race ./... attempted; fails in existing observe HTTP listener test because socket creation is denied (EPERM), not a passing full race suite.
`conformance-final.json` / `.log`: full required conformance runner; vet, docs, stdio acceptance and extreme limits pass; Go unit/race and HTTP acceptance fail on sandbox socket restrictions. Earlier initial default-cache failures are retained separately. Core source and tests are bound in source-manifest.json; the conformance commit field alone does not describe these uncommitted changes.
`sdk-final.log`: official go-sdk v1.8.0 real stdio subprocess PASS: discovery, inspect, unchanged match, drift FAIL, pinned baseline after disk replacement, target override rejected, probe error inconclusive. This is an SDK synthetic-fixture test run by this agent, not independent human verification or real Codex/Claude/Cursor model invocation.

All build/runtime temporary directories use disk-backed TMPDIR under /home/ubuntu/.cache/ddc-chat-lab (the writable session subdirectory); GOCACHE was redirected there because the default cache is read-only. No long-lived background process was started.

## Production and release blockers

`conduit.json` records a bounded read-only attempt against the previously selected existing Conduit endpoint http://127.0.0.1:8765/mcp. Independent Python discovery: INCONCLUSIVE, URLError errno 1; fresh Go inspector: exit 3, INCONCLUSIVE. No discovered tools were executed. This sandbox's socket restrictions do not establish a VPS/service outage. Prior direct-VPS inventory evidence remains historical and does not certify this changed source.

No independently approved production Conduit baseline or trusted key provenance has been established. No production monitor was deployed; monitor uptime and operational alert delivery remain unverified. Real endpoint behavior and independent agent-host operation remain unverified. Supervisor must review the source and rerun full HTTP/race/Conduit checks in an authorized socket-capable environment. Native cross-platform, hosted release signing, independent acceptance and release authorization remain separate unresolved gates. This repair is not a production-readiness certification.
