# Production monitoring repair — 2026-10-23

Implemented a one-shot CLI verification wrapper, transactional SQLite transition
and alert journal, serialized checks, bounded verifier resources, explicit trust
configuration, inactive hourly systemd templates and operations documentation.
Tests were added before implementation (initial import failed as expected).

Validation:

- Monitor tests: 6 run, 5 pass, 1 skipped because this execution sandbox denies
  socket creation. Includes durable deduplication across processes, atomic
  rollback on failed state writes, approval failure, exit mapping and timeout.
- Python scripts suite: 53 run, 47 pass, 6 skipped.
- Conformance: Go vet, documentation, stdio acceptance and extreme limits pass.
  Full Go unit/race and HTTP acceptance fail because sandbox socket creation is
  denied. The detailed failures are retained in conformance.json. These are
  blocked checks, not claimed passes. No race-free production certification.
- The real verifier fixture test for signed baseline, wrong key, endpoint down,
  drift and recovery is implemented but requires a socket-capable environment.
- systemd-analyze verify: exits 1 in this sandbox with SO_PASSRIGHTS/SO_PASSCRED
  socket permission errors; host-side unit validation is still required.
- Documentation checks and git diff --check pass.

Production remains inactive: no independently approved baseline or authenticated
external public key was supplied. No baseline or key was minted for production.
No service/timer was installed or enabled, no production endpoint was queried,
and no existing Conduit or unrelated process was changed. Test subprocesses
complete synchronously or are stopped in fixture cleanup; no daemon is left.

Existing modified tracked native-vps evidence and untracked continuation.bundle,
continuation.patch and mcpdrift-current were preserved, not staged. Nothing was
committed or pushed. This evidence is local validation, not independent authority.
