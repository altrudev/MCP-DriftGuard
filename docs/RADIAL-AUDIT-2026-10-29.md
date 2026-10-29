# Independent local audit of timeout readback and CI release gates

Candidate: `291531f`, the checkout, local main and cached origin/main on
2026-10-29. GitHub DNS/API access failed; current remote main, external reviewer
PR23 contents and hosted CI results could not be verified. This is a local
review, not external reviewer approval or release authorization.

## Findings

1. **High: HTTP response correlation is absent.**
   `internal/observe/modern.go:189` and `internal/observe/legacy.go:161` decode
   the JSON-RPC ID and return success without comparing it with the request.
   A temporary Go test overlay using an in-memory HTTP RoundTripper confirmed
   both paths accept response ID 999 for tools/list request ID 2. A stale or
   unrelated inventory can therefore be consumed as the requested readback.
   Existing HTTP tests do not assert this rejection. Production repair and its
   rejecting HTTP regression remain outstanding; this audit does not encode
   acceptance as a permanent passing test.

2. **Closed test gap: stdio correlation and parent deadline.**
   Added `internal/observe/stdio_correlation_test.go`. A real approved child
   provides matching inventory, replays the initialization ID during tools/list,
   or withholds the inventory response. Tests require successful matching
   readback, explicit mismatch rejection, and bounded failure at the parent's
   deadline. Temporary overlays removing the ID comparison or replacing the
   parent context with a background context both fail the new test. The timeout
   fixture independently exits after three seconds to bound a broken version.

3. **Closed test gap: release CLI boundary.**
   Existing release tests exercised assess(), leaving main() checkout checks and
   release authorization output unasserted. Added clean-checkout, wrong-HEAD,
   tracked-dirty and untracked-dirty cases, requiring correct exit/verdict,
   hosted_ci UNVERIFIED and release_authorized false. Temporary mutations
   bypassing either checkout check or changing authorization to true are killed.
   Git output is mocked; these cases test CLI decisions, not Git integration.

## CI review and validation

CI runs release mutation tests and the conformance runner, whose Go unit suite
will discover the new stdio tests. It then validates revision-bound evidence.
No workflow, production implementation, required suite, or fail-closed gate was
changed. A local passing gate never authorizes release. Hosted native and Docker
job outcomes, repository branch protection and PR23 remain unverified.

- `go test ./...`: attempted; observe panics because sandbox policy denies
  httptest loopback socket creation. Other packages pass.
- All non-observe Go test packages: pass. Selected socket-free observe tests,
  including the new regression: pass.
- New stdio regression under `go test -race`: pass.
- `go vet ./...`: pass using a writable temporary GOCACHE.
- Release gate tests: 11 pass. Artifact integrity mutation tests: pass.
- Five targeted mutations killed: stdio ID check, parent deadline, release
  revision check, dirty-checkout check and authorization flag.
- `git diff --check`: pass.

Disposition: request-correlation repair and a full Go/hosted-CI rerun are still
needed before treating this candidate as verified. No commits or pushes made.
