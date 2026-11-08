# Contributing to MCP DriftGuard

Thank you for helping. Bug reports, interoperability results against real MCP servers, and fixes are all welcome.

## Before you start

- Open an issue for anything larger than a small fix, so the approach can be agreed first.
- Security problems: follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- Keep the core standalone. New features must not add a required dependency on a hosted service, an LLM provider, or any Altru.dev infrastructure (see [COMMERCIAL.md](COMMERCIAL.md)).

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` line certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/):

```sh
git commit -s -m "your message"
```

The sign-off name and email must match the commit author. Pull requests with unsigned commits will not be merged.

## Checks to run locally

```sh
gofmt -l .                      # must print nothing
go vet ./...
go test ./...
python3 scripts/check_docs.py
python3 scripts/conformance_suite.py --output /tmp/mcpdrift-conformance.json
```

CI runs the same checks plus the release-integrity and mutation suites.

## Pull requests

- One logical change per pull request, with tests for new behaviour.
- Update [SPEC.md](SPEC.md), [GLOSSARY.md](GLOSSARY.md) or [THREAT_MODEL.md](THREAT_MODEL.md) when you change what DriftGuard detects or how a verdict is reached.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
