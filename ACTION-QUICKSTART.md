# MCP DriftGuard — GitHub Action preview

**Action candidate, not yet Marketplace certified.** Use only with a reviewed and signed baseline and independently trusted Ed25519 public key.

Example, running against your own authorized, reachable test endpoint:

```yaml
name: MCP drift verification
on: [workflow_dispatch]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: altrudev/MCP-DriftGuard@REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA
        with:
          endpoint: https://your-authorized-test.example/mcp
          baseline: ${{ github.workspace }}/trust/approved-baseline.json
          verify-key: ${{ github.workspace }}/trust/approved-public-key.pem
          format: json
```

The example trust files must be committed or provisioned through an operator-controlled trusted channel. Do not include signing private keys in Git, secrets or Action inputs. No baseline is generated or automatically approved by the Action. Container actions require GitHub-hosted or self-hosted runners with Docker; the authorized endpoint must be reachable from inside the container. Failure and invalid trust must produce nonzero job status, not a successful green check. Do not run against unknown external endpoints.

MCP DriftGuard detects inventory/metadata drift; it does **not** execute discovered MCP tools or certify runtime safety. An Action runs in CI; local desktop notifications are separate and cannot appear on a user's computer from the hosted runner.
