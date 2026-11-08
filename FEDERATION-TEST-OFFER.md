# Proposed Federation cross-participant test offer (NOT SUBMITTED)

## Intent

Invite opt-in independent participants to evaluate **MCP DriftGuard** as a standalone Apache-2.0 security utility, separately from Federation governance, TRACE, AgenTrust, Frequency membership, or Federation endorsement.

The offer is **testing only**. It does not imply acceptance into Federation, authority to access production endpoints, intellectual-property transfer, or a deployment obligation.

## Requested evaluation

Participants with MCP test environments can run the public-source, disposable, read-only acceptance harness and, if independently authorized, test their **own** sacrificial MCP endpoints. Request a short structured report of:
- implementation/SDK version and transport (synthetic or deidentified),
- reproducible installation and agent-skill discovery,
- PASS and unauthorized-tool-drift FAIL (with expected exit codes 0 and 2),
- REVIEW and invalid/incomplete probe classification,
- capability, schema, annotation, authorization and protocol variations they can safely simulate,
- whether hostile tool descriptions change agent decisions or baseline approval,
- command/version details, redacted logs, and observed limitations.

No secrets, proprietary code, signing private keys or production endpoints should be shared.

## Proposed participation terms

1. Fully optional; participants retain their own rights to their test artifacts.
2. DriftGuard remains independently owned, maintained and Apache-2.0 licensed. No joint IP, certification rights, implied endorsement or membership commitment.
3. Only explicitly approved disposable or tester-owned endpoints; no network scanning, arbitrary remote execution or client data collection.
4. Reproduction contract: pinned DriftGuard commit, pinned MCP implementation, commands/exit codes, expected vs actual output and evidence redaction.
5. Third-party publication of results requires the tester's consent; do not reveal Federation-private or company-private information.
6. Acceptance remains internal until independent cross-platform review and all product release gates pass.

## Suggested channel

Use the **existing Federation technical testing/conformance discussion** if Federation maintainers confirm it accepts outside tool evaluation; otherwise request a dedicated opt-in evaluation thread from the Federation maintainer. Do not attach this to TRACE/AgenTrust issues. Do not assume access to Federation systems or reviewers' resources.

## Decision

**HOLD FOR OWNER APPROVAL.** This is preparation inside the DriftGuard repository only. It has not been posted to Federation, sent to any participant, or interpreted as Federation authorization.
