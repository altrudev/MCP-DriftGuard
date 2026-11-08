# Customer-local notification implementation evidence

Native adapters: Linux notify-send with desktop session detection, macOS osascript
with current-user console detection, Windows PowerShell NotifyIcon with interactive
session detection. Native interpreter source is fixed; event text is data only.
Linux markup is escaped. Calls are bounded to five seconds. No remote service is
required. The Linux/POSIX monitor defaults to local delivery; installed user units
no longer require an external receiver. The portable Windows adapter is not a
Windows monitor installer; systemd installation remains Linux-specific.

SQLite retains drift/error/recovery transitions, pending delivery and acknowledged
event IDs. Desktop failure leaves events retryable; status and delivery dedup are
preserved. Off and agent modes do not acknowledge or send events. An explicit
external receiver remains supported. MCP tool responses add structured actionable
notification results with host_push=false and retain original text evidence.

Test-first observations: new Python tests initially failed importing the missing
local_notifications module. New Go actionable-result test initially failed because
notification status/action were absent. Both passed after implementation.

Final Python discovery: 66 tests, OK, six environment-dependent skips.
Final notification tests: eight passed, including a real disposable executable
receiving hostile text as argv without executing it. MCP server race tests passed.
See python-tests.log, notifications-tests.log, and mcpserver-race.log.

Conformance was run; consult conformance.json and conformance.log for individual
results. Go unit/race loopback fixtures and HTTP acceptance cannot pass in this
sandbox because socket creation is denied. Writable GOCACHE=/tmp/driftguard-local-go-cache
resolved the initial read-only cache failure. No claim of a fully passing
conformance run or desktop visibility is made. Linux visible desktop receipt,
macOS and Windows execution, and real agent-host presentation remain unverified.

The skill validator rejects the pre-existing compatibility frontmatter field;
skill-validation-baseline.log reproduces the same failure from HEAD. That existing
metadata was preserved. Repository documentation checks pass.

Baseline approval and artifact-pin checks were retained. No timer activation,
Conduit changes, commits or pushes were performed. Pre-existing working-tree files
and changes were preserved. implementation-sha256.json identifies the implemented
source and documentation independently of the unchanged HEAD commit.
