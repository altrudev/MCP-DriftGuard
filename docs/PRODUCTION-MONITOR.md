# Linux Conduit monitor

The read-only monitor verifies `http://127.0.0.1:8765/mcp` against an independently
approved signed baseline. It does not call discovered tools, generate keys,
approve baselines, or repair drift. Production activation is still blocked on
independent approval and target-host acceptance. Tests use disposable fixtures.

## User installation (no root required)

Build a reviewed revision, then install it without starting any process:

```sh
go build -trimpath -o /tmp/mcpdrift-reviewed ./cmd/mcpdrift
python3 scripts/install_user_monitor.py --binary /tmp/mcpdrift-reviewed
```

The installer copies the binary and monitor under `~/.local/lib/mcp-driftguard`,
creates example configs under `$XDG_CONFIG_HOME/mcp-driftguard` (default
`~/.config/mcp-driftguard`), state under `$XDG_STATE_HOME/mcp-driftguard` (default
`~/.local/state/mcp-driftguard`), and units under `$XDG_CONFIG_HOME/systemd/user`.
Explicit absolute `--prefix`, `--config-dir`, `--state-dir`, and `--unit-dir`
overrides support staging and disposable acceptance. Existing release/unit files
are rejected; upgrades must be staged and reviewed separately. Installation never
runs systemctl, creates approved config, or enables a timer. An interrupted install
may leave partial files; inspect and remove only those staged files before retry.
User services require a Linux systemd user manager; resource controls require
cgroup delegation. Lingering for operation after logout is an operator decision.

## Independent approval gate

The authority must authenticate the public key out of band and review/sign the
baseline. An operator then reviews the installed verifier and all three artifacts.
Record their SHA-256 hashes with `sha256sum` and explicitly supply them in the
`sha256.binary`, `sha256.baseline`, and `sha256.public_key` fields of the example.
Only after that review, create `approved-monitor.json` with `approved: true`.
The monitor requires absolute existing file paths, all three pins, and a matching
hash for each artifact before launching verification. The Go verifier additionally
validates the baseline signature with the supplied key. Changes require a fresh
review; the monitor never updates pins or signatures. Legacy Boolean-only configs
now fail closed and need operator review. No production approval is provided here.

These files are operator-controlled local policy, not a cryptographic record of
human approval. A user-level deployment trusts the account owner and filesystem;
it does not separate that owner from the approver. Keep policy, binary, key and
baseline inaccessible to untrusted writers. Digest checks do not prevent a
concurrent privileged file replacement between hashing and execution. Deploy with
administrator-controlled artifacts if stronger account separation is required.
Never place private signing keys in the monitor installation.

## Alert delivery and retry

Direct customer-local desktop delivery is the default: no remote service, account,
receiver or credentials are required. Linux uses `notify-send` when installed and
`DBUS_SESSION_BUS_ADDRESS` identifies the logged-in user's desktop session. Run
under that user; a systemd user manager may need the desktop environment imported
by the login session. Never invent another user's bus address. Missing capability,
headless sessions, nonzero adapter exits and timeouts leave events pending.
The portable adapter also supports macOS `osascript` and Windows PowerShell
NotifyIcon in an interactive session. Their real desktop behavior requires testing
on those operating systems; the monitor/systemd installation is Linux/POSIX.
OS submission success does not establish that the user saw the notification;
permissions, focus modes and desktop policy may hide it. Event content is bounded
and passed as data, never interpolated into shell, AppleScript or PowerShell code.

Use `--notifications off` to opt out of delivery while preserving the journal and
pending events. Use `--notifications agent` to return up to ten pending actionable
events as JSON with `host_push: false`, without desktop delivery or acknowledgement.
These explicit modes override `--alert-config`. Repeated agent reads preserve the
same pending events. Agent hosts decide how to present them; this is not unsolicited
host push. `mcpdrift serve` also returns actionable `structuredContent.notification`
with verification evidence; it is stateless and cannot infer recovery on its own.

A headless VPS cannot reach the customer's laptop or phone unaided. Run the monitor
on the customer's desktop for local notifications, or explicitly configure an
external receiver/bridge for remote delivery. A VPS journal is not customer receipt.

To choose an optional external receiver, create `alerts.json` from
`alerts.example.json` and explicitly pass `--alert-config /absolute/path/alerts.json`
(manually edit the staged user unit if needed). This replaces local delivery.
Its `command` is an argv array whose first item is an absolute executable path.
No shell is used. The receiver gets one JSON event on stdin containing `id`,
`time` (Unix seconds), `status`, `detail`, and `action`; it must exit zero only after
durable acceptance. Only PATH and a state-local TMPDIR are passed. Receiver output
is discarded and capped at 1 MiB. The administrator-managed system service retains
its explicit external receiver, since its isolated user has no customer desktop.

SQLite is the durable outbox. Initial drift/error, changes between error and drift,
and recovery produce alert rows. Repeated status and initial health do not alert.
Delivery retries pending events in order on every run, including healthy runs.
At most 10 events and 20 seconds are spent on delivery per invocation, with a
five-second limit per receiver. Failure stops the batch, leaves it pending and
fails the service. A receiver crash or failure after accepting an event can cause
a duplicate: delivery is at least once. Deduplicate by event ID within this
installation's database; IDs can repeat in another installation or after database
replacement. Keep the database and its backup to preserve history and deduplication.
A missing/invalid explicit receiver config leaves delivery pending. Native delivery
uses the same acknowledgements, retry order and bounds. Switching delivery methods
does not replay previously acknowledged events. Pending local delivery fails the
service; an empty outbox requires no desktop. Opt-out leaves pending events intact.

After independent approval and local desktop or receiver testing, an operator can run a single check:

```sh
systemctl --user daemon-reload
systemctl --user start mcp-driftguard-monitor.service
journalctl --user -u mcp-driftguard-monitor.service
sqlite3 ~/.local/state/mcp-driftguard/monitor.sqlite3 \
  'SELECT id,status,detail,action FROM events ORDER BY id;'
```

Adjust the database path for an XDG override. Verify receipt of a disposable test
alert before any production scheduling. Only with separate activation approval:

```sh
systemctl --user enable --now mcp-driftguard-monitor.timer
```

No timer activation is authorized or performed by this change. To suspend an
existing schedule, the operator uses `systemctl --user disable --now
mcp-driftguard-monitor.timer`. The timer is hourly and does not catch up missed
runs. The same account must protect its state directory; use disk-backed state,
not tmpfs. SQLite FULL synchronization commits transitions atomically. An exclusive
lock covers checks and delivery. Retention and disk-space monitoring are operator
responsibilities; storage failures fail the process and require journal inspection.

The service bounds runtime at 90 seconds, memory at 256 MiB with no swap, CPU at
50%, and tasks at 16. Verification has a 45-second deadline, 40 CPU-second limit,
4 GiB virtual-address cap, 192 MiB Go soft heap target, and 1 MiB output cap.
Child process groups are killed after success/failure/timeout; descendants that
escape into another session require cgroup containment. This is resource bounding,
not a complete sandbox. Manual execution lacks the service's total memory cap.

Exit 0 means healthy with no failed delivery (including explicit opt-out or agent mode); exit 1 means drift,
verification error or delivery failure. JSON distinguishes those states. Verifier
codes 1/2 mean drift; other nonzero codes mean error. A bad signature, missing
approval or changed artifact cannot become healthy. For drift, investigate and
seek independent baseline review. For connection errors, inspect Conduit without
restarting unrelated services. Never fix trust errors by accepting a live snapshot.

## System service and verification limits

The alternative administrator-managed units in `deploy/` use `/opt/mcp-driftguard`,
`/etc/mcp-driftguard/approved-monitor.json`, `/etc/mcp-driftguard/alerts.json`, and
`/var/lib/mcp-driftguard-monitor`. Install manually only after reviewing ownership;
the dynamic service user needs read access to artifacts. These units are not
installed by the user installer. Both deployment modes share the approval/outbox
implementation. Existing system-service upgrades need a daemon reload and review
of the new pin and delivery requirements before execution.

Run `TMPDIR=/tmp python3 -m unittest discover -s scripts -p test_production_monitor.py`.
The suite covers installation without activation, approval rejection, durable
transitions, real command delivery/retry, and a signed real-verifier loopback test.
Socket-restricted environments skip that last test; a skipped test does not
establish production network acceptance. Hosted CI runs the suite on Linux.
Remaining gates: authenticated production trust key and baseline; independently
reproduced signed-verifier/network tests; real systemd/cgroup user-manager execution;
and visible receipt on the chosen desktop or optional external receiver. No production-ready or
independent security certification claim is made.
