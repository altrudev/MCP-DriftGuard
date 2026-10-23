# Frequency Conduit production monitor

The monitor performs one signed-baseline verification against
`http://127.0.0.1:8765/mcp`. It only initializes the MCP session and lists
inventory; it does not call tools, approve changes, write a baseline, or hold a
private signing key. Production activation remains blocked until an independent
authority supplies an approved signed baseline and its externally authenticated
public trust key. Fixture keys in tests establish no production authority.

Install the reviewed binary at `/opt/mcp-driftguard/mcpdrift` and script at
`/opt/mcp-driftguard/scripts/production_monitor.py`. Install the service and timer
from `deploy/` into `/etc/systemd/system/`. Review paths in the example config;
keep config, binary, baseline and public key administrator-owned and unwritable
by the service. The baseline and public key must be readable by the dynamic user.
Keep signing keys elsewhere. Do not copy the example to the approved config name
or enable the timer until independent baseline approval and key authentication
have actually occurred. The `approved` field records operator deployment approval;
it is not a signature or a substitute for independent authority.

After those prerequisites, install the reviewed config with `approved: true` at
`/etc/mcp-driftguard/approved-monitor.json`. Run `systemctl daemon-reload` and
`systemctl start mcp-driftguard-monitor.service` for a single verification. Inspect
its durable results before enabling `mcp-driftguard-monitor.timer` with
`systemctl enable --now mcp-driftguard-monitor.timer`. No units are installed or
enabled by this repository or its tests. The timer schedules once per hour, does
not catch up missed runs, and both units skip when approved config is absent.
A false approval field fails closed without contacting Conduit. A present but
invalid config or bad trust material records an error. Stop/disable the timer to
suspend monitoring; retain the database for incident history.

The service has a 60-second lifetime, 256 MiB cgroup memory cap, no swap, CPU and
task limits. The verifier has a 45-second timeout, 40 CPU-second limit, 4 GiB
virtual-address cap, 192 MiB Go soft heap target, and 1 MiB output-file limit.
For manual invocation use the supplied service to enforce the total memory cap;
the Go heap target alone is not a hard resident-memory bound. Persistent state
and transient output both reside on the disk-backed `/var/lib` filesystem;
ensure it is not mounted as tmpfs. The script uses a state-local `tmp` directory,
not the private `/tmp`. Temporary output is unlinked automatically and never
loaded wholesale into Python memory. No bearer token or proxy environment is
inherited by verification.

`/var/lib/mcp-driftguard-monitor/monitor.sqlite3` is the authoritative durable
alert and recovery journal. Inspect, for example:

```sh
sudo sqlite3 /var/lib/mcp-driftguard-monitor/monitor.sqlite3 \
  'SELECT id,datetime(time,"unixepoch"),status,detail,action FROM events WHERE alert=1 ORDER BY id;'
```

Initial health is recorded without alerting. Initial drift/error, transitions
between error/drift, and recovery each produce one alert row. Repeated identical
states produce no additional alert. Each transaction commits the alert row and
current state together with SQLite FULL synchronization. A process lock prevents
concurrent checks from reordering transitions. A crash before commit leaves no
partial transition; the next invocation checks again. Journal rows survive
process restarts. Storage errors fail the service; check journald for Python
errors and restore disk space/permissions. Preserve and back up the database;
removing it resets deduplication. History grows with transitions; archive it under
operator retention policy. The journal is the alert sink; email/webhook delivery
is not configured and no external delivery or exactly-once network guarantee is
claimed. Any downstream sender should checkpoint the unique event ID.

Exit 0 means healthy, 1 means drift/error (the JSON status distinguishes them).
Verifier codes 1/2 mean drift, 3 means probe/usage error, 4 means baseline/key
loading error, and 5 means invalid trust/signature. For drift investigate inventory
changes; an independent authority must review any new baseline. For endpoint
errors check the existing Conduit service without restarting unrelated processes.
For trust errors reauthenticate the supplied public key and baseline. Never fix
these by automatically generating keys or accepting a live snapshot. After repair,
the next healthy run records recovery. Captured verifier output is bounded and
discarded; reproduce one reviewed verification manually for detailed inventory
diffs, avoiding logging sensitive descriptions to broadly accessible sinks.

Run `TMPDIR=/tmp python3 -m unittest discover -s scripts -p test_production_monitor.py`.
The real-verifier test builds disposable binaries, generates fixture-only keys,
uses an ephemeral loopback port, and terminates only its own fixture processes.
New run evidence belongs in `evidence/production-monitor-20261023/`; previous
native VPS evidence and continuation artifacts must remain untouched.
