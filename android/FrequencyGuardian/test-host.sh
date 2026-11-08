#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./cached-kotlin.sh
export TMPDIR="${FG_TMPDIR:-/dev/shm/frequency-guardian-tmp}"
mkdir -p "$TMPDIR"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djava.io.tmpdir=$TMPDIR"
export FG_TEST_OUT="${FG_BUILD_ROOT:-/dev/shm/frequency-guardian-build}/host-tests"
mkdir -p "$FG_TEST_OUT"
fg_kotlinc app/src/main/java/dev/frequency/guardian/Approval.kt app/src/main/java/dev/frequency/guardian/Diagnostics.kt app/src/main/java/dev/frequency/guardian/TrustProtocol.kt app/src/main/java/dev/frequency/guardian/OnlineProtocol.kt tests/OnlineChecks.kt tests/FixtureChecks.kt tests/TrustChecks.kt tests/CrossChecks.kt -jvm-target 17 -classpath "$FG_STDLIB" -d "$FG_TEST_OUT/checks.jar"
java -cp "$FG_TEST_OUT/checks.jar:$FG_STDLIB" dev.frequency.guardian.FixtureChecksKt

java -cp "$FG_TEST_OUT/checks.jar:$FG_STDLIB" dev.frequency.guardian.TrustChecksKt

python3 - <<'PYTEST'
import json, os
with open(os.path.join(os.environ["FG_TEST_OUT"], "report.json")) as source:
    report = json.load(source)
assert len(report["checks"]) == 10
assert {item["status"] for item in report["checks"].values()} == {"pass", "fail", "pending"}
assert report["production_eligible"] is False
assert report["private_keys_exported"] is False
assert report["external_attestation_challenge_required"] is True
assert report["checks"]["update"]["detail"] == 'quote" newline\n slash\\'
print("PASS: independent JSON parser, ten checks, three statuses and escaped detail roundtrip")
PYTEST

PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/guardian_crosscheck.py prepare
java -cp "$FG_TEST_OUT/checks.jar:$FG_STDLIB" dev.frequency.guardian.CrossChecksKt
PYTHONDONTWRITEBYTECODE=1 python3 ../../scripts/guardian_crosscheck.py verify

java -cp "$FG_TEST_OUT/checks.jar:$FG_STDLIB" dev.frequency.guardian.OnlineChecksKt
