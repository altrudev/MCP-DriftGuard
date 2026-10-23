#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./cached-kotlin.sh
mkdir -p app/build/host-tests
fg_kotlinc app/src/main/java/dev/frequency/guardian/Approval.kt app/src/main/java/dev/frequency/guardian/Diagnostics.kt tests/FixtureChecks.kt -jvm-target 17 -classpath "$FG_STDLIB" -d app/build/host-tests/checks.jar
java -cp "app/build/host-tests/checks.jar:$FG_STDLIB" dev.frequency.guardian.FixtureChecksKt

python3 - <<'PYTEST'
import json
with open("app/build/host-tests/report.json") as source:
    report = json.load(source)
assert len(report["checks"]) == 10
assert {item["status"] for item in report["checks"].values()} == {"pass", "fail", "pending"}
assert report["production_eligible"] is False
assert report["private_keys_exported"] is False
assert report["external_attestation_challenge_required"] is True
assert report["checks"]["update"]["detail"] == 'quote" newline\n slash\\'
print("PASS: independent JSON parser, ten checks, three statuses and escaped detail roundtrip")
PYTEST
