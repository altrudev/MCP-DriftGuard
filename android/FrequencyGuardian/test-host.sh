#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./cached-kotlin.sh
mkdir -p app/build/host-tests
fg_kotlinc app/src/main/java/dev/frequency/guardian/Approval.kt tests/FixtureChecks.kt -jvm-target 17 -classpath "$FG_STDLIB" -d app/build/host-tests/checks.jar
java -cp "app/build/host-tests/checks.jar:$FG_STDLIB" dev.frequency.guardian.FixtureChecksKt
