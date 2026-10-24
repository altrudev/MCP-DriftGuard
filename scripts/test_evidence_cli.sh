#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
go build -o "$tmp/mcpdrift" ./cmd/mcpdrift
"$tmp/mcpdrift" keygen --private "$tmp/key.pem" --public "$tmp/pub.pem" >/dev/null
printf '[{"id":"run-1","actor":"agent-a","receipt_meaning":"accepted","reconstruction_meaning":"retry-preserved"}]\n' >"$tmp/old.json"
printf '[{"id":"run-1","actor":"agent-a","receipt_meaning":"executed","reconstruction_meaning":"retry-preserved"}]\n' >"$tmp/new.json"
"$tmp/mcpdrift" evidence-sign --sign-key "$tmp/key.pem" --output "$tmp/old.sig.json" "$tmp/old.json" >/dev/null
"$tmp/mcpdrift" evidence-sign --sign-key "$tmp/key.pem" --output "$tmp/new.sig.json" "$tmp/new.json" >/dev/null
"$tmp/mcpdrift" evidence-diff --verify-key "$tmp/pub.pem" "$tmp/old.sig.json" "$tmp/old.sig.json" | grep '"match": true' >/dev/null
set +e
"$tmp/mcpdrift" evidence-diff --verify-key "$tmp/pub.pem" "$tmp/old.sig.json" "$tmp/new.sig.json" >"$tmp/diff.out"
status=$?
set -e
[[ $status == 2 ]] && grep 'receipt_meaning' "$tmp/diff.out" >/dev/null || exit 1
python3 - "$tmp/new.sig.json" <<'PY'
import json,sys
p=sys.argv[1];d=json.load(open(p));d['claims'][0]['receipt_meaning']='forged';json.dump(d,open(p,'w'))
PY
set +e
"$tmp/mcpdrift" evidence-diff --verify-key "$tmp/pub.pem" "$tmp/old.sig.json" "$tmp/new.sig.json" >/dev/null 2>&1
status=$?
set -e
[[ $status == 5 ]] || exit 1
printf 'Signed evidence CLI positive/drift/tamper checks PASS\n'
