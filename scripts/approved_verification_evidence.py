#!/usr/bin/env python3
"""Trusted operator-side MCP verification; Codex only reads resulting evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True)
    ap.add_argument('--endpoint', required=True)
    ap.add_argument('--approved-endpoint', required=True)
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    parsed = urlsplit(args.endpoint)
    if args.endpoint != args.approved_endpoint or parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password or parsed.fragment:
        ap.error('endpoint must exactly match an explicitly approved loopback target')
    binary = Path(args.binary).resolve(strict=True)
    baseline = Path(args.baseline).resolve(strict=True)
    output = Path(args.output).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK) or not baseline.is_file() or output.exists() or output.is_symlink():
        ap.error('invalid binary/baseline or output already exists')
    digest_before = hashlib.sha256(baseline.read_bytes()).hexdigest()
    command = [str(binary), 'verify', '--baseline', str(baseline), '--format', 'json', args.endpoint]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False, env={'PATH':'/usr/bin:/bin'})
        verdict = {0:'PASS',1:'REVIEW',2:'FAIL',3:'INCONCLUSIVE',4:'BASELINE_ERROR',5:'INTEGRITY_FAILURE'}.get(result.returncode,'UNEXPECTED_EXIT')
        data = json.loads(result.stdout) if result.stdout.strip() else None
        if not isinstance(data, dict):
            verdict = 'INCONCLUSIVE'
        if result.returncode in (0, 1, 2) and (not isinstance(data, dict) or data.get('match') is not (result.returncode == 0)):
            verdict = 'INCONCLUSIVE'
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        verdict, data, result = 'INCONCLUSIVE', None, None
    digest_after = hashlib.sha256(baseline.read_bytes()).hexdigest()
    if digest_before != digest_after:
        raise RuntimeError('baseline changed during verification; evidence refused')
    payload = {'schema':'mcpdrift-operator-evidence/v1','endpoint':args.endpoint,'baseline_sha256':digest_before,'baseline_path':str(baseline),'verifier_binary':str(binary),'verdict':verdict,'exit_code':result.returncode if result else None,'result':data,'error_class':('VERIFIER_ERROR' if result and result.returncode not in (0,1,2) else 'NONE') if result else 'TIMEOUT_OR_MALFORMED_JSON','authorization':'operator-supplied exact loopback target','baseline_modified':False}
    fd = os.open(output, os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(payload,f,indent=2,sort_keys=True)
        f.write('\n')
    print(json.dumps({'verdict':verdict,'evidence':str(output),'baseline_sha256':digest_before}))
    return 0 if verdict in ('PASS','REVIEW','FAIL') else 1

if __name__=='__main__':
    sys.exit(main())
