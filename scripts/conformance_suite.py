#!/usr/bin/env python3
"""Versioned offline acceptance runner for DriftGuard. No hosted models or customer endpoints."""
import argparse, hashlib, json, platform, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SUITES=[
 ("local_notifications",[sys.executable,"-m","unittest","discover","-s","scripts","-p","test_local_notifications.py"]),
 ("production_monitor",[sys.executable,"-m","unittest","discover","-s","scripts","-p","test_production_monitor.py"]),
 ("go_unit",["go","test","./..."]),
 ("go_race",["go","test","-race","./..."]),
 ("go_vet",["go","vet","./..."]),
 ("docs", [sys.executable,"scripts/check_docs.py"]),
 ("http_acceptance",[sys.executable,"skills/mcp-driftguard/test_agent_skill.py"]),
 ("stdio_acceptance",[sys.executable,"skills/mcp-driftguard/test_stdio_transport.py"]),
 ("extreme_limits",[sys.executable,"scripts/extreme_limits.py","--sizes","10,100,1000,10000"]),
]
def run(cmd):
    try:
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=120)
        return {"exit":p.returncode,"stdout_sha256":hashlib.sha256(p.stdout.encode()).hexdigest(),
                "stderr_sha256":hashlib.sha256(p.stderr.encode()).hexdigest(),
                "stdout_tail":p.stdout[-900:],"stderr_tail":p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        return {"exit":124,"error":"bounded suite timed out"}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",help="write sanitized JSON evidence to this path")
    args=ap.parse_args()
    commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()
    report={"format":"mcpdrift-conformance-evidence/v1","commit":commit,
            "platform":platform.system(),"arch":platform.machine(),
            "timestamp_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "limitations":["Local tests are not formal certification",
                           "Federation external rerun remains independently controlled",
                           "Agent-host integration and Windows/macOS native executions not established"],
            "suites":{}}
    for label,cmd in SUITES:
        result=run(cmd)
        report["suites"][label]=result
        print(label,"PASS" if result["exit"]==0 else "FAIL",flush=True)
    report["passed"]=all(x["exit"]==0 for x in report["suites"].values())
    payload=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if args.output:
        Path(args.output).write_text(payload)
    else:
        print(payload)
    return 0 if report["passed"] else 1

if __name__=="__main__":raise SystemExit(main())
