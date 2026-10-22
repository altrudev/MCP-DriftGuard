#!/usr/bin/env python3
"""Disposable end-to-end stdio MCP acceptance. Never launches arbitrary user executables."""
import json
import os
import platform
import time
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def call(args, env=None, cwd=None, timeout=35):
    return subprocess.run(list(map(str,args)),cwd=cwd or ROOT,env=env,text=True,
                          capture_output=True,timeout=timeout)

def main():
    results={}
    with tempfile.TemporaryDirectory(prefix="mcpdrift-stdio-") as td:
        t=Path(td); exe=t/"mcpdrift"; fixture=t/"server.py"
        build=call(["go","build","-o",exe,"./cmd/mcpdrift"])
        if build.returncode:raise RuntimeError(build.stderr)
        shutil.copyfile(ROOT/"examples/stdio-fixture/server.py",fixture)
        fixture.chmod(0o700)
        env=os.environ.copy();env.pop("MCPDRIFT_FIXTURE_DRIFT",None);env.pop("MCPDRIFT_STDIO_ALLOWED_ARGS_JSON",None)
        env["MCPDRIFT_STDIO_ALLOWED_EXEC"]=str(fixture)
        common=["--stdio-exec",fixture]
        baseline=t/"approved.json"
        r=call([exe,"inspect",*common,"--format","json","stdio"],env)
        results["inspect"]=r.returncode
        if r.returncode==0:
            snap=json.loads(r.stdout)
            results["inventory"]=tuple(len(snap[x]) for x in ("tools","resources","prompts"))==(1,1,1)
        r=call([exe,"baseline",*common,"--output",baseline,"stdio"],env)
        results["baseline"]=r.returncode
        if r.returncode != 0 or not baseline.is_file():
            results["baseline_file_present"]=False
            print(json.dumps(results,indent=2,sort_keys=True))
            return 1
        results["baseline_file_present"]=True
        before=baseline.read_bytes()
        r=call([exe,"verify",*common,"--baseline",baseline,"stdio"],env)
        results["unchanged"]=r.returncode
        (t/"drift.enabled").touch()
        r=call([exe,"verify",*common,"--baseline",baseline,"stdio"],env)
        results["drift"]=r.returncode
        results["detected_added_tool"]="export_customer_database" in r.stdout
        (t/"drift.enabled").unlink()
        env2=dict(env);env2["MCPDRIFT_STDIO_ALLOWED_EXEC"]=str(t/"unapproved")
        r=call([exe,"inspect",*common,"stdio"],env2)
        results["unapproved_executable"]=r.returncode
        r=call([exe,"inspect","--stdio-exec",fixture,"--stdio-args-json","not-json","stdio"],env)
        results["bad_args"]=r.returncode
        for mode in ("--malformed","--wrong-id","--repeated-cursor","--missing-inventory"):
            authorized_env=dict(env); authorized_env["MCPDRIFT_STDIO_ALLOWED_ARGS_JSON"]=json.dumps([mode])
            r=call([exe,"inspect",*common,"--stdio-args-json",json.dumps([mode]),"stdio"],authorized_env)
            results[mode]=r.returncode
        secret_env=dict(env);secret_env["MCPDRIFT_BEARER_TOKEN"]="synthetic-stdio-secret"
        secret_env["MCPDRIFT_STDIO_ALLOWED_ARGS_JSON"]=json.dumps(["--env-probe"])
        r=call([exe,"inspect",*common,"--stdio-args-json",json.dumps(["--env-probe"]),"--format","json","stdio"],secret_env)
        results["env_secret_isolated"]=r.returncode==0 and "credential-leaked" not in r.stdout and "synthetic-stdio-secret" not in r.stdout
        r=call([exe,"inspect",*common,"--stdio-args-json",json.dumps(["--malformed"]),"stdio"],env)
        results["unapproved_args"]=r.returncode
        if platform.system()=="Linux":
            child_env=dict(env)
            child_env["MCPDRIFT_STDIO_ALLOWED_ARGS_JSON"]=json.dumps(["--hang-with-child"])
            began=time.monotonic()
            r=call([exe,"inspect",*common,"--stdio-args-json",'["--hang-with-child"]',"stdio"],child_env,timeout=35)
            elapsed=time.monotonic()-began
            pid_file=t/"spawned.pid"
            pid=int(pid_file.read_text()) if pid_file.exists() else None
            time.sleep(0.15)
            live=False
            if pid is not None:
                stat=Path("/proc")/str(pid)/"stat"
                if stat.exists():
                    state=stat.read_text().rsplit(") ",1)[-1].split(" ",1)[0]
                    live=state not in ("Z","X")
            results["linux_descendant_killed"]=r.returncode==3 and pid is not None and not live and 18<=elapsed<30
        results["baseline_unchanged"]=baseline.read_bytes()==before
    expected={"inspect":0,"inventory":True,"baseline":0,"unchanged":0,"drift":2,
              "detected_added_tool":True,"unapproved_executable":3,"bad_args":3,
              "baseline_unchanged":True,"baseline_file_present":True,
              "--malformed":3,"--wrong-id":3,"--repeated-cursor":3,"--missing-inventory":3,
              "env_secret_isolated":True,"unapproved_args":3}
    if platform.system()=="Linux":expected["linux_descendant_killed"]=True
    results["pass"]=all(results.get(k)==v for k,v in expected.items())
    print(json.dumps(results,indent=2,sort_keys=True))
    return 0 if results["pass"] else 1

if __name__=="__main__":raise SystemExit(main())
