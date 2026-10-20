#!/usr/bin/env python3
"""Codex host-side MCP registration smoke; does not invoke an AI agent."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

codex = os.getenv("MCPDRIFT_CODEX_BIN") or shutil.which("codex")
if not codex:
    print("BLOCKED: Codex CLI unavailable; clean-host gate not run")
    sys.exit(2)
with tempfile.TemporaryDirectory(prefix="mcpdrift-codex-clean-") as root:
    home = Path(root) / "codex-home"
    home.mkdir()
    env = dict(os.environ, CODEX_HOME=str(home))
    def run(*args):
        result = subprocess.run([codex,"mcp",*args],capture_output=True,text=True,env=env,timeout=20)
        if result.returncode:
            raise RuntimeError("Codex local MCP configuration operation failed: " + result.stderr[:300])
        return result.stdout
    empty = run("list")
    if "No MCP servers configured" not in empty:
        raise RuntimeError("Codex test home not clean")
    run("add","driftguard-disposable", "--", "/usr/bin/true")
    config = json.loads(run("get","--json","driftguard-disposable"))
    if config.get("transport",{}).get("command") != "/usr/bin/true" and config.get("command") != "/usr/bin/true":
        raise RuntimeError("registered command differs from intended executable")
    if "driftguard-disposable" not in run("list"):
        raise RuntimeError("registered server missing from listing")
    run("remove","driftguard-disposable")
    if "No MCP servers configured" not in run("list"):
        raise RuntimeError("Codex cleanup did not restore empty home")
print("PASS: clean Codex MCP registration, inspect, removal; agent execution NOT TESTED")
