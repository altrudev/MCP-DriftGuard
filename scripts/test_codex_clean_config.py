#!/usr/bin/env python3
"""Codex host-side MCP registration smoke; does not invoke an AI agent."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

def main():
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
        # Optional exact operator configuration; registration never approves a baseline.
        command = json.loads(os.environ.get("MCPDRIFT_CODEX_COMMAND_JSON", '["/usr/bin/true"]'))
        if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
            raise ValueError("MCPDRIFT_CODEX_COMMAND_JSON must be a nonempty string array")
        if not Path(command[0]).is_absolute():
            raise ValueError("Codex server executable must be absolute")
        run("add","driftguard-disposable", "--", *command)
        config = json.loads(run("get","--json","driftguard-disposable"))
        transport = config.get("transport", config)
        if transport.get("command") != command[0] or transport.get("args", []) != command[1:]:
            raise RuntimeError("registered command differs from intended executable")
        if config.get("enabled") is not True:
            raise RuntimeError("registered MCP server is not enabled")
        if "driftguard-disposable" not in run("list"):
            raise RuntimeError("registered server missing from listing")
        run("remove","driftguard-disposable")
        if "No MCP servers configured" not in run("list"):
            raise RuntimeError("Codex cleanup did not restore empty home")
    print(json.dumps({"registered_executable": command[0],
                      "arguments_sha256": hashlib.sha256(json.dumps(command[1:]).encode()).hexdigest(),
                      "enabled": True, "isolated_home_removed": not home.exists()}))
    print("PASS: clean Codex MCP registration, inspect, removal; agent execution NOT TESTED")


if __name__ == "__main__":
    main()
