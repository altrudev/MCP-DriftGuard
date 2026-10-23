#!/usr/bin/env python3
"""Real official-SDK client against the Go stdio server and synthetic target.
No credentials, network targets, baseline approval, or external host configuration.
Run directly; requires Go 1.26 for the isolated SDK client, Go 1.23 for core.
Set TMPDIR=/dev/shm/... to keep all build/runtime outputs in memory.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="driftguard-sdk-") as td:
        root = Path(td)
        binary, client, fixture = root / "mcpdrift", root / "client", root / "fixture.py"
        baseline = root / "approved.json"
        def run(args, **kwargs):
            return subprocess.run(list(map(str, args)), cwd=ROOT, check=True,
                                  text=True, capture_output=True, timeout=120, **kwargs)
        run(["go", "build", "-o", binary, "./cmd/mcpdrift"])
        run(["go", "-C", ROOT / "scripts/mcp-sdk-client", "build", "-mod=readonly", "-o", client, "."])
        shutil.copyfile(ROOT / "examples/stdio-fixture/server.py", fixture)
        fixture.chmod(0o700)
        env = dict(os.environ, MCPDRIFT_STDIO_ALLOWED_EXEC=str(fixture))
        run([binary, "baseline", "--stdio-exec", fixture, "--output", baseline, "stdio"], env=env)
        print(run([client, binary, fixture, baseline], env=env).stdout, end="")


if __name__ == "__main__":
    main()
