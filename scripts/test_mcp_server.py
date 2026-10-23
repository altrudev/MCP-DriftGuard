#!/usr/bin/env python3
"""Real official-SDK client against the Go stdio server and synthetic target.
No credentials, network targets, baseline approval, or external host configuration.
Run directly; requires Go 1.26 for the isolated SDK client, Go 1.23 for core.
Set TMPDIR to an operator-selected disk-backed temporary directory.
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
        binary = Path(os.environ.get("MCPDRIFT_TEST_BINARY", root / "mcpdrift")).resolve()
        client, fixture = root / "client", root / "fixture.py"
        baseline = root / "approved.json"
        private, public = root / "private.pem", root / "public.pem"
        def run(args, **kwargs):
            result = subprocess.run(list(map(str, args)), cwd=ROOT,
                                    text=True, capture_output=True, timeout=120, **kwargs)
            if result.returncode:
                raise RuntimeError(f"acceptance command failed ({result.returncode}): {args}\n{result.stderr[-4000:]}")
            return result
        if "MCPDRIFT_TEST_BINARY" not in os.environ:
            run(["go", "build", "-o", binary, "./cmd/mcpdrift"])
        elif not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("MCPDRIFT_TEST_BINARY must identify an existing executable")
        run(["go", "-C", ROOT / "scripts/mcp-sdk-client", "build", "-mod=readonly", "-o", client, "."])
        shutil.copyfile(ROOT / "examples/stdio-fixture/server.py", fixture)
        fixture.chmod(0o700)
        env = dict(os.environ, MCPDRIFT_STDIO_ALLOWED_EXEC=str(fixture))
        run([binary, "keygen", "--private", private, "--public", public])
        run([binary, "baseline", "--sign-key", private, "--stdio-exec", fixture, "--output", baseline, "stdio"], env=env)
        print(run([client, binary, fixture, baseline, public], env=env).stdout, end="")


if __name__ == "__main__":
    main()
