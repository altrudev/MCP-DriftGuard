#!/usr/bin/env python3
"""Deterministic Go candidate builds, revision-bound checksum manifest."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
sys.dont_write_bytecode = True
from verify_artifacts import PLATFORMS, verify

root = pathlib.Path(__file__).resolve().parents[1]
out = pathlib.Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
artifacts = {}
for platform in PLATFORMS:
    goos, goarch = platform.split("-")
    name = "mcpdrift-" + platform + (".exe" if goos == "windows" else "")
    dest = out / name
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", str(dest), "./cmd/mcpdrift"], cwd=root, env=env, check=True)
    data = dest.read_bytes()
    artifacts[platform] = {"filename": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
manifest = {"schema": "mcpdrift-artifacts/v1", "commit": commit, "release_authorized": False, "artifacts": artifacts}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
verify(out)
print("candidate artifacts verified for", commit)
