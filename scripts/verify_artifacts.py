#!/usr/bin/env python3
"""Verify release-candidate artifacts without authorizing a release."""
import hashlib
import json
import pathlib
import subprocess
import sys

PLATFORMS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64")

def verify(root):
    root = pathlib.Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != "mcpdrift-artifacts/v1":
        raise ValueError("invalid artifact manifest schema")
    if manifest.get("release_authorized") is not False:
        raise ValueError("release authorization must remain false")
    if set(manifest.get("artifacts", {})) != set(PLATFORMS):
        raise ValueError("unexpected platform set")
    for platform, expected in manifest["artifacts"].items():
        suffix = ".exe" if platform.startswith("windows-") else ""
        name = "mcpdrift-" + platform + suffix
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("artifact missing or symlinked: " + name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected.get("filename") != name or expected.get("sha256") != digest or expected.get("size") != path.stat().st_size:
            raise ValueError("artifact integrity mismatch: " + name)
    return manifest

if __name__ == "__main__":
    try:
        print(json.dumps({"verdict": "ARTIFACT_BYTES_VERIFIED_NOT_RELEASE_AUTHORIZED", "commit": verify(sys.argv[1])["commit"]}))
    except (OSError, ValueError, IndexError, json.JSONDecodeError) as exc:
        print("ARTIFACT_VERIFY_FAIL:", exc, file=sys.stderr)
        sys.exit(1)
