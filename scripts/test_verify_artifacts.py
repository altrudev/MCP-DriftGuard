#!/usr/bin/env python3
"""Mutation checks for candidate artifact manifest validation."""
import json
import pathlib
import sys
import tempfile
sys.dont_write_bytecode = True
from verify_artifacts import PLATFORMS, verify
import hashlib

with tempfile.TemporaryDirectory(prefix="mcpdrift-artifact-mutations-") as td:
    root=pathlib.Path(td)
    artifacts={}
    for platform in PLATFORMS:
        name="mcpdrift-"+platform+(".exe" if platform.startswith("windows-") else "")
        data=(platform+"-synthetic-test-only").encode()
        (root/name).write_bytes(data)
        artifacts[platform]={"filename":name,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
    manifest={"schema":"mcpdrift-artifacts/v1","commit":"test-revision","release_authorized":False,"artifacts":artifacts}
    def write(): (root/"manifest.json").write_text(json.dumps(manifest))
    write();verify(root)
    victim=root/artifacts["linux-amd64"]["filename"]
    victim.write_bytes(b"tampered")
    try: verify(root);raise AssertionError("tampered bytes accepted")
    except ValueError: pass
    data=b"linux-amd64-synthetic-test-only";victim.write_bytes(data)
    manifest["release_authorized"]=True;write()
    try: verify(root);raise AssertionError("unauthorized release accepted")
    except ValueError: pass
    manifest["release_authorized"]=False;del manifest["artifacts"]["darwin-arm64"];write()
    try: verify(root);raise AssertionError("missing platform accepted")
    except ValueError: pass
print("artifact mutation tests PASS")
