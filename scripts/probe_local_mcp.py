#!/usr/bin/env python3
"""Independent, bounded discovery of an operator-selected loopback HTTP MCP.

Never calls tools, follows redirects, uses credentials, or creates a baseline.
Evidence contains counts/hashes rather than proprietary inventory descriptions.
An inaccessible service is inconclusive and exits nonzero.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_endpoint(endpoint):
    url = urllib.parse.urlsplit(endpoint)
    if (url.scheme != "http" or url.username or url.password or url.fragment
            or url.query or not url.hostname
            or not ipaddress.ip_address(url.hostname).is_loopback):
        raise ValueError("explicit loopback HTTP address required, without credentials/query/fragment")
    return endpoint


def discover(endpoint):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    next_id = 0
    deadline = time.monotonic() + 30

    def rpc(method, params=None, notification=False):
        nonlocal next_id
        if time.monotonic() >= deadline:
            raise TimeoutError("discovery deadline")
        next_id += 1
        body = {"jsonrpc": "2.0", "method": method}
        if not notification:
            body["id"] = next_id
        if params is not None:
            body["params"] = params
        request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), headers=headers)
        with opener.open(request, timeout=min(5, max(.1, deadline-time.monotonic()))) as response:
            session = response.headers.get("Mcp-Session-Id")
            if session:
                headers["Mcp-Session-Id"] = session
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise ValueError("response exceeds 1 MiB")
            if notification:
                return None
            # This probe deliberately covers JSON responses, not SSE conformance.
            data = json.loads(raw)
            if data.get("jsonrpc") != "2.0" or data.get("id") != next_id or "error" in data:
                raise ValueError("invalid or failed RPC response")
            return data["result"]

    init = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                              "clientInfo": {"name": "independent-local-probe", "version": "1"}})
    headers["MCP-Protocol-Version"] = init["protocolVersion"]
    rpc("notifications/initialized", notification=True)
    inventories = {}
    for kind in ("tools", "resources", "prompts"):
        items, seen, cursor = [], set(), None
        if kind in init.get("capabilities", {}):
            for _ in range(100):
                result = rpc(kind + "/list", {"cursor": cursor} if cursor else {})
                page = result.get(kind)
                if not isinstance(page, list):
                    raise ValueError("missing inventory")
                items.extend(page)
                if len(items) > 10000:
                    raise ValueError("inventory limit")
                cursor = result.get("nextCursor")
                if not cursor:
                    break
                if not isinstance(cursor, str) or cursor in seen:
                    raise ValueError("invalid/repeated cursor")
                seen.add(cursor)
            else:
                raise ValueError("pagination limit")
        inventories[kind] = items
    return inventories


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, type=validate_endpoint)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    report = {"format": "mcpdrift-local-discovery/v1", "endpoint": args.endpoint,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "baseline_approved": False, "monitoring_enabled": False,
              "limitations": ["JSON HTTP discovery only", "inventory agreement is not baseline approval"]}
    try:
        inventories = discover(args.endpoint)
        report["independent_discovery"] = "PASS"
    except Exception as exc:
        inventories = None
        report["independent_discovery"] = "INCONCLUSIVE"
        report["independent_error_type"] = type(exc).__name__
        report["independent_errno"] = getattr(getattr(exc, "reason", exc), "errno", None)
    try:
        result = subprocess.run([str(binary), "inspect", "--format", "json", args.endpoint],
                                capture_output=True, timeout=40,
                                env={"PATH": os.defpath, "LANG": "C.UTF-8"})
        report["inspector_exit"] = result.returncode
        report["inspector_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        snapshot = json.loads(result.stdout) if result.returncode == 0 else None
        report["inspector"] = "PASS" if snapshot is not None else "INCONCLUSIVE"
        if inventories is not None and snapshot is not None:
            agreement = True
            report["inventories"] = {}
            for kind, items in inventories.items():
                key = "uri" if kind == "resources" else "name"
                names = sorted(x[key] for x in items)
                same = names == sorted(x[key] for x in snapshot.get(kind, []))
                agreement &= same
                report["inventories"][kind] = {"count": len(names), "names_match": same,
                    "names_sha256": hashlib.sha256(json.dumps(names).encode()).hexdigest()}
            report["inventory_agreement"] = agreement
    except Exception as exc:
        report["inspector"] = "INCONCLUSIVE"
        report["inspector_error_type"] = type(exc).__name__
    report["passed"] = report.get("inventory_agreement", False)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
