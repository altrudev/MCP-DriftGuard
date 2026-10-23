import json
import unittest
from unittest.mock import patch

from probe_local_mcp import discover, validate_endpoint


class LocalProbeTests(unittest.TestCase):
    def test_rejects_remote_and_credential_destinations(self):
        for url in ("https://127.0.0.1/mcp", "http://example.org/mcp",
                    "http://169.254.169.254/mcp", "http://user:secret@127.0.0.1/mcp",
                    "http://127.0.0.1/mcp?token=secret", "http://127.0.0.1/mcp#frag"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_endpoint(url)
        self.assertEqual(validate_endpoint("http://[::1]:8765/mcp"), "http://[::1]:8765/mcp")

    def run_discovery(self, repeat=False, wrong_id=False):
        calls = []

        class Response:
            headers = {}
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return json.dumps(self.body).encode()

        class Opener:
            def open(self, request, timeout):
                body = json.loads(request.data)
                calls.append(body["method"])
                if body["method"] == "initialize":
                    result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
                elif body["method"] == "notifications/initialized":
                    return Response({})
                else:
                    result = {"tools": [{"name": "read_only"}]}
                    if repeat:
                        result["nextCursor"] = "same"
                return Response({"jsonrpc": "2.0", "id": -1 if wrong_id else body["id"], "result": result})

        with patch("probe_local_mcp.urllib.request.build_opener", return_value=Opener()):
            result = discover("http://127.0.0.1:8765/mcp")
        return result, calls

    def test_only_discovery_no_tool_execution(self):
        result, calls = self.run_discovery()
        self.assertEqual(calls, ["initialize", "notifications/initialized", "tools/list"])
        self.assertEqual(result["tools"], [{"name": "read_only"}])
        self.assertEqual(result["resources"], [])

    def test_cursor_loop_is_inconclusive(self):
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.run_discovery(repeat=True)

    def test_wrong_id_is_inconclusive(self):
        with self.assertRaisesRegex(ValueError, "RPC"):
            self.run_discovery(wrong_id=True)


if __name__ == "__main__":
    unittest.main()
