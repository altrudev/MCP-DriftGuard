# Fresh-clone stdio reference-server evidence

Source: 51b5573aac1045bd2be6bb7911f9a755df388b8e.
Environment: isolated Ubuntu VPS clone, Go toolchain, npm-installed @modelcontextprotocol/server-everything@2.0.0.
Procedure: go test ./...; python3 scripts/conformance_suite.py --output conformance.json; build ./cmd/mcpdrift; inspect, baseline, verify with exactly allowlisted server-everything dist/index.js executable in a disposable path.
Observations: 16 tools; 16/16 input schemas; 16/16 annotations; baseline and unchanged verification PASS. No tool execution or production credentials.
Scope: self-operated reference-server interoperability. Not third-party independent reproduction, certification, or proof of live server mutation detection. For synthetic mutation proof, see internal/observe/stdio_schema_test.go.
