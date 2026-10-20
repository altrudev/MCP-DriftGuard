# Codex clean configuration smoke — scope and limitation

Run `MCPDRIFT_CODEX_BIN=/absolute/path/to/codex python3 scripts/test_codex_clean_config.py` in an authorized test environment. The test creates a disposable `CODEX_HOME`, verifies an empty MCP registry, registers an inert local executable, reads back its configuration, and removes it. It does not invoke tools or models, connect to a server, or exercise a real Codex agent conversation. No personal Codex home or login is needed.

Result observed on the VPS, Codex CLI 0.163.0: **PASS** for the clean configuration registration/readback/removal smoke. This evidence establishes host configuration compatibility only. Real Codex agent read-only verification, prompt-injection boundaries, Claude Code, and Cursor remain **UNVERIFIED**. Release remains unauthorized.
