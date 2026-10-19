package observe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

const stdioMaxLine = 4 << 20

// InspectStdio launches one explicitly approved local executable, without a shell.
// Stdout is reserved for MCP JSON-RPC framing. The process is always terminated.
func InspectStdio(parent context.Context, binary string, args []string) (snapshot canonical.Snapshot, err error) {
	allowed := os.Getenv("MCPDRIFT_STDIO_ALLOWED_EXEC")
	if allowed == "" {
		return snapshot, errors.New("stdio executable not approved: set MCPDRIFT_STDIO_ALLOWED_EXEC to its absolute path")
	}
	approved, e := filepath.EvalSymlinks(allowed)
	if e != nil {
		return snapshot, fmt.Errorf("resolve approved executable: %w", e)
	}
	target, e := filepath.EvalSymlinks(binary)
	if e != nil {
		return snapshot, fmt.Errorf("resolve executable: %w", e)
	}
	if !filepath.IsAbs(binary) || !filepath.IsAbs(allowed) || approved != target {
		return snapshot, errors.New("stdio executable does not match approved absolute path")
	}
	if info, e := os.Stat(target); e != nil || info.IsDir() {
		return snapshot, errors.New("approved executable is not a regular executable file")
	}
	// Interpreter executables can run arbitrary scripts through their arguments.
	// Authorize the complete argv independently of model-provided CLI parameters.
	allowedArgJSON := os.Getenv("MCPDRIFT_STDIO_ALLOWED_ARGS_JSON")
	if allowedArgJSON == "" {
		if len(args) != 0 {
			return snapshot, errors.New("stdio arguments require explicit MCPDRIFT_STDIO_ALLOWED_ARGS_JSON authorization")
		}
	} else {
		var allowedArgs []string
		if e := json.Unmarshal([]byte(allowedArgJSON), &allowedArgs); e != nil {
			return snapshot, fmt.Errorf("invalid approved stdio argv: %w", e)
		}
		if len(args) != len(allowedArgs) {
			return snapshot, errors.New("stdio arguments differ from approved argv")
		}
		for i := range args {
			if args[i] != allowedArgs[i] {
				return snapshot, errors.New("stdio arguments differ from approved argv")
			}
		}
	}
	// The entire argument vector belongs to the trusted caller; never pass model-generated argv.
	fingerprint := sha256.Sum256([]byte(target + "\x00" + strings.Join(args, "\x00")))
	identity := "stdio://" + hex.EncodeToString(fingerprint[:])
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	launch, launchArgs, sandboxErr := stdioSandboxCommand(target, args)
	if sandboxErr != nil {
		return snapshot, sandboxErr
	}
	cmd := exec.CommandContext(ctx, launch, launchArgs...)
	configureStdioProcess(cmd)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.Stderr = io.Discard
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return snapshot, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return snapshot, e
	}
	if e = cmd.Start(); e != nil {
		return snapshot, e
	}
	// A descendant may inherit stdout after the parent exits. Terminate the
	// process group at deadline independently of the blocking scanner.
	stopTimeoutKill := context.AfterFunc(ctx, func() { terminateStdioProcess(cmd) })
	defer stopTimeoutKill()
	defer func() {
		_ = stdin.Close()
		terminateStdioProcess(cmd)
		_ = cmd.Wait()
	}()
	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 65536), stdioMaxLine)
	send := func(v any) error {
		data, e := json.Marshal(v)
		if e != nil {
			return e
		}
		data = append(data, '\n')
		_, e = stdin.Write(data)
		return e
	}
	read := func(id int) (json.RawMessage, error) {
		for i := 0; i < 32; i++ {
			if !reader.Scan() {
				if e := reader.Err(); e != nil {
					return nil, fmt.Errorf("stdio response: %w", e)
				}
				return nil, errors.New("stdio endpoint closed before response")
			}
			line := reader.Bytes()
			var response struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if e = json.Unmarshal(line, &response); e != nil {
				return nil, fmt.Errorf("invalid stdio JSON-RPC: %w", e)
			}
			if response.ID == nil {
				continue
			}
			if *response.ID != id {
				return nil, errors.New("stdio JSON-RPC response ID mismatch")
			}
			if response.Error != nil {
				return nil, fmt.Errorf("stdio RPC error %d: %s", response.Error.Code, response.Error.Message)
			}
			if len(response.Result) == 0 {
				return nil, errors.New("stdio RPC missing result")
			}
			return response.Result, nil
		}
		return nil, errors.New("too many unsolicited stdio notifications")
	}
	rpc := func(id int, method string, params any) (json.RawMessage, error) {
		if e := send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); e != nil {
			return nil, e
		}
		return read(id)
	}
	init, e := rpc(1, "initialize", map[string]any{"protocolVersion": LegacyProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "mcpdrift", "version": "0.1.0"}})
	if e != nil {
		return snapshot, e
	}
	var handshake struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if e = json.Unmarshal(init, &handshake); e != nil {
		return snapshot, e
	}
	if handshake.ProtocolVersion == "" {
		return snapshot, errors.New("stdio init missing protocol version")
	}
	if e = send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); e != nil {
		return snapshot, e
	}
	snapshot = canonical.Snapshot{Format: "mcpdrift-snapshot/v1", ObservedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: identity, Transport: canonical.Transport{Scheme: "stdio"}, Server: canonical.Server{Name: handshake.ServerInfo.Name, Version: handshake.ServerInfo.Version, ProtocolVersion: handshake.ProtocolVersion, SupportedVersions: []string{handshake.ProtocolVersion}}, Capabilities: handshake.Capabilities}
	id := 2
	for _, category := range []string{"tools", "resources", "prompts"} {
		if _, ok := handshake.Capabilities[category]; !ok {
			continue
		}
		cursor := ""
		seen := map[string]bool{}
		completed := false
		for page := 0; page < maxPages; page++ {
			params := map[string]string{}
			if cursor != "" {
				params["cursor"] = cursor
			}
			result, e := rpc(id, category+"/list", params)
			id++
			if e != nil {
				return snapshot, e
			}
			var contents struct {
				Tools      []canonical.Tool     `json:"tools"`
				Resources  []canonical.Resource `json:"resources"`
				Prompts    []canonical.Prompt   `json:"prompts"`
				NextCursor string               `json:"nextCursor"`
			}
			if e = json.Unmarshal(result, &contents); e != nil {
				return snapshot, e
			}
			// Advertised categories must return a corresponding JSON array,
			// even if empty. Missing/null inventory cannot prove a clean surface.
			var fields map[string]json.RawMessage
			if e = json.Unmarshal(result, &fields); e != nil {
				return snapshot, e
			}
			field := fields[category]
			if len(field) == 0 || field[0] != '[' {
				return snapshot, fmt.Errorf("stdio %s/list omitted required %s array", category, category)
			}
			snapshot.Tools = append(snapshot.Tools, contents.Tools...)
			snapshot.Resources = append(snapshot.Resources, contents.Resources...)
			snapshot.Prompts = append(snapshot.Prompts, contents.Prompts...)
			if contents.NextCursor == "" {
				completed = true
				break
			}
			if seen[contents.NextCursor] {
				return snapshot, errors.New("stdio repeated pagination cursor")
			}
			seen[contents.NextCursor] = true
			cursor = contents.NextCursor
		}
		if !completed {
			return snapshot, errors.New("stdio pagination exceeded limit")
		}
	}
	return snapshot, nil
}
