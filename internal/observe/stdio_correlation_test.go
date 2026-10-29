package observe

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Run a real child through InspectStdio so approval, framing and cleanup are
// exercised together. The marker is an approved argument, not inherited env.
func TestStdioCorrelationFixture(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "stdio-correlation-fixture" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var request struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if decoder.Decode(&request) != nil {
			os.Exit(0)
		}
		if request.ID == 0 {
			continue
		}
		if request.Method == "initialize" {
			_ = encoder.Encode(map[string]any{"id": request.ID, "result": map[string]any{
				"protocolVersion": LegacyProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
			}})
			continue
		}
		if mode == "timeout" {
			// Bound even a broken implementation which ignores the deadline.
			time.Sleep(3 * time.Second)
			os.Exit(0)
		}
		id := request.ID
		if mode == "stale" {
			id-- // Replay the initialization ID during tools/list.
		}
		_ = encoder.Encode(map[string]any{"id": id, "result": map[string]any{"tools": []any{}}})
	}
}

func TestStdioReadbackCorrelationAndDeadline(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPDRIFT_STDIO_ALLOWED_EXEC", binary)
	t.Setenv("MCPDRIFT_STDIO_SANDBOX", "")
	for _, mode := range []string{"matching", "stale", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"-test.run=^TestStdioCorrelationFixture$", "--", "stdio-correlation-fixture", mode}
			approved, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("MCPDRIFT_STDIO_ALLOWED_ARGS_JSON", string(approved))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			snapshot, err := InspectStdio(ctx, binary, args)
			switch mode {
			case "matching":
				if err != nil || snapshot.Server.ProtocolVersion != LegacyProtocolVersion {
					t.Fatalf("matching response failed: %v, %+v", err, snapshot)
				}
			case "stale":
				if err == nil || !strings.Contains(err.Error(), "response ID mismatch") {
					t.Fatalf("stale readback must fail on correlation: %v", err)
				}
			case "timeout":
				if err == nil || ctx.Err() != context.DeadlineExceeded {
					t.Fatalf("readback must fail at parent deadline: %v (context %v)", err, ctx.Err())
				}
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("readback exceeded deadline cleanup bound: %s", elapsed)
				}
			}
		})
	}
}
