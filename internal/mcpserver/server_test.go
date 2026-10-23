package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLifecycleAndBoundaries(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":3,"method":"tools/list"}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"driftguard_verify","arguments":{"endpoint":"http://attacker"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"driftguard_verify","arguments":{}}}
{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"driftguard://policy"}}
{"jsonrpc":"2.0","id":7,"method":"prompts/get","params":{"name":"review_drift"}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"driftguard_inspect"}}
`
	calls := 0
	var out bytes.Buffer
	err := Serve(strings.NewReader(input), &out, "test", func(name string) (any, error) {
		calls++
		if name == "driftguard_inspect" {
			return nil, errors.New("secret-token")
		}
		return map[string]any{"match": false}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 8 || calls != 2 {
		t.Fatalf("responses=%d calls=%d %s", len(lines), calls, out.String())
	}
	var responses []map[string]any
	for _, line := range lines {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, r)
	}
	if responses[0]["error"] == nil || responses[3]["error"] == nil {
		t.Fatal("state and caller-controlled target must fail")
	}
	if strings.Contains(out.String(), "secret-token") {
		t.Fatal("backend errors leaked")
	}
	if !strings.Contains(lines[7], `"isError":true`) {
		t.Fatal("probe failure must be tool error")
	}
}

func TestInvalidEnvelopes(t *testing.T) {
	for _, input := range []string{`{`, `[]`, `{"jsonrpc":"1.0","id":1,"method":"ping"}`, `{"jsonrpc":"2.0","id":{},"method":"ping"}`} {
		var out bytes.Buffer
		if err := Serve(strings.NewReader(input+"\n"), &out, "test", nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"error"`) {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestOversizedFrameAndOutputFailure(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(strings.NewReader(strings.Repeat("x", (1<<20)+1)+"\n"), &out, "test", nil); err == nil {
		t.Fatal("oversized input accepted")
	}
	if err := Serve(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), brokenWriter{}, "test", nil); err == nil {
		t.Fatal("output failure ignored")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write(p []byte) (int, error) { return 0, errors.New("output closed") }

func TestNullInitializeIsInvalidParams(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":null}`+"\n"), &out, "test", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"code":-32602`) {
		t.Fatal(out.String())
	}
}
func TestInvalidParamsPing(t *testing.T) {
	var out bytes.Buffer
	if err := Serve(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}`+"\n"), &out, "test", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"code":-32602`) {
		t.Fatal(out.String())
	}
}

func TestActionableNotificationResult(t *testing.T) {
	for _, tc := range []struct {
		value  any
		err    error
		status string
	}{
		{map[string]any{"match": false}, nil, "drift"},
		{map[string]any{"match": true}, nil, "healthy"},
		{nil, errors.New("private"), "error"},
	} {
		input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"driftguard_verify","arguments":{}}}
`
		var out bytes.Buffer
		if err := Serve(strings.NewReader(input), &out, "test", func(string) (any, error) { return tc.value, tc.err }); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		var response struct {
			Result struct {
				StructuredContent struct {
					Notification struct {
						Status   string
						HostPush bool `json:"host_push"`
						Action   string
					}
				}
			}
		}
		if err := json.Unmarshal([]byte(lines[1]), &response); err != nil {
			t.Fatal(err)
		}
		n := response.Result.StructuredContent.Notification
		if n.Status != tc.status || n.HostPush || n.Action == "" {
			t.Fatalf("invalid notification: %+v", n)
		}
	}
}
