// Independent official-SDK stdio acceptance client. Synthetic fixture only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if len(os.Args) != 5 {
		panic("usage: client BINARY FIXTURE APPROVED_BASELINE TRUSTED_PUBLIC_KEY")
	}
	binary, fixture, baseline := os.Args[1], os.Args[2], os.Args[3]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.Command(binary, "serve", "--endpoint", "stdio", "--stdio-exec", fixture, "--baseline", baseline, "--verify-key", os.Args[4])
	cmd.Env = append(os.Environ(), "MCPDRIFT_STDIO_ALLOWED_EXEC="+fixture)
	session, err := mcp.NewClient(&mcp.Implementation{Name: "driftguard-independent-acceptance", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	check(err)
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	check(err)
	if len(tools.Tools) != 2 {
		panic("tool inventory")
	}
	resources, err := session.ListResources(ctx, nil)
	check(err)
	if len(resources.Resources) != 1 {
		panic("resource inventory")
	}
	_, err = session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "driftguard://policy"})
	check(err)
	prompts, err := session.ListPrompts(ctx, nil)
	check(err)
	if len(prompts.Prompts) != 1 {
		panic("prompt inventory")
	}
	_, err = session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "review_drift"})
	check(err)
	inspect, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "driftguard_inspect", Arguments: map[string]any{}})
	check(err)
	if inspect.IsError {
		panic("inspect failed")
	}
	verify := func(wantMatch bool) {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "driftguard_verify", Arguments: map[string]any{}})
		check(err)
		if result.IsError || len(result.Content) != 1 {
			panic("verify failed")
		}
		text, ok := result.Content[0].(*mcp.TextContent)
		if !ok {
			panic("nontext result")
		}
		var drift struct {
			Match bool `json:"match"`
			Score int  `json:"score"`
		}
		check(json.Unmarshal([]byte(text.Text), &drift))
		if drift.Match != wantMatch || (!wantMatch && (drift.Score < 35 || !strings.Contains(text.Text, "export_customer_database"))) {
			panic("wrong verdict: " + text.Text)
		}
	}
	verify(true)
	original, err := os.ReadFile(baseline)
	check(err)
	check(os.WriteFile(baseline, []byte("tampered on disk"), 0600))
	verify(true) // A running session must keep its independently validated artifact.
	check(os.WriteFile(baseline, original, 0600))
	marker := filepath.Join(filepath.Dir(fixture), "drift.enabled")
	check(os.WriteFile(marker, nil, 0600))
	defer os.Remove(marker)
	verify(false)
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "driftguard_verify", Arguments: map[string]any{"endpoint": "http://unapproved.invalid"}})
	if err == nil {
		panic("caller target override accepted")
	}
	check(os.Remove(marker))
	check(os.Rename(fixture, fixture+".unavailable"))
	defer os.Rename(fixture+".unavailable", fixture)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "driftguard_verify", Arguments: map[string]any{}})
	check(err)
	if !result.IsError {
		panic("probe failure became PASS")
	}
	fmt.Println(`{"sdk":"github.com/modelcontextprotocol/go-sdk v1.8.0","transport":"real stdio subprocess","tools":2,"resources":1,"prompts":1,"inspect":true,"unchanged_match":true,"drift_fail":true,"baseline_pinned":true,"target_override_rejected":true,"probe_error_inconclusive":true,"pass":true}`)
}
