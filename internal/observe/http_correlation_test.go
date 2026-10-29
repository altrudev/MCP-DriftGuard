package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type correlationTransport func(*http.Request) (*http.Response, error)

func (f correlationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPResponseCorrelation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		protocol := "modern"
		if legacy {
			protocol = "legacy"
		}
		for _, contentType := range []string{"application/json", "text/event-stream"} {
			for _, stage := range []string{"handshake", "tools/list", "resources/list", "prompts/list", "tools/page2"} {
				for _, responseError := range []bool{false, true} {
					for _, idCase := range []string{"matching", "wrong", "replayed", "missing", "null", "string", "boolean", "fraction", "object", "array", "overflow"} {
						name := fmt.Sprintf("%s/%s/%s/error=%t/%s", protocol, contentType, stage, responseError, idCase)
						t.Run(name, func(t *testing.T) {
							rejected, reached := false, false
							client := &Client{HTTP: &http.Client{Transport: correlationTransport(func(r *http.Request) (*http.Response, error) {
								if rejected {
									t.Error("inspection continued after uncorrelated response")
								}
								reply := func(status int, body string) (*http.Response, error) {
									if contentType == "text/event-stream" {
										body = "data: " + body + "\n\n"
									}
									return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body)), Proto: "HTTP/1.1"}, nil
								}
								if r.Method != http.MethodPost {
									return reply(http.StatusNotFound, "{}")
								}
								var req struct {
									ID     int            `json:"id"`
									Method string         `json:"method"`
									Params map[string]any `json:"params"`
								}
								if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
									t.Fatal(err)
								}
								if legacy && req.Method == "server/discover" {
									return reply(http.StatusNotFound, "{}")
								}
								if req.Method == "notifications/initialized" {
									return reply(http.StatusAccepted, "")
								}
								handshake := req.Method == "server/discover" || req.Method == "initialize"
								target := stage == "handshake" && handshake || stage == req.Method || stage == "tools/page2" && req.Method == "tools/list" && req.Params["cursor"] == "p2"
								result := map[string]any{}
								if handshake {
									result = map[string]any{"supportedVersions": []string{ModernProtocolVersion}, "protocolVersion": LegacyProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}}}
								} else {
									category := strings.TrimSuffix(req.Method, "/list")
									result[category] = []any{map[string]any{"name": "accepted", "uri": "test://accepted", "inputSchema": map[string]any{"type": "object"}}}
									if stage == "tools/page2" && req.Method == "tools/list" && req.Params["cursor"] == nil {
										result["nextCursor"] = "p2"
									}
								}
								envelope := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
								if target {
									reached = true
									if responseError {
										delete(envelope, "result")
										envelope["error"] = map[string]any{"code": -32601, "message": "Method not found"}
									}
									switch idCase {
									case "wrong":
										envelope["id"] = 999
									case "replayed":
										envelope["id"] = req.ID - 1
									case "missing":
										delete(envelope, "id")
									case "null":
										envelope["id"] = nil
									case "string":
										envelope["id"] = fmt.Sprint(req.ID)
									case "boolean":
										envelope["id"] = true
									case "fraction":
										envelope["id"] = float64(req.ID) + 0.5
									case "object":
										envelope["id"] = map[string]any{}
									case "array":
										envelope["id"] = []int{req.ID}
									case "overflow":
										envelope["id"] = json.RawMessage("99999999999999999999999999999999999999")
									}
									rejected = idCase != "matching"
								}
								body, err := json.Marshal(envelope)
								if err != nil {
									t.Fatal(err)
								}
								return reply(http.StatusOK, string(body))
							})}}
							snapshot, err := client.Inspect(context.Background(), "http://fixture.invalid/mcp")
							if !reached {
								t.Fatal("target response was not exercised")
							}
							if idCase != "matching" {
								if err == nil || !strings.Contains(err.Error(), "response ID") {
									t.Fatalf("expected correlation rejection, got %v", err)
								}
								// A rejected page must never contribute inventory (prior valid pages may).
								if stage == "tools/list" && len(snapshot.Tools) != 0 || stage == "resources/list" && len(snapshot.Resources) != 0 || stage == "prompts/list" && len(snapshot.Prompts) != 0 || stage == "tools/page2" && len(snapshot.Tools) != 1 {
									t.Fatalf("uncorrelated inventory consumed: %#v", snapshot)
								}
							} else if !responseError && err != nil {
								t.Fatalf("matching response rejected: %v", err)
							}
						})
					}
				}
			}
		}
	}
}
