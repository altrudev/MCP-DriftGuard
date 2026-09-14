package observe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModernDiscoveryAndPagination(t *testing.T) {
	var toolPages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("MCP-Protocol-Version") != ModernProtocolVersion {
			t.Errorf("missing modern protocol version")
		}
		if r.Header.Get("Mcp-Method") != req.Method {
			t.Errorf("Mcp-Method mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "server/discover":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"supportedVersions": []string{ModernProtocolVersion},
					"capabilities":      map[string]any{"tools": map[string]any{}},
					"_meta": map[string]any{
						"io.modelcontextprotocol/serverInfo": map[string]any{"name": "fixture", "version": "1"},
					},
				},
			})
		case "tools/list":
			toolPages++
			cursor, _ := req.Params["cursor"].(string)
			if cursor == "" {
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": 2,
					"result": map[string]any{
						"tools":      []any{map[string]any{"name": "read", "inputSchema": map[string]any{"type": "object"}}},
						"nextCursor": "p2",
					},
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": 3,
					"result": map[string]any{
						"tools": []any{map[string]any{"name": "write", "inputSchema": map[string]any{"type": "object"}}},
					},
				})
			}
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer srv.Close()

	s, err := New().Inspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if s.Server.ProtocolVersion != ModernProtocolVersion {
		t.Fatalf("version=%q", s.Server.ProtocolVersion)
	}
	if s.Server.Name != "fixture" {
		t.Fatalf("name=%q", s.Server.Name)
	}
	if len(s.Tools) != 2 || toolPages != 2 {
		t.Fatalf("tools=%d pages=%d", len(s.Tools), toolPages)
	}
}

func TestModernListFailureFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "server/discover" {
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"supportedVersions": []string{ModernProtocolVersion},
					"capabilities":      map[string]any{"tools": map[string]any{}},
				},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("inventory unavailable"))
	}))
	defer srv.Close()

	if _, err := New().Inspect(context.Background(), srv.URL); err == nil {
		t.Fatal("partial inventory was accepted")
	}
}

func TestLegacyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "server/discover":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]any{"code": -32601, "message": "Method not found"},
			})
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "legacy-session")
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"protocolVersion": LegacyProtocolVersion,
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]any{"name": "legacy", "version": "1"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	}))
	defer srv.Close()

	s, err := New().Inspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if s.Server.ProtocolVersion != LegacyProtocolVersion || s.Server.Name != "legacy" {
		t.Fatalf("unexpected legacy snapshot: %#v", s.Server)
	}
}

func TestAuthMetadataPathInsertion(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			json.NewEncoder(w).Encode(map[string]any{
				"resource":              base + "/mcp",
				"authorization_servers": []string{base + "/tenant1"},
			})
		case "/.well-known/oauth-authorization-server/tenant1":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 base + "/tenant1",
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL

	s, err := New().Inspect(context.Background(), srv.URL+"/mcp")
	if err == nil {
		t.Fatal("expected unauthorized probe error")
	}
	if s.Auth.ResourceMetadataURL == "" || len(s.Auth.AuthorizationMeta) == 0 {
		t.Fatalf("authorization metadata not captured: %#v", s.Auth)
	}
}
