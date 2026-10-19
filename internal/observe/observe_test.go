package observe

import (
	"context"
	"encoding/json"
	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestExplicitUnsupportedVersionAllowsLegacyFallback(t *testing.T) {
	var initialized bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "server/discover":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32000, "message": "Bad Request: Unsupported protocol version: 2026-07-28 (supported versions: 2025-11-25, 2025-06-18)"}})
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"protocolVersion": LegacyProtocolVersion, "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "external-style", "version": "1"}}})
		case "notifications/initialized":
			initialized = true
			w.WriteHeader(http.StatusAccepted)
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	s, err := New().Inspect(context.Background(), srv.URL)
	if err != nil || s.Server.ProtocolVersion != LegacyProtocolVersion || !initialized {
		t.Fatalf("expected safe legacy fallback, snapshot=%#v err=%v initialized=%v", s.Server, err, initialized)
	}
}

func TestGenericBadRequestMustNotDowngrade(t *testing.T) {
	if legacyFallbackBody(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Invalid credentials"}}`) {
		t.Fatal("generic error allowed downgrade")
	}
	if legacyFallbackBody(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Unsupported protocol version: 2026-07-28"}}`) {
		t.Fatal("unsubstantiated version error allowed downgrade")
	}
}

func TestPythonSDKUnsupportedVersionFallbackSignature(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Bad Request: Unsupported protocol version: 2026-07-28. Supported versions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25"}}`
	if !legacyFallbackBody(body) {
		t.Fatal("explicit Python SDK protocol rejection must permit legacy negotiation")
	}
	if legacyFallbackBody(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"Bad Request: Invalid request"}}`) {
		t.Fatal("generic invalid request must not permit fallback")
	}
}

func TestUninitializedServerAllowsLegacyHandshake(t *testing.T) {
	body := `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Server not initialized"},"id":null}`
	if !legacyFallbackBody(body) {
		t.Fatal("explicit initialization requirement should permit legacy handshake")
	}
	if legacyFallbackBody(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Server not initialized because credentials missing"},"id":null}`) {
		t.Fatal("unrelated initialization-like message must not trigger fallback")
	}
}

func TestEmptySSEPrefaceIsIgnored(t *testing.T) {
	raw := `id: preface
data:

event: message
data: {"jsonrpc":"2.0","id":1,"result":{}}

`
	got, err := readRPCBody(strings.NewReader(raw), "text/event-stream")
	if err != nil || !json.Valid(got) {
		t.Fatalf("SSE preface parsing: payload=%q err=%v", got, err)
	}
}

func TestBearerTokenForwardedToMCPRPCOnly(t *testing.T) {
	t.Setenv("MCPDRIFT_BEARER_TOKEN", "test-only-secret")
	var gotAuthorization bool
	var leakedToMetadata bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.Header.Get("Authorization") != "" {
				leakedToMetadata = true
			}
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "Bearer test-only-secret" {
			gotAuthorization = true
		}
		var request struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"supportedVersions": []string{ModernProtocolVersion}, "capabilities": map[string]any{}}})
		default:
			t.Errorf("unexpected method %s", request.Method)
		}
	}))
	defer srv.Close()
	if _, err := New().Inspect(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if !gotAuthorization || leakedToMetadata {
		t.Fatalf("bearer forwarded=%v metadata leaked=%v", gotAuthorization, leakedToMetadata)
	}
}

func TestBearerNeverFollowsCrossOriginRedirect(t *testing.T) {
	t.Setenv("MCPDRIFT_BEARER_TOKEN", "synthetic-test-only")
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" {
			t.Error("secret leaked to redirect destination")
		}
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}))
	defer destination.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer src.Close()
	if _, err := New().Inspect(context.Background(), src.URL); err == nil {
		t.Fatal("redirected request accepted")
	}
	if redirected {
		t.Fatal("MCP request followed redirect")
	}
}

func TestMetadataOversizeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("a", (1<<20)+1)))
	}))
	defer srv.Close()
	c := New()
	_, _, err := c.getJSON(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized metadata accepted: %v", err)
	}
}

func TestMetadataRedirectNotFollowed(t *testing.T) {
	var reached bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; _, _ = w.Write([]byte("{}")) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := New()
	_, status, err := c.getJSON(context.Background(), source.URL)
	if err != nil || status != http.StatusTemporaryRedirect || reached {
		t.Fatalf("metadata redirected: status=%d reached=%v err=%v", status, reached, err)
	}
}

func TestCrossOriginOAuthIssuerRequiresExplicitApproval(t *testing.T) {
	var issuerRequests int
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuerRequests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer issuer.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_servers":["` + issuer.URL + `"]}`))
	}))
	defer origin.Close()
	endpoint, _ := url.Parse(origin.URL + "/mcp")
	var snapshot canonical.Snapshot
	t.Setenv("MCPDRIFT_ALLOWED_AUTH_ISSUERS", "")
	if err := New().discoverAuth(context.Background(), endpoint, &snapshot); err == nil {
		t.Fatal("cross-origin authorization issuer accepted without approval")
	}
	if issuerRequests != 0 {
		t.Fatal("blocked cross-origin issuer was contacted")
	}
	t.Setenv("MCPDRIFT_ALLOWED_AUTH_ISSUERS", issuer.URL)
	if err := New().discoverAuth(context.Background(), endpoint, &snapshot); err != nil {
		t.Fatal(err)
	}
	if issuerRequests == 0 {
		t.Fatal("approved cross-origin issuer not contacted")
	}
}

func TestOAuthIssuerApprovalIsExactOrigin(t *testing.T) {
	t.Setenv("MCPDRIFT_ALLOWED_AUTH_ISSUERS", "https://example.org/path,https://user@example.net,https://valid.example")
	good, _ := url.Parse("https://valid.example/a")
	bad, _ := url.Parse("https://example.org")
	if !approvedAuthorizationIssuer(good) {
		t.Fatal("explicit approved origin rejected")
	}
	if approvedAuthorizationIssuer(bad) {
		t.Fatal("issuer approved through path-bearing allowlist")
	}
}

// A hostile MCP endpoint can put credential-like values in challenge extras.
// Only the required resource_metadata URL is retained in the snapshot.
func TestUnauthorizedChallengeDoesNotPersistSecretParameters(t *testing.T) {
	const secret = "synthetic-canary-never-persist-9e82a"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+secret+`", error_description="`+secret+`", resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	result, _ := New().Inspect(context.Background(), server.URL+"/mcp")
	contents, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), secret) {
		t.Fatalf("challenge secret persisted in snapshot")
	}
	if strings.Contains(result.Auth.WWWAuthenticate, "realm") {
		t.Fatal("untrusted challenge parameters retained")
	}
}
