package observe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/evidence"
)

type discoveryTransport func(*http.Request) (*http.Response, error)

func (f discoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Transport fixtures exercise the production RPC acquisition and signing path
// without sockets or an external API. They are not independent runtime acceptance.
func TestDiscoverySignedOutcomes(t *testing.T) {
	declarationPub, declarationKey, _ := ed25519.GenerateKey(rand.Reader)
	actorPub, actorKey, _ := ed25519.GenerateKey(rand.Reader)
	m, err := evidence.Sign([]evidence.Claim{{ID: "discovery", Actor: "observer"}}, declarationKey)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := evidence.NewLedger(m, declarationPub, map[string]ed25519.PublicKey{"observer": actorPub})
	if err != nil {
		t.Fatal(err)
	}
	replies := []struct {
		body      string
		status    int
		transport bool
		want      string
	}{
		{`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, 200, false, "response"},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"secret"}}`, 200, false, "rpc_error"},
		{`secret-body`, 503, false, "http_error"},
		{`invalid`, 200, false, "decode_error"},
		{`{"jsonrpc":"2.0","id":99,"result":{}}`, 200, false, "decode_error"},
		{``, 0, true, "transport_error"},
	}
	for _, reply := range replies {
		c := New()
		c.HTTP = &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) {
			var request struct{ Method string }
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Method != "tools/list" {
				t.Fatalf("unexpected RPC %s", request.Method)
			}
			if reply.transport {
				return nil, errors.New("secret transport error")
			}
			return &http.Response{StatusCode: reply.status, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(reply.body))}, nil
		})}
		c.DiscoverySink = func(d evidence.Discovery) error {
			return ledger.RecordDiscovery(d, "observer", "discovery", "attempts", "", actorKey)
		}
		_, _, _ = c.modernRPC(context.Background(), "https://fixture.invalid/mcp", 1, "tools/list", nil)
		records := ledger.File().Observations
		last := records[len(records)-1]
		if last.Discovery.Status != reply.want {
			t.Fatalf("got %s want %s", last.Discovery.Status, reply.want)
		}
	}
	f := ledger.File()
	if _, err := evidence.VerifyLedger(f, m, declarationPub, map[string]ed25519.PublicKey{"observer": actorPub}, ledger.Head()); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(f)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("raw secret leaked")
	}
	result, err := evidence.CompareDiscovery(f.Observations[0], f.Observations[1])
	if err != nil || result.Match {
		t.Fatalf("missing outcome drift: %+v %v", result, err)
	}
	f.Observations[0].Discovery.Method = "tools/call" // Validation only; never sent.
	if _, err := evidence.VerifyLedger(f, m, declarationPub, map[string]ed25519.PublicKey{"observer": actorPub}, ""); err == nil {
		t.Fatal("tampered discovery accepted")
	}
	if ledger.File().Observations[0].Discovery.Method != "tools/list" {
		t.Fatal("history aliased")
	}
}

func TestDiscoverySinkFailureAndUnsafeSource(t *testing.T) {
	c := New()
	sent := 0
	c.HTTP = &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) { sent++; return nil, errors.New("offline") })}
	c.DiscoverySink = func(evidence.Discovery) error { return errors.New("ledger full") }
	_, _, err := c.modernRPC(context.Background(), "https://fixture.invalid/mcp", 1, "tools/list", nil)
	if err == nil || !strings.Contains(err.Error(), "ledger full") {
		t.Fatalf("append failure hidden: %v", err)
	}
	_, _, err = c.modernRPC(context.Background(), "https://fixture.invalid/mcp?token=secret", 1, "tools/list", nil)
	if err == nil || sent != 1 {
		t.Fatal("unsafe evidence source sent")
	}
}

func TestDiscoveryLegacyAndFallbackAppendFailure(t *testing.T) {
	c := New()
	var methods []string
	c.HTTP = &http.Client{Transport: discoveryTransport(func(r *http.Request) (*http.Response, error) {
		var request struct {
			Method string
			ID     int
		}
		json.NewDecoder(r.Body).Decode(&request)
		methods = append(methods, request.Method)
		status, body := 200, `{"jsonrpc":"2.0","id":1,"result":{}}`
		if request.Method == "server/discover" {
			status, body = 404, "not found"
		}
		return &http.Response{StatusCode: status, Proto: "HTTP/1.1", Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	var captured evidence.Discovery
	c.DiscoverySink = func(d evidence.Discovery) error { captured = d; return nil }
	_, _, _, err := c.legacyRPC(context.Background(), "https://fixture.invalid/mcp", "secret-session", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize"})
	if err != nil || captured.Method != "initialize" || captured.Status != "response" {
		t.Fatalf("legacy capture: %+v %v", captured, err)
	}
	c.DiscoverySink = func(d evidence.Discovery) error { return errors.New("append rejected") }
	_, err = c.Inspect(context.Background(), "https://fixture.invalid/mcp")
	if err == nil || !strings.Contains(err.Error(), "append rejected") || len(methods) != 2 {
		t.Fatalf("fallback hid failure: %v %v", methods, err)
	}
}
