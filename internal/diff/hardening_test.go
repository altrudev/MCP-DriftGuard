package diff

import (
	"encoding/json"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

func TestSchemaWideningIsHighRisk(t *testing.T) {
	a := canonical.Snapshot{
		Endpoint: "https://x",
		Tools: []canonical.Tool{{
			Name:        "search",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["query"]}`),
		}},
	}
	b := a
	b.Tools = []canonical.Tool{{
		Name:        "search",
		InputSchema: json.RawMessage(`{"type":"object","additionalProperties":true,"required":[]}`),
	}}
	r := Compare(a, b)
	if r.Score < 35 || len(r.Changes) == 0 || r.Changes[0].Kind != "widened" {
		t.Fatalf("expected fail-level widening: %#v", r)
	}
}

func TestSchemaNarrowingIsReview(t *testing.T) {
	a := canonical.Snapshot{
		Endpoint: "https://x",
		Tools: []canonical.Tool{{
			Name:        "search",
			InputSchema: json.RawMessage(`{"type":"object","required":[]}`),
		}},
	}
	b := a
	b.Tools = []canonical.Tool{{
		Name:        "search",
		InputSchema: json.RawMessage(`{"type":"object","required":["query"]}`),
	}}
	r := Compare(a, b)
	if len(r.Changes) != 1 || r.Changes[0].Kind != "narrowed" || r.Changes[0].Severity != Medium {
		t.Fatalf("expected review-level narrowing: %#v", r)
	}
}

func TestTLSKeyChangeIsHigh(t *testing.T) {
	a := canonical.Snapshot{
		Endpoint:  "https://x",
		Transport: canonical.Transport{TLSSPKISHA256: "sha256:a"},
	}
	b := a
	b.Transport.TLSSPKISHA256 = "sha256:b"
	r := Compare(a, b)
	if r.Score < 35 {
		t.Fatalf("expected fail-level TLS key drift: %#v", r)
	}
}

func TestSelfReportedNameChangeIsNotIdentityFailure(t *testing.T) {
	a := canonical.Snapshot{Endpoint: "https://x", Server: canonical.Server{Name: "one"}}
	b := a
	b.Server.Name = "two"
	r := Compare(a, b)
	if len(r.Changes) != 1 || r.Changes[0].Severity != Medium || r.Changes[0].Category != "metadata" {
		t.Fatalf("unexpected server-name treatment: %#v", r)
	}
}

func TestServerVersionChangeIsDetected(t *testing.T) {
	old := canonical.Snapshot{Server: canonical.Server{Version: "1"}}
	live := canonical.Snapshot{Server: canonical.Server{Version: "2"}}
	r := Compare(old, live)
	if r.Match {
		t.Fatal("server version drift was missed")
	}
}

func TestAdvertisedCapabilityChangeIsHighRisk(t *testing.T) {
	old := canonical.Snapshot{Capabilities: map[string]any{"tools": map[string]any{}}}
	live := canonical.Snapshot{Capabilities: map[string]any{"tools": map[string]any{}, "sampling": map[string]any{}}}
	r := Compare(old, live)
	if r.Match || r.Score < 35 {
		t.Fatalf("capability drift not fail-level: %#v", r)
	}
}

func TestResourceDefinitionChangeIsDetected(t *testing.T) {
	old := canonical.Snapshot{Resources: []canonical.Resource{{URI: "file:///x", Name: "x", MIMEType: "text/plain"}}}
	live := canonical.Snapshot{Resources: []canonical.Resource{{URI: "file:///x", Name: "x", MIMEType: "application/json"}}}
	r := Compare(old, live)
	if r.Match {
		t.Fatal("resource mutation was missed")
	}
}

func TestRawJSONKeyOrderDoesNotCreateDrift(t *testing.T) {
	old := canonical.Snapshot{Tools: []canonical.Tool{{Name: "x", InputSchema: json.RawMessage(`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"}}}`)}}}
	live := canonical.Snapshot{Tools: []canonical.Tool{{Name: "x", InputSchema: json.RawMessage(`{"properties":{"b":{"type":"number"},"a":{"type":"string"}},"type":"object"}`)}}}
	r := Compare(old, live)
	if !r.Match {
		t.Fatalf("semantic-equivalent JSON created drift: %#v", r)
	}
}
