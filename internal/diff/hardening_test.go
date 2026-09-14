package diff

import (
	"encoding/json"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

func TestSchemaWideningIsHighRisk(t *testing.T) {
	a:=canonical.Snapshot{
		Endpoint:"https://x",
		Tools:[]canonical.Tool{{
			Name:"search",
			InputSchema:json.RawMessage(`{"type":"object","additionalProperties":false,"required":["query"]}`),
		}},
	}
	b:=a
	b.Tools=[]canonical.Tool{{
		Name:"search",
		InputSchema:json.RawMessage(`{"type":"object","additionalProperties":true,"required":[]}`),
	}}
	r:=Compare(a,b)
	if r.Score<35 || len(r.Changes)==0 || r.Changes[0].Kind!="widened" {
		t.Fatalf("expected fail-level widening: %#v",r)
	}
}

func TestSchemaNarrowingIsReview(t *testing.T) {
	a:=canonical.Snapshot{
		Endpoint:"https://x",
		Tools:[]canonical.Tool{{
			Name:"search",
			InputSchema:json.RawMessage(`{"type":"object","required":[]}`),
		}},
	}
	b:=a
	b.Tools=[]canonical.Tool{{
		Name:"search",
		InputSchema:json.RawMessage(`{"type":"object","required":["query"]}`),
	}}
	r:=Compare(a,b)
	if len(r.Changes)!=1 || r.Changes[0].Kind!="narrowed" || r.Changes[0].Severity!=Medium {
		t.Fatalf("expected review-level narrowing: %#v",r)
	}
}

func TestTLSKeyChangeIsHigh(t *testing.T) {
	a:=canonical.Snapshot{
		Endpoint:"https://x",
		Transport:canonical.Transport{TLSSPKISHA256:"sha256:a"},
	}
	b:=a
	b.Transport.TLSSPKISHA256="sha256:b"
	r:=Compare(a,b)
	if r.Score<35 {
		t.Fatalf("expected fail-level TLS key drift: %#v",r)
	}
}

func TestSelfReportedNameChangeIsNotIdentityFailure(t *testing.T) {
	a:=canonical.Snapshot{Endpoint:"https://x",Server:canonical.Server{Name:"one"}}
	b:=a
	b.Server.Name="two"
	r:=Compare(a,b)
	if len(r.Changes)!=1 || r.Changes[0].Severity!=Medium || r.Changes[0].Category!="metadata" {
		t.Fatalf("unexpected server-name treatment: %#v",r)
	}
}
