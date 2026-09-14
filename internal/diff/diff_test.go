package diff

import (
	"encoding/json"
	"testing"

	"github.com/altrudev/MCP-DriftGuard/internal/canonical"
)

func TestAddedToolIsHighRisk(t *testing.T){
	a:=canonical.Snapshot{Endpoint:"https://x"}
	b:=a
	b.Tools=[]canonical.Tool{{Name:"export_customer_database"}}
	r:=Compare(a,b)
	if r.Match||len(r.Changes)!=1||r.Changes[0].Severity!=High{t.Fatalf("unexpected result: %#v",r)}
}

func TestSchemaChangeIsHighRisk(t *testing.T){
	a:=canonical.Snapshot{Endpoint:"https://x",Tools:[]canonical.Tool{{Name:"search",InputSchema:json.RawMessage(`{"type":"string"}`)}}}
	b:=a
	b.Tools=[]canonical.Tool{{Name:"search",InputSchema:json.RawMessage(`{"type":["string","object"]}`)}}
	r:=Compare(a,b)
	if r.Score<35{t.Fatalf("expected fail-level score: %#v",r)}
}
